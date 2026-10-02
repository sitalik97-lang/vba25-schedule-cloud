"""Local transactional domain store. Secret values are never configuration records."""
import json
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager, closing
from datetime import datetime, timezone, timedelta
from pathlib import Path
from access import (SCOPES, LEVELS, ROLE_PERMISSIONS, EXTRA_PERMISSIONS, CHAT_FEATURES,
                    USER_DEFAULTS, owner_matches, allowed, resolve_feature)
from lesson_index import next_lesson


def now():
    return datetime.now(timezone.utc).isoformat()


def safe_text(value):
    text = str(value)
    for key in ('TELEGRAM_BOT_TOKEN', 'BOT_TOKEN', 'TELEGRAM_PROXY_URL', 'UPDATE_SECRET', 'WEBHOOK_SECRET', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
        secret = os.getenv(key)
        if secret:
            text = text.replace(secret, '[секрет скрыт]')
    text = re.sub(r'(?i)(https?|socks5h?)://[^/\s:@]+:[^/\s@]+@', r'\1://[hidden]@', text)
    return re.sub(r'\b\d{6,15}:[A-Za-z0-9_-]{20,}\b', '[секрет скрыт]', text)


def dump(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


class Store:
    def __init__(self, path, owner_id=None):
        self.path = Path(path)
        self.owner_id = owner_id if type(owner_id) is int and owner_id > 0 else None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and self.path.stat().st_size:
            with closing(sqlite3.connect(self.path)) as db:
                version = db.execute('PRAGMA user_version').fetchone()[0]
                if version not in (0, 1, 2, 3, 4):
                    raise ValueError('Unsupported database version')
                if version in (1,2,3):
                    folder=self.path.parent/'backups'; folder.mkdir(exist_ok=True)
                    copy=folder/(f'backup-before-v4-from-v{version}-'+secrets.token_hex(6)+'.sqlite3')
                    with closing(sqlite3.connect(copy)) as target: db.backup(target)
        with self.connect() as db:
            db.executescript('''
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, preferences TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS chats(id INTEGER PRIMARY KEY, scope TEXT NOT NULL,
                title TEXT NOT NULL, approved INTEGER NOT NULL DEFAULT 0,
                blocked INTEGER NOT NULL DEFAULT 0, settings TEXT NOT NULL DEFAULT '{}');
            CREATE TABLE IF NOT EXISTS roles(user_id INTEGER, name TEXT, frozen INTEGER DEFAULT 0,
                PRIMARY KEY(user_id,name));
            CREATE TABLE IF NOT EXISTS extras(user_id INTEGER, permission TEXT, PRIMARY KEY(user_id,permission));
            CREATE TABLE IF NOT EXISTS defaults(scope TEXT PRIMARY KEY, settings TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS homework(id INTEGER PRIMARY KEY, author INTEGER NOT NULL,
                version INTEGER NOT NULL, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS versions(homework_id INTEGER, version INTEGER, body TEXT,
                PRIMARY KEY(homework_id,version));
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at TEXT NOT NULL,
                actor INTEGER NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS issues(id INTEGER PRIMARY KEY, author INTEGER, chat_id INTEGER,
                category TEXT, context TEXT, at TEXT, status TEXT DEFAULT 'open');
            CREATE TABLE IF NOT EXISTS pending(id TEXT PRIMARY KEY, actor INTEGER, kind TEXT,
                payload TEXT, expires TEXT, used INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS deliveries(key TEXT PRIMARY KEY, state TEXT, at TEXT);
            CREATE TABLE IF NOT EXISTS templates(id INTEGER PRIMARY KEY, author INTEGER, name TEXT, body TEXT);
            CREATE TABLE IF NOT EXISTS role_definitions(name TEXT PRIMARY KEY, permissions TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS signatures(label TEXT PRIMARY KEY, owner_only INTEGER NOT NULL);
            INSERT OR IGNORE INTO signatures SELECT 'Куратор ДЗ',0 WHERE (SELECT user_version FROM pragma_user_version)<2;
            INSERT OR IGNORE INTO signatures SELECT 'Владелец',1 WHERE (SELECT user_version FROM pragma_user_version)<2;
            CREATE TABLE IF NOT EXISTS metrics(day TEXT, chat_id INTEGER, action TEXT, count INTEGER, PRIMARY KEY(day,chat_id,action));
            CREATE TABLE IF NOT EXISTS bot_settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT OR IGNORE INTO bot_settings VALUES('id_mode','everyone');
            CREATE TABLE IF NOT EXISTS user_profiles(user_id INTEGER PRIMARY KEY, display_name TEXT NOT NULL, username TEXT NOT NULL, seen_at TEXT NOT NULL);
            PRAGMA user_version=4;
            COMMIT;
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA foreign_keys=ON')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _log(self, db, actor, action, target=''):
        db.execute('INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)',
                   (now(), actor, action, safe_text(target)[:200]))

    def _can(self, db, actor, permission):
        if self._user_blocked(db,actor): return False
        roles = [dict(r) for r in db.execute('SELECT name,frozen FROM roles WHERE user_id=?', (actor,))]
        extra = [r[0] for r in db.execute('SELECT permission FROM extras WHERE user_id=?', (actor,))]
        definitions={**ROLE_PERMISSIONS,**{r['name']:frozenset(json.loads(r['permissions'])) for r in db.execute('SELECT * FROM role_definitions')}}
        return allowed(actor, self.owner_id, permission, roles, extra, definitions)

    def require(self, db, actor, permission):
        if not self._can(db, actor, permission):
            raise PermissionError('Недостаточно прав')

    def _user_blocked(self, db, target):
        if owner_matches(target,self.owner_id): return False
        row=db.execute("SELECT value FROM bot_settings WHERE key=?",('blocked_user:'+str(target),)).fetchone()
        return bool(row and row[0]=='1')

    def user_blocked(self, target):
        with self.connect() as db: return self._user_blocked(db,target)

    def set_user_blocked(self, actor, target, blocked):
        if type(target) is not int or target<=0 or type(blocked) is not bool: raise ValueError('Некорректный пользователь')
        with self.connect() as db:
            self.require(db,actor,'admin')
            if owner_matches(target,self.owner_id): raise ValueError('Владельца нельзя заблокировать')
            db.execute('INSERT INTO bot_settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',('blocked_user:'+str(target),'1' if blocked else '0'))
            if blocked: db.execute('UPDATE pending SET used=1 WHERE actor=?',(target,))
            self._log(db,actor,'user.blocked' if blocked else 'user.unblocked',target)

    def can(self, actor, permission):
        with self.connect() as db:
            return self._can(db, actor, permission)

    def register(self, actor, chat_id, scope, title='', display_name=None, username=None):
        if (scope not in SCOPES or type(actor) is not int or actor <= 0 or type(chat_id) is not int
                or (scope == 'PRIVATE' and chat_id != actor) or (scope != 'PRIVATE' and chat_id >= 0)):
            raise ValueError('Invalid identity')
        with self.connect() as db:
            db.execute('INSERT OR IGNORE INTO users VALUES(?,?)', (actor, dump(USER_DEFAULTS)))
            if display_name is not None:
                db.execute('INSERT INTO user_profiles VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET display_name=excluded.display_name,username=excluded.username,seen_at=excluded.seen_at',
                           (actor,' '.join(safe_text(display_name).split())[:120],safe_text(username or '')[:64],now()))
            old = db.execute('SELECT scope FROM chats WHERE id=?', (chat_id,)).fetchone()
            if old and old[0] != scope:
                raise ValueError('Chat scope mismatch')
            db.execute('INSERT INTO chats(id,scope,title) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title',
                       (chat_id, scope, safe_text(title)[:150]))

    def preferences(self, actor):
        with self.connect() as db:
            row = db.execute('SELECT preferences FROM users WHERE id=?', (actor,)).fetchone()
            return {**USER_DEFAULTS, **(json.loads(row[0]) if row else {})}

    def set_preference(self, actor, key, value):
        if key == 'subgroup' and (type(value) is not int or value not in (0,1,2)): raise ValueError('Unknown subgroup')
        if key == 'reminder_moments' and (not isinstance(value,list) or len(value)>2 or any(v not in ('evening','morning') for v in value)): raise ValueError('Unknown reminder time')
        if key == 'suggestion_snooze' and value and datetime.fromisoformat(value).tzinfo is None: raise ValueError('Timezone required')
        if key not in USER_DEFAULTS:
            raise ValueError('Unknown preference')
        if key == 'level' and value not in LEVELS:
            raise ValueError('Unknown interface level')
        if key in {'help','compact','reminders','suggestions','preview'} and type(value) is not bool:
            raise ValueError('Boolean expected')
        if key in {'hidden','favorites','dismissed_suggestions'} and (not isinstance(value,list) or
                len(value)>30 or not all(isinstance(x,str) and len(x)<50 for x in value)):
            raise ValueError('Invalid actions')
        if key == 'reminder_offsets' and (not isinstance(value,list) or len(value)>5 or
                not all(type(x) is int and 0 <= x <= 10080 for x in value)):
            raise ValueError('Invalid reminder times')
        with self.connect() as db:
            row = db.execute('SELECT preferences FROM users WHERE id=?', (actor,)).fetchone()
            prefs = {**USER_DEFAULTS, **(json.loads(row[0]) if row else {}), key:value}
            db.execute('INSERT INTO users VALUES(?,?) ON CONFLICT(id) DO UPDATE SET preferences=excluded.preferences', (actor,dump(prefs)))
            self._log(db, actor, 'preferences.changed', key)

    def role(self, actor, target, name, operation):
        if type(target) is not int or target <= 0:
            raise ValueError('Invalid role or user')
        with self.connect() as db:
            self.require(db,actor,'admin')
            if name not in ROLE_PERMISSIONS and not db.execute('SELECT 1 FROM role_definitions WHERE name=?',(name,)).fetchone(): raise ValueError('Unknown role')
            if operation == 'remove':
                db.execute('DELETE FROM roles WHERE user_id=? AND name=?',(target,name))
            elif operation in ('grant','freeze','unfreeze'):
                db.execute('INSERT INTO roles VALUES(?,?,?) ON CONFLICT(user_id,name) DO UPDATE SET frozen=excluded.frozen',
                           (target,name,int(operation=='freeze')))
            else:
                raise ValueError('Invalid operation')
            self._log(db,actor,'role.'+operation,f'{target}:{name}')

    def extra(self, actor, target, permission, enabled):
        if permission not in EXTRA_PERMISSIONS or type(target) is not int or target <= 0:
            raise ValueError('Invalid permission or user')
        with self.connect() as db:
            self.require(db,actor,'admin')
            if enabled:
                db.execute('INSERT OR IGNORE INTO extras VALUES(?,?)',(target,permission))
            else:
                db.execute('DELETE FROM extras WHERE user_id=? AND permission=?',(target,permission))
            self._log(db,actor,'permission.changed',f'{target}:{permission}:{enabled}')

    def chats(self, actor):
        with self.connect() as db:
            self.require(db,actor,'admin')
            return [dict(r) for r in db.execute('SELECT * FROM chats ORDER BY scope,id')]

    def chat(self, chat_id):
        with self.connect() as db:
            row = db.execute('SELECT * FROM chats WHERE id=?',(chat_id,)).fetchone()
            return dict(row) if row else None

    def authorize_chat(self, actor, chat_id, approved=None, blocked=None):
        with self.connect() as db:
            self.require(db,actor,'admin')
            if not db.execute('SELECT 1 FROM chats WHERE id=?',(chat_id,)).fetchone():
                raise ValueError('Чат ещё не известен боту')
            if approved is not None:
                db.execute('UPDATE chats SET approved=? WHERE id=?',(int(approved),chat_id))
            if blocked is not None:
                db.execute('UPDATE chats SET blocked=? WHERE id=?',(int(blocked),chat_id))
            self._log(db,actor,'chat.access',chat_id)

    def chat_allowed(self, chat_id, owner_present=False):
        chat = self.chat(chat_id)
        return bool(chat and not chat['blocked'] and not (chat['scope']=='PRIVATE' and self.user_blocked(chat_id)) and (chat['scope']=='PRIVATE' or chat['approved'] or owner_present))

    def feature(self, chat_id, key):
        with self.connect() as db:
            chat = db.execute('SELECT * FROM chats WHERE id=?',(chat_id,)).fetchone()
            if not chat:
                return False,'unknown-chat'
            row = db.execute('SELECT settings FROM defaults WHERE scope=?',(chat['scope'],)).fetchone()
            return resolve_feature(chat['scope'],key,json.loads(row[0]) if row else {},json.loads(chat['settings']),blocked=bool(chat['blocked']))

    def set_feature(self, actor, chat_id, key, value):
        if key not in CHAT_FEATURES or (value is not None and type(value) is not bool):
            raise ValueError('Invalid setting')
        with self.connect() as db:
            self.require(db,actor,'admin')
            row = db.execute('SELECT settings FROM chats WHERE id=?',(chat_id,)).fetchone()
            if not row:
                raise ValueError('Unknown chat')
            settings=json.loads(row[0])
            if value is None:
                settings.pop(key,None)
            else:
                settings[key]=value
            db.execute('UPDATE chats SET settings=? WHERE id=?',(dump(settings),chat_id))
            self._log(db,actor,'chat.setting',f'{chat_id}:{key}:{value}')

    def prepare(self, actor, kind, payload):
        with self.connect() as db:
            self.require(db,actor,'admin' if kind=='bulk' else 'announcement.send')
            if kind not in ('bulk','broadcast'):
                raise ValueError('Unknown action')
            ids=list(dict.fromkeys(payload['chat_ids']))
            chats=[db.execute('SELECT * FROM chats WHERE id=?',(i,)).fetchone() for i in ids]
            if not ids or len(ids)>100 or any(c is None for c in chats) or len({c['scope'] for c in chats})!=1:
                raise ValueError('Выберите известные чаты одного типа')
            if kind=='bulk' and (payload['key'] not in CHAT_FEATURES or type(payload['value']) is not bool):
                raise ValueError('Invalid setting')
            payload={**payload,'chat_ids':ids,'scope':chats[0]['scope']}
            if kind=='broadcast':
                payload['text']=safe_text(payload['text'])[:3500]
                if not payload['text'].strip():
                    raise ValueError('Empty announcement')
                signatures={r['label'] for r in db.execute('SELECT * FROM signatures') if not r['owner_only'] or owner_matches(actor,self.owner_id)} | {''}
                if payload.get('signature','') not in signatures:
                    raise ValueError('Unknown signature')
            ident=secrets.token_hex(12)
            db.execute('INSERT INTO pending VALUES(?,?,?,?,?,0)',(ident,actor,kind,dump(payload),
                       (datetime.now(timezone.utc)+timedelta(minutes=15)).isoformat()))
            return ident,payload

    def confirm(self, actor, ident):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM pending WHERE id=?',(ident,)).fetchone()
            if not row or row['actor']!=actor or row['used'] or row['expires']<now():
                raise PermissionError('Подтверждение истекло или уже использовано')
            kind=row['kind']; payload=json.loads(row['payload'])
            self.require(db,actor,'admin' if kind=='bulk' else 'announcement.send')
            if kind=='broadcast':
                signatures={r['label'] for r in db.execute('SELECT * FROM signatures') if not r['owner_only'] or owner_matches(actor,self.owner_id)} | {''}
                if payload.get('signature','') not in signatures: raise PermissionError('Подпись больше не разрешена')
            for cid in payload['chat_ids']:
                chat=db.execute('SELECT * FROM chats WHERE id=?',(cid,)).fetchone()
                if not chat or chat['scope']!=payload['scope']:
                    raise ValueError('Список чатов изменился')
                if kind=='bulk':
                    settings=json.loads(chat['settings']); settings[payload['key']]=payload['value']
                    db.execute('UPDATE chats SET settings=? WHERE id=?',(dump(settings),cid))
            db.execute('UPDATE pending SET used=1 WHERE id=?',(ident,))
            self._log(db,actor,kind+'.confirmed',ident)
            return kind,payload

    def create_homework(self, actor, body):
        body=self._validate_homework(body)
        body['state']='draft'
        with self.connect() as db:
            self.require(db,actor,'homework.create')
            cur=db.execute('INSERT INTO homework(author,version,body) VALUES(?,1,?)',(actor,dump(body)))
            ident=cur.lastrowid
            db.execute('INSERT INTO versions VALUES(?,1,?)',(ident,dump(body)))
            self._log(db,actor,'homework.created',ident)
            return ident

    def _validate_homework(self, body):
        keys={'subject','text','attachments','subgroup','deadline_kind','anchor','due','state','custom_due'}
        if set(body)-keys:
            raise ValueError('Unknown homework field')
        if not body.get('subject') or len(body['subject'])>250 or len(body.get('text',''))>3000:
            raise ValueError('Invalid homework text')
        if body.get('subgroup',0) not in (0,1,2) or body.get('deadline_kind','none') not in ('none','fixed','next','custom'):
            raise ValueError('Invalid deadline or audience')
        if body.get('state','draft') not in ('draft','published','corrected','archived'):
            raise ValueError('Invalid state')
        files=body.get('attachments',[])
        if len(files)>10 or any(set(f)!={'kind','file_id'} or f['kind'] not in ('photo','document') or not isinstance(f['file_id'],str) for f in files):
            raise ValueError('Invalid attachments')
        if body.get('due'):
            dt=datetime.fromisoformat(body['due'])
            if dt.tzinfo is None: raise ValueError('Timezone required')
        if body.get('deadline_kind')=='next':
            if datetime.fromisoformat(body['anchor']).tzinfo is None: raise ValueError('Timezone required')
        return json.loads(safe_text(dump(body)))

    def homework(self, actor, drafts=False):
        with self.connect() as db:
            self.require(db,actor,'homework.read')
            result=[]
            for row in db.execute('SELECT * FROM homework ORDER BY id DESC'):
                item={**dict(row),'body':json.loads(row['body'])}
                if item['body']['state'] in ('published','corrected') or (drafts and (row['author']==actor or self._can(db,actor,'homework.edit.any'))):
                    result.append(item)
            return result

    def edit_homework(self, actor, ident, expected_version, changes=None, rollback=False):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM homework WHERE id=?',(ident,)).fetchone()
            if not row: raise ValueError('ДЗ не найдено')
            permission='homework.edit.own' if row['author']==actor else 'homework.edit.any'
            self.require(db,actor,permission)
            if row['version']!=expected_version: raise ValueError('ДЗ уже изменилось; откройте заново')
            old=json.loads(row['body'])
            if rollback:
                previous=db.execute('SELECT body FROM versions WHERE homework_id=? AND version=?',(ident,expected_version-1)).fetchone()
                if not previous: raise ValueError('Нет предыдущей версии')
                body=json.loads(previous[0])
            else:
                body=self._validate_homework({**old,**(changes or {})})
                if old['state'] in ('published','corrected') and 'state' not in (changes or {}): body['state']='corrected'
            if body['state'] in ('published','corrected'):
                self.require(db,actor,'homework.publish')
                if not body.get('text','').strip() and not body.get('attachments'): raise ValueError('Добавьте текст или вложения')
            if body['state']=='archived': self.require(db,actor,'homework.archive.own' if row['author']==actor else 'homework.archive.any')
            version=expected_version+1
            db.execute('UPDATE homework SET version=?,body=? WHERE id=?',(version,dump(body),ident))
            db.execute('INSERT INTO versions VALUES(?,?,?)',(ident,version,dump(body)))
            self._log(db,actor,'homework.rollback' if rollback else 'homework.changed',ident)
            return version

    def reconcile(self, schedule):
        changed=[]
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for row in db.execute('SELECT * FROM homework').fetchall():
                body=json.loads(row['body'])
                if body.get('deadline_kind')!='next' or body['state']=='archived': continue
                if body.get('due') and datetime.fromisoformat(body['due']) < datetime.now(timezone.utc): continue
                lesson=next_lesson(schedule,body['subject'],body['anchor'],body.get('subgroup',0))
                due=lesson['at'] if lesson else None
                if due==body.get('due'): continue
                body['due']=due; version=row['version']+1
                db.execute('UPDATE homework SET version=?,body=? WHERE id=?',(version,dump(body),row['id']))
                db.execute('INSERT INTO versions VALUES(?,?,?)',(row['id'],version,dump(body)))
                self._log(db,0,'deadline.recalculated',row['id'])
                changed.append((row['author'],row['id']))
        return changed

    def reminder_candidates(self, at=None):
        at=at or datetime.now(timezone.utc)
        result=[]
        with self.connect() as db:
            users=db.execute("SELECT u.id,u.preferences FROM users u JOIN chats c ON c.id=u.id WHERE c.scope='PRIVATE' AND c.blocked=0").fetchall()
            for user in users:
                prefs=json.loads(user['preferences'])
                if self._user_blocked(db,user['id']) or not prefs.get('reminders') or not self.feature(user['id'],'homework')[0]: continue
                for row in db.execute('SELECT * FROM homework'):
                    body=json.loads(row['body'])
                    if body['state'] not in ('published','corrected') or not body.get('due'): continue
                    if prefs.get('subgroup',0) and body.get('subgroup',0) not in (0,prefs['subgroup']): continue
                    due=datetime.fromisoformat(body['due'])
                    times=[(str(minutes),due-timedelta(minutes=minutes)) for minutes in prefs.get('reminder_offsets',[1440])]
                    from zoneinfo import ZoneInfo
                    local=due.astimezone(ZoneInfo('Europe/Moscow'))
                    if 'evening' in prefs.get('reminder_moments',[]): times.append(('evening',(local-timedelta(days=1)).replace(hour=20,minute=0,second=0,microsecond=0)))
                    if 'morning' in prefs.get('reminder_moments',[]): times.append(('morning',local.replace(hour=7,minute=0,second=0,microsecond=0)))
                    for minutes,trigger in times:
                        if not trigger<=at<=min(due,trigger+timedelta(minutes=10)): continue
                        key=f"reminder:{user['id']}:{row['id']}:{body['due']}:{minutes}"
                        if not db.execute('SELECT 1 FROM deliveries WHERE key=?',(key,)).fetchone():
                            result.append((key,user['id'],row['id'],body))
        return result

    def claim_delivery(self, key):
        with self.connect() as db:
            cur=db.execute('INSERT OR IGNORE INTO deliveries VALUES(?,?,?)',(key,'sending',now()))
            return cur.rowcount==1

    def finish_delivery(self, key, state):
        if state not in ('sent','failed','uncertain'): raise ValueError('Invalid delivery state')
        with self.connect() as db:
            db.execute('UPDATE deliveries SET state=?,at=? WHERE key=?',(state,now(),key))
            self._log(db,0,'delivery.'+state,key)

    def issue(self, actor, chat_id, category, context):
        if category not in ('homework','schedule','bot','interface','notifications','help','other'):
            raise ValueError('Unknown issue type')
        clean={k:safe_text(v)[:1000] for k,v in context.items() if k in ('date','subject','action','text','homework_id')}
        with self.connect() as db:
            self.require(db,actor,'issue.create')
            db.execute('INSERT INTO issues(author,chat_id,category,context,at) VALUES(?,?,?,?,?)',(actor,chat_id,category,dump(clean),now()))
            self._log(db,actor,'issue.created',category)

    def overview(self, actor, table='audit'):
        if table not in ('audit','issues','users','deliveries'): raise ValueError('Unknown view')
        with self.connect() as db:
            self.require(db,actor,'admin')
            return [dict(r) for r in db.execute(f'SELECT * FROM {table} ORDER BY rowid DESC LIMIT 50')]

    def backup(self, actor, directory):
        with self.connect() as db:
            self.require(db,actor,'admin')
            directory=Path(directory); directory.mkdir(parents=True,exist_ok=True)
            path=directory/('backup-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3)+'.sqlite3')
            with closing(sqlite3.connect(path)) as target:
                db.backup(target)
            self._log(db,actor,'backup.created',path.name)
            return path

    def set_default(self, actor, scope, key, value):
        if scope not in SCOPES or key not in CHAT_FEATURES or type(value) is not bool:
            raise ValueError('Invalid default')
        with self.connect() as db:
            self.require(db, actor, 'admin')
            row=db.execute('SELECT settings FROM defaults WHERE scope=?',(scope,)).fetchone()
            values=json.loads(row[0]) if row else {}
            values[key]=value
            db.execute('INSERT INTO defaults VALUES(?,?) ON CONFLICT(scope) DO UPDATE SET settings=excluded.settings',(scope,dump(values)))
            self._log(db,actor,'default.changed',f'{scope}:{key}:{value}')

    def history(self, actor, ident):
        with self.connect() as db:
            self.require(db,actor,'homework.history')
            row=db.execute('SELECT author FROM homework WHERE id=?',(ident,)).fetchone()
            if not row or (row[0]!=actor and not self._can(db,actor,'homework.edit.any')):
                raise PermissionError('Недостаточно прав')
            return [dict(r) for r in db.execute('SELECT version,body FROM versions WHERE homework_id=? ORDER BY version DESC',(ident,))]

    def templates(self, actor):
        with self.connect() as db:
            self.require(db,actor,'templates.self')
            return [{**dict(r),'body':json.loads(r['body'])} for r in db.execute('SELECT * FROM templates WHERE author=? ORDER BY id',(actor,))]

    def save_template(self, actor, name, body):
        # Templates never carry a past deadline, attachments, or publication state.
        values={k:v for k,v in body.items() if k in ('subject','subgroup','deadline_kind','custom_due')}
        if not isinstance(name,str) or not name.strip() or len(name)>60:
            raise ValueError('Название от 1 до 60 символов')
        self._validate_homework({**values,'anchor':now()})
        with self.connect() as db:
            self.require(db,actor,'templates.self')
            if db.execute('SELECT count(*) FROM templates WHERE author=?',(actor,)).fetchone()[0]>=20:
                raise ValueError('Лимит: 20 шаблонов')
            ident=db.execute('INSERT INTO templates(author,name,body) VALUES(?,?,?)',(actor,safe_text(name),dump(values))).lastrowid
            self._log(db,actor,'template.created',ident)
            return ident

    def delete_template(self, actor, ident):
        with self.connect() as db:
            self.require(db,actor,'templates.self')
            db.execute('DELETE FROM templates WHERE id=? AND author=?',(ident,actor))
            self._log(db,actor,'template.deleted',ident)

    def broadcast_candidates(self, actor):
        with self.connect() as db:
            self.require(db,actor,'announcement.send')
            ids=[r[0] for r in db.execute('SELECT id FROM chats WHERE blocked=0')]
        key='owner_broadcast' if owner_matches(actor,self.owner_id) else 'curator_broadcast'
        return [self.chat(cid) for cid in ids if self.feature(cid,key)[0]]

    def broadcast_targets(self, actor, owner_present=()):
        return [chat for chat in self.broadcast_candidates(actor) if self.chat_allowed(chat['id'],chat['id'] in owner_present)]

    def record_error(self, action):
        with self.connect() as db:
            self._log(db,0,'system.error',action)

    def restore(self, actor, source, directory):
        source=Path(source).resolve(); directory=Path(directory).resolve()
        if source.parent!=directory or not source.name.startswith('backup-') or source.suffix!='.sqlite3':
            raise ValueError('Выберите локальную резервную копию')
        with self.connect() as db:
            self.require(db,actor,'admin')
            expected={r[0]:[tuple(c) for c in db.execute('PRAGMA table_info('+r[0]+')')] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            delivery_rows=[tuple(r) for r in db.execute('SELECT * FROM deliveries')]
            audit_rows=[tuple(r) for r in db.execute('SELECT at,actor,action,target FROM audit')]
        if not source.is_file(): raise ValueError('Копия не найдена')
        staging=self.path.with_name('restore-'+secrets.token_hex(8)+'.sqlite3')
        try:
            with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as candidate:
                if candidate.execute('PRAGMA integrity_check').fetchone()[0]!='ok' or candidate.execute('PRAGMA user_version').fetchone()[0]!=4:
                    raise ValueError('Копия повреждена или несовместима')
                names={r[0] for r in candidate.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if names!=set(expected) or candidate.execute("SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view')").fetchone():
                    raise ValueError('Неизвестная схема копии')
                if any([tuple(c) for c in candidate.execute('PRAGMA table_info('+name+')')]!=expected[name] for name in names):
                    raise ValueError('Несовместимые столбцы копии')
                for row in candidate.execute('SELECT body FROM homework'):
                    self._validate_homework(json.loads(row[0]))
                for row in candidate.execute('SELECT preferences FROM users'):
                    values=json.loads(row[0])
                    if not isinstance(values,dict) or set(values)-set(USER_DEFAULTS): raise ValueError('Некорректные настройки копии')
                target=sqlite3.connect(staging)
                try:
                    candidate.backup(target)
                    target.execute('DELETE FROM pending')
                    target.executemany('INSERT OR REPLACE INTO deliveries VALUES(?,?,?)',delivery_rows)
                    for row in audit_rows:
                        if not target.execute('SELECT 1 FROM audit WHERE at=? AND actor=? AND action=? AND target=?',row).fetchone():
                            target.execute('INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)',row)
                    self._log(target,actor,'backup.restored',source.name)
                    target.commit()
                finally: target.close()
            # Nothing above touches the live database. Commit only after validation.
            recovery=self.backup(actor,directory)
            os.replace(staging,self.path)
            return recovery
        finally:
            if staging.exists(): staging.unlink()

    def cancel_pending(self, actor):
        with self.connect() as db:
            db.execute('UPDATE pending SET used=1 WHERE actor=? AND used=0',(actor,))

    def role_definitions(self, actor):
        with self.connect() as db:
            self.require(db,actor,'admin')
            return {**{k:sorted(v) for k,v in ROLE_PERMISSIONS.items()}, **{r['name']:json.loads(r['permissions']) for r in db.execute('SELECT * FROM role_definitions')}}

    def create_role(self, actor, name, permissions):
        if not re.fullmatch('[a-z][a-z0-9_]{1,15}',name) or name in ROLE_PERMISSIONS:
            raise ValueError('Название роли: 2–16 латинских букв, цифр или _, начинается с буквы')
        if not permissions or not set(permissions)<=EXTRA_PERMISSIONS:
            raise ValueError('Выберите допустимые права')
        with self.connect() as db:
            self.require(db,actor,'admin')
            if db.execute('SELECT count(*) FROM role_definitions').fetchone()[0]>=20:
                raise ValueError('Лимит: 20 дополнительных ролей')
            if db.execute('SELECT 1 FROM role_definitions WHERE name=?',(name,)).fetchone():
                raise ValueError('Роль существует; создайте другую, чтобы не менять права незаметно')
            db.execute('INSERT INTO role_definitions VALUES(?,?)',(name,dump(sorted(set(permissions)))))
            self._log(db,actor,'role.created',name)

    def template_suggestion(self, actor, body):
        prefs=self.preferences(actor)
        if not prefs['suggestions'] or 'template' in prefs['dismissed_suggestions'] or prefs.get('suggestion_snooze','')>now(): return False
        keys=('subject','deadline_kind','subgroup')
        with self.connect() as db:
            rows=[json.loads(r[0]) for r in db.execute('SELECT body FROM homework WHERE author=? ORDER BY id DESC LIMIT 3',(actor,))]
            templates=[json.loads(r[0]) for r in db.execute('SELECT body FROM templates WHERE author=?',(actor,))]
        return len(rows)==3 and all(all(r.get(k)==body.get(k) for k in keys) for r in rows) and not any(all(t.get(k)==body.get(k) for k in keys) for t in templates)

    def signatures(self, actor):
        with self.connect() as db:
            self.require(db,actor,'announcement.send')
            return ['']+[r['label'] for r in db.execute('SELECT * FROM signatures ORDER BY label') if not r['owner_only'] or owner_matches(actor,self.owner_id)]

    def set_signature(self, actor, label, enabled):
        if not label.strip() or len(label)>40 or safe_text(label)!=label:
            raise ValueError('Подпись: от 1 до 40 символов, без секретов')
        with self.connect() as db:
            self.require(db,actor,'admin')
            if enabled:
                db.execute('INSERT OR IGNORE INTO signatures VALUES(?,0)',(label,))
            else: db.execute('DELETE FROM signatures WHERE label=?',(label,))
            self._log(db,actor,'signature.changed',label)

    def record_usage(self, chat_id, action):
        if action not in ('schedule','homework'): return
        with self.connect() as db:
            db.execute('INSERT INTO metrics VALUES(?,?,?,1) ON CONFLICT(day,chat_id,action) DO UPDATE SET count=count+1',(now()[:10],chat_id,action))

    def metrics(self, actor):
        with self.connect() as db:
            self.require(db,actor,'admin')
            return [dict(r) for r in db.execute('SELECT * FROM metrics ORDER BY day DESC LIMIT 100')]


    def identity_mode(self, actor):
        with self.connect() as db:
            self.require(db,actor,'admin')
            row=db.execute("SELECT value FROM bot_settings WHERE key='id_mode'").fetchone()
            return row[0] if row else 'disabled'

    def set_identity_mode(self, actor, mode):
        if mode not in ('everyone','allowed','owner','disabled'):
            raise ValueError('Неизвестный режим /id')
        with self.connect() as db:
            self.require(db,actor,'admin')
            db.execute("INSERT INTO bot_settings VALUES('id_mode',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(mode,))
            self._log(db,actor,'security.id_mode',mode)

    def identity_allowed(self, actor):
        if type(actor) is not int or actor<=0 or self.user_blocked(actor): return False
        with self.connect() as db:
            row=db.execute("SELECT value FROM bot_settings WHERE key='id_mode'").fetchone()
            mode=row[0] if row else 'disabled'
            if mode=='everyone': return True
            if mode=='owner': return owner_matches(actor,self.owner_id)
            if mode=='allowed': return self._can(db,actor,'identity.self')
            return False


    def known_users(self, actor, search=''):
        with self.connect() as db:
            self.require(db,actor,'admin')
            # Manually assigned role holders remain selectable even before /start.
            rows=db.execute("""SELECT ids.id,COALESCE(p.display_name,'') AS display_name,
                COALESCE(p.username,'') AS username,COALESCE(p.seen_at,'') AS seen_at
                FROM (SELECT id FROM users UNION SELECT user_id FROM roles UNION SELECT user_id FROM extras) ids
                LEFT JOIN user_profiles p ON p.user_id=ids.id ORDER BY seen_at DESC,ids.id""").fetchall()
            term=search.strip().lstrip('@').casefold()
            return [dict(r) for r in rows if not term or any(term in str(r[key]).casefold() for key in ('id','display_name','username'))]

    def user_roles(self, actor, target):
        with self.connect() as db:
            self.require(db,actor,'admin')
            return [dict(r) for r in db.execute('SELECT name,frozen FROM roles WHERE user_id=? ORDER BY name',(target,))]


    def permission_report(self, actor, target=None):
        from access import PERMISSION_LABELS
        target=actor if target is None else target
        with self.connect() as db:
            if target!=actor: self.require(db,actor,'admin')
            return [(label,self._can(db,target,key)) for key,label in PERMISSION_LABELS.items()]
