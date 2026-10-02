"""Deterministic access rules, independent of Telegram and persistence."""
from types import MappingProxyType

SCOPES = frozenset({'PRIVATE', 'GROUP', 'SUPERGROUP'})
LEVELS = ('simple', 'normal', 'advanced', 'maximum')
ROLE_PERMISSIONS = MappingProxyType({
    'user': frozenset({'schedule.read', 'homework.read', 'issue.create', 'preferences.self'}),
    'curator': frozenset({'homework.create', 'homework.edit.own', 'homework.publish',
                          'homework.archive.own', 'homework.history', 'templates.self'}),
})
EXTRA_PERMISSIONS = frozenset().union(*ROLE_PERMISSIONS.values(), {
    'homework.edit.any', 'homework.archive.any', 'announcement.send', 'identity.self'})
CHAT_FEATURES = frozenset({'schedule', 'homework', 'system_notifications',
    'owner_broadcast', 'curator_broadcast', 'statistics'})
DEFAULTS = {scope: {key: key in {'schedule', 'homework', 'owner_broadcast'}
                   for key in CHAT_FEATURES} for scope in SCOPES}
USER_DEFAULTS = {'level': 'simple', 'help': True, 'hidden': [], 'favorites': [],
    'compact': True, 'reminders': False, 'reminder_offsets': [1440],
    'suggestions': True, 'dismissed_suggestions': [], 'preview': True,
    'subgroup': 0, 'reminder_moments': [], 'suggestion_snooze': ''}


def owner_matches(user_id, owner_id):
    return (type(user_id) is int and user_id > 0 and type(owner_id) is int
            and owner_id > 0 and user_id == owner_id)


def allowed(user_id, owner_id, permission, roles=(), extra=(), definitions=None):
    if type(user_id) is not int or user_id <= 0: return False
    definitions = definitions or ROLE_PERMISSIONS
    if permission not in EXTRA_PERMISSIONS | {'admin'}:
        return False
    if owner_matches(user_id, owner_id):
        return True
    if permission == 'admin':
        return False
    return (permission in ROLE_PERMISSIONS['user'] or permission in extra or any(
        not role['frozen'] and permission in definitions.get(role['name'], ())
        for role in roles))


def resolve_feature(scope, feature, global_rules, chat_rules, personal=None, blocked=False):
    if scope not in SCOPES or feature not in CHAT_FEATURES:
        raise ValueError('Unknown scope or feature')
    if blocked:
        return False, 'owner-security'
    value, source = global_rules.get(feature, DEFAULTS[scope][feature]), 'global-default'
    if feature in chat_rules:
        value, source = chat_rules[feature], 'chat-override'
    if (personal or {}).get(feature) is False:
        return False, 'personal'
    return bool(value), source


def visible_actions(registry, preferences, check):
    level = preferences.get('level', 'simple')
    rank = LEVELS.index(level) if level in LEVELS else 0
    actions = [a for a in registry if check(a.get('permission', 'schedule.read'))
               and LEVELS.index(a.get('level', 'simple')) <= rank
               and (a['id'] == 'settings' or a['id'] not in preferences.get('hidden', []))
               and (not a.get('help') or preferences.get('help', True))]
    favorites = preferences.get('favorites', [])
    return sorted(actions, key=lambda a: favorites.index(a['id']) if a['id'] in favorites else len(favorites))

PERMISSION_LABELS = {
    'schedule.read':'Смотреть расписание', 'homework.read':'Читать опубликованные ДЗ',
    'preferences.self':'Настраивать свой интерфейс и напоминания', 'issue.create':'Сообщать о проблемах',
    'homework.create':'Создавать ДЗ', 'homework.edit.own':'Изменять свои ДЗ',
    'homework.publish':'Публиковать ДЗ', 'homework.archive.own':'Архивировать свои ДЗ',
    'homework.history':'Смотреть историю своих ДЗ', 'templates.self':'Создавать личные шаблоны',
    'homework.edit.any':'Изменять чужие ДЗ', 'homework.archive.any':'Архивировать чужие ДЗ',
    'announcement.send':'Отправлять объявления в разрешённые чаты', 'identity.self':'Получать свой ID в ограниченном режиме',
    'admin':'Управлять ботом и правами людей',
}
