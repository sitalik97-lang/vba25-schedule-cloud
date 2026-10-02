import re
import unicodedata

# Latin/Cyrillic look-alikes that commonly appear in filenames/site text.
_HOMOGLYPHS = str.maketrans({
    "A": "А", "B": "В", "C": "С", "E": "Е", "H": "Н", "K": "К",
    "M": "М", "O": "О", "P": "Р", "T": "Т", "X": "Х", "Y": "У",
    "a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "y": "у",
})


def clean_text(value: str | None) -> str:
    if not value:
        return ""
    return " ".join(value.replace("\n", " ").split())


def normalize_group(value: str | None) -> str:
    """Normalize a group identifier for robust matching.

    Example: 'М9-Вба25О-1 + ...' -> 'М9ВБА25О1...'
    """
    text = unicodedata.normalize("NFKC", value or "").translate(_HOMOGLYPHS).upper()
    text = text.replace("Ё", "Е")
    return re.sub(r"[^0-9А-Я]", "", text)


def group_matches(text: str | None, stable_group: str) -> bool:
    return normalize_group(stable_group) in normalize_group(text)
