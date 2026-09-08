"""Tiny persistent settings store (JSON under ~/.domainscan)."""

import json
import os


def base_dir():
    return os.path.join(os.path.expanduser("~"), ".domainscan")


def _path():
    return os.path.join(base_dir(), "settings.json")


def _load():
    try:
        with open(_path(), encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def get(key, default=None):
    return _load().get(key, default)


def set(key, value):
    data = _load()
    data[key] = value
    try:
        os.makedirs(base_dir(), exist_ok=True)
        with open(_path(), "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
        return True
    except Exception:
        return False
