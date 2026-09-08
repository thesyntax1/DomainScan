import json
import os
import time

from domainscan.helpers import short


def base_dir():
    return os.path.join(os.path.expanduser("~"), ".domainscan", "history")


def safe_host(host):
    return "".join(char if char.isalnum() or char in ".-_" else "_" for char in host)


def save_run(result, directory=None):
    target_dir = directory or base_dir()
    os.makedirs(target_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    host = safe_host(result["target"]["host"])
    path = os.path.join(target_dir, host + "-" + stamp + ".json")
    data = {"meta": result["meta"], "target": result["target"], "sections": {}}
    for section, items in result["sections"].items():
        if section == "Changes":
            continue
        data["sections"][section] = [{"item": key, "value": value} for key, value in items]
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
    return path


def list_runs(host, directory=None):
    target_dir = directory or base_dir()
    if not os.path.isdir(target_dir):
        return []
    prefix = safe_host(host) + "-"
    paths = []
    for name in os.listdir(target_dir):
        if name.startswith(prefix) and name.endswith(".json"):
            paths.append(os.path.join(target_dir, name))
    paths.sort(key=lambda item: os.path.getmtime(item), reverse=True)
    return paths


def load_run(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    sections = {}
    for section, items in data.get("sections", {}).items():
        sections[section] = [(item["item"], item["value"]) for item in items]
    return {"meta": data.get("meta", {}), "target": data.get("target", {}), "sections": sections}


def prune_old(host, keep=20, directory=None):
    removed = 0
    for path in list_runs(host, directory)[keep:]:
        try:
            os.remove(path)
            removed += 1
        except Exception:
            continue
    return removed


def previous_run(host, current_stamp, directory=None):
    for path in list_runs(host, directory)[:5]:
        try:
            data = load_run(path)
        except Exception:
            continue
        if data["meta"].get("scanned_at", "") != current_stamp:
            return data
    return None


def flatten(result):
    flat = {}
    for section, items in result["sections"].items():
        if section in ("Summary", "Changes"):
            continue
        for key, value in items:
            flat[(section, key)] = value
    return flat


def diff_runs(old, new, cap=200):
    rows = []
    rows.append(("Compared with", str(old["meta"].get("scanned_at", "previous scan"))))
    before = flatten(old)
    after = flatten(new)
    added = [(key, after[key]) for key in after if key not in before]
    removed = [(key, before[key]) for key in before if key not in after]
    changed = [(key, before[key], after[key]) for key in after if key in before and before[key] != after[key]]
    rows.append(("Added", str(len(added))))
    rows.append(("Removed", str(len(removed))))
    rows.append(("Changed", str(len(changed))))
    shown = 0
    for (section, key), value in sorted(added)[:cap]:
        if shown >= cap:
            break
        rows.append(("Added finding", section + " / " + key + " = " + short(value, 160)))
        shown += 1
    for (section, key), value in sorted(removed)[:cap]:
        if shown >= cap:
            break
        rows.append(("Removed finding", section + " / " + key + " (was " + short(value, 120) + ")"))
        shown += 1
    for (section, key), old_value, new_value in sorted(changed)[:cap]:
        if shown >= cap:
            break
        rows.append(("Changed finding", section + " / " + key + ": " + short(old_value, 80) + " -> " + short(new_value, 80)))
        shown += 1
    total = len(added) + len(removed) + len(changed)
    if total > shown:
        rows.append(("Diff note", "Showing " + str(shown) + " of " + str(total)))
    if not total:
        rows.append(("Result", "No differences"))
    return rows


def trend_rows(host, current, directory=None, cap=6):
    rows = []
    runs = []
    for path in list_runs(host, directory)[:cap]:
        try:
            runs.append(load_run(path))
        except Exception:
            continue
    runs = list(reversed(runs))
    if current:
        runs.append(current)
    if len(runs) < 2:
        rows.append(("Trend", "Need at least two scans to show a trend"))
        return rows
    series = []
    for run in runs[-cap:]:
        stamp = str(run.get("meta", {}).get("scanned_at", "?"))[:16]
        count = len(flatten(run))
        series.append((stamp, count))
    rows.append(("Runs in trend", str(len(series))))
    rows.append(("Findings trend", " -> ".join(str(count) for _, count in series)))
    first = series[0][1]
    last = series[-1][1]
    if last > first:
        rows.append(("Trend direction", "+" + str(last - first) + " findings since " + series[0][0]))
    elif last < first:
        rows.append(("Trend direction", str(last - first) + " findings since " + series[0][0]))
    else:
        rows.append(("Trend direction", "Stable at " + str(last) + " findings"))
    return rows
