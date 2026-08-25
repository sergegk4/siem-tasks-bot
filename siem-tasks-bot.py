#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import csv
import html
import json
import logging
import os
import re
import sqlite3
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timedelta

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "config.ini"
)

config = configparser.ConfigParser()
config.read(CONFIG_FILE, encoding="utf-8")

HOST = config.get("siem", "host")
TOKEN = config.get("siem", "token")

BASE = f"https://{HOST}"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

TASK_STATUSES = [
    "new", "preparing", "waiting", "running",
    "finishing", "finished", "suspending", "suspended",
    "stopping", "stopped", "failed",
]

TELEGRAM_PROXIES = None

SOURCES_DB_LOCK = threading.Lock()

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger(__name__)


def build_telegram_proxies(cfg):
    if cfg.getboolean("telegram", "no_proxy", fallback=False):
        return {"http": None, "https": None}
    proxy_url = cfg.get("telegram", "proxy", fallback="").strip()
    if proxy_url:
        return {"http": proxy_url, "https": proxy_url}
    return None


def send_tg_message(token, chat_id, text, topic_id=None):
    if not token or not chat_id:
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if topic_id:
        payload["message_thread_id"] = int(topic_id)

    try:
        requests.post(url, json=payload, proxies=TELEGRAM_PROXIES, timeout=15)
    except Exception as e:
        log.error("Ошибка отправки сообщения в TG: %s", e)


def send_tg_document(token, chat_id, file_path, caption="", topic_id=None):
    if not token or not chat_id:
        return
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    data = {"chat_id": chat_id, "caption": caption}
    if topic_id:
        data["message_thread_id"] = int(topic_id)
    try:
        with open(file_path, "rb") as f:
            requests.post(url, data=data, files={"document": f}, proxies=TELEGRAM_PROXIES, timeout=60)
    except Exception as e:
        log.error("Ошибка отправки файла в TG: %s", e)


def get_tasks(text_filter="", status_filter="", limit=1000):
    params = {}
    if text_filter:
        params["mainFilter"] = text_filter
    if status_filter:
        params["additionalFilter"] = status_filter

    r = requests.get(
        BASE + "/api/scanning/v3/scanner_tasks",
        headers=HEADERS,
        params=params,
        verify=False,
        timeout=60,
    )

    if r.status_code == 404:
        payload = {"offset": 0, "limit": limit, "orderBy": "name", "orderDirection": "asc", "validate": False}
        if text_filter:
            payload["text"] = text_filter
        if status_filter:
            payload["statuses"] = status_filter
        r = requests.post(
            BASE + "/api/scanning/v4/scanner_tasks",
            headers=HEADERS,
            json=payload,
            verify=False,
            timeout=60,
        )

    r.raise_for_status()
    data = r.json()
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("items", "rows", "data", "tasks"):
            if key in data:
                return data[key]
    return []


def start_task(task_id):
    r = requests.post(
        BASE + "/api/scanning/v3/scanner_tasks/" + task_id + "/start",
        headers=HEADERS,
        json={},
        verify=False,
        timeout=30,
    )
    if r.status_code in (200, 202, 204):
        return True
    r.raise_for_status()
    return False


def extract_status(task):
    status = task.get("status", "")
    if isinstance(status, str):
        return status
    if isinstance(status, list) and status:
        return str(status[0])
    if isinstance(status, dict):
        return status.get("value", str(status))
    return str(status) if status else "unknown"


def extract_groups(task):
    groups = task.get("groups", [])
    if not groups:
        return ""
    names = []
    for g in groups:
        if isinstance(g, dict):
            names.append(g.get("name") or g.get("id") or "")
        elif isinstance(g, str):
            names.append(g)
    return "; ".join(filter(None, names))


def build_tasks_info(raw_tasks):
    result = []
    for task in raw_tasks:
        result.append({
            "id": task.get("id", ""),
            "name": task.get("name", ""),
            "_status": extract_status(task),
            "groups": extract_groups(task),
            "_raw": task,
        })
    return result


def filter_by_group(tasks_info, group_name):
    if not group_name:
        return tasks_info
    group_name_l = group_name.lower()
    return [t for t in tasks_info if group_name_l in (t.get("groups", "").lower())]


# =========================================================================
# Мониторинг потока событий (Events Storage, /api/events/v2/events)
# =========================================================================

def get_match_value(task, source, fallback_name):
    if source == "id":
        return task.get("id") or fallback_name
    raw_task = task.get("_raw", {}) or {}
    if source == "scope":
        scope = raw_task.get("scope") or []
        if isinstance(scope, list) and scope:
            first = scope[0]
            if isinstance(first, dict):
                return first.get("name") or fallback_name
        return fallback_name
    if source == "agent":
        agent = raw_task.get("agent") or []
        if isinstance(agent, list) and agent:
            first = agent[0]
            if isinstance(first, dict):
                return first.get("name") or fallback_name
        elif isinstance(agent, dict):
            return agent.get("name") or fallback_name
        return fallback_name
    return fallback_name


def build_events_where(field, operator, value):
    value_escaped = str(value).replace('"', '\\"')
    if operator == "contains":
        return f'{field} contains "{value_escaped}"'
    return f'{field} = "{value_escaped}"'


def get_events_count(where, time_from_ts, time_to_ts):
    payload = {
        "filter": {
            "aggregateBy": [],
            "aliases": None,
            "distributeBy": [],
            "groupBy": [],
            "orderBy": [],
            "select": ["time"],
            "top": None,
            "where": where,
        },
        "groupValues": [],
        "timeFrom": int(time_from_ts),
        "timeTo": int(time_to_ts),
    }
    r = requests.post(
        BASE + "/api/events/v2/events",
        headers=HEADERS,
        params={"limit": 1},
        json=payload,
        verify=False,
        timeout=60,
    )
    r.raise_for_status()
    data = r.json()
    return int(data.get("totalCount", 0))


def notify_events_drop(problems, window_minutes, tg_token, tg_chat_id, tg_topic_id=None):
    lines = [
        "⚠️ <b>Поток событий упал</b>",
        f"⏱ <b>Окно проверки:</b> {window_minutes} мин",
        "",
    ]
    for name, count, eps, state, threshold in problems:
        if state == "empty":
            lines.append(f"🧩 <b>{name}</b> — событий нет вообще (0 за {window_minutes} мин, порог {threshold} eps)")
        else:
            lines.append(f"🧩 <b>{name}</b> — {count} событий за {window_minutes} мин (~{eps:.3f} eps, порог {threshold} eps)")
    send_tg_message(tg_token, tg_chat_id, "\n".join(lines), topic_id=tg_topic_id)


def notify_events_recovered(recovered, window_minutes, tg_token, tg_chat_id, tg_topic_id=None):
    lines = [
        "✅ <b>Поток событий восстановился</b>",
        "",
    ]
    for name, count, eps in recovered:
        lines.append(f"🧩 <b>{name}</b> — {count} событий за {window_minutes} мин (~{eps:.3f} eps)")
    send_tg_message(tg_token, tg_chat_id, "\n".join(lines), topic_id=tg_topic_id)


def is_quiet_period(events_cfg, now_dt=None):
    if not events_cfg.get("quiet_enabled"):
        return False

    tz_name = events_cfg.get("quiet_timezone")
    if now_dt is None:
        try:
            if tz_name:
                from zoneinfo import ZoneInfo
                now_dt = datetime.now(ZoneInfo(tz_name))
            else:
                now_dt = datetime.now()
        except Exception as e:
            log.warning("Не удалось применить часовой пояс '%s' для quiet_hours, использую локальное время сервера: %s", tz_name, e)
            now_dt = datetime.now()

    if events_cfg.get("quiet_skip_weekends") and now_dt.weekday() >= 5:
        return True

    start_str = events_cfg.get("quiet_start")
    end_str = events_cfg.get("quiet_end")
    if not start_str or not end_str:
        return False

    try:
        sh, sm = (int(x) for x in start_str.strip().split(":"))
        eh, em = (int(x) for x in end_str.strip().split(":"))
    except Exception as e:
        log.warning("Некорректный формат quiet_start/quiet_end ('%s'/'%s'): %s", start_str, end_str, e)
        return False

    start_t = now_dt.replace(hour=sh, minute=sm, second=0, microsecond=0)
    end_t = now_dt.replace(hour=eh, minute=em, second=0, microsecond=0)

    if start_t <= end_t:
        return start_t <= now_dt <= end_t
    return now_dt >= start_t or now_dt <= end_t


def load_custom_eps_map(cfg):
    custom_eps_map = {}
    if not cfg.has_section("events"):
        return custom_eps_map

    indices = set()
    for opt in cfg.options("events"):
        m = re.match(r"^custom_task(\d+)$", opt)
        if m:
            indices.add(int(m.group(1)))

    for idx in sorted(indices):
        task_name = cfg.get("events", f"custom_task{idx}", fallback="").strip()
        eps_raw = cfg.get("events", f"custom_eps_task{idx}", fallback="").strip()
        if not task_name or not eps_raw:
            log.warning("Пропущена кастомная настройка custom_task%s / custom_eps_task%s — не заполнено имя задачи или порог", idx, idx)
            continue
        try:
            custom_eps_map[task_name.lower()] = float(eps_raw)
        except ValueError:
            log.warning("Некорректное значение custom_eps_task%s = '%s', пропускаю", idx, eps_raw)

    return custom_eps_map


def check_events_stream(tasks_info, events_cfg, events_state, tg_token, tg_chat_id, tg_events_topic_id, verbose=False, ignore_quiet=False):
    if not ignore_quiet and is_quiet_period(events_cfg):
        if verbose:
            log.info("[events] сейчас тихий период (quiet_hours/выходные) — проверка потока событий пропущена")
        return

    window_seconds = events_cfg["window_minutes"] * 60
    now_ts = int(time.time())
    time_from = now_ts - window_seconds
    time_to = now_ts

    custom_eps_map = events_cfg.get("custom_eps_map", {})

    problems = []
    recovered = []

    for t in tasks_info:
        task_id = t["id"]
        name = t["name"]

        value = get_match_value(t, events_cfg["match_value_source"], name)
        where = build_events_where(events_cfg["match_field"], events_cfg["match_operator"], value)

        try:
            count = get_events_count(where, time_from, time_to)
        except Exception as e:
            log.error("Ошибка получения статистики событий для '%s': %s", name, e)
            continue

        eps = count / window_seconds if window_seconds else 0.0

        effective_min_eps = custom_eps_map.get(name.strip().lower(), events_cfg["min_eps"])

        if verbose:
            log.info("[events] '%s' where=%s -> count=%s eps=%.4f (порог=%s)", name, where, count, eps, effective_min_eps)

        if count == 0:
            state = "empty"
        elif eps < effective_min_eps:
            state = "low"
        else:
            state = "ok"

        prev = events_state.get(task_id, {"state": "ok", "last_alert_ts": 0})
        prev_state = prev["state"]

        if state in ("low", "empty"):
            should_alert = False
            if prev_state == "ok":
                should_alert = True
            elif events_cfg["repeat_alert_seconds"] > 0 and \
                    (now_ts - prev["last_alert_ts"]) >= events_cfg["repeat_alert_seconds"]:
                should_alert = True

            if should_alert:
                problems.append((name, count, eps, state, effective_min_eps))
                events_state[task_id] = {"state": state, "last_alert_ts": now_ts}
            else:
                events_state[task_id] = {"state": state, "last_alert_ts": prev["last_alert_ts"]}
        else:
            if prev_state in ("low", "empty") and events_cfg.get("notify_recovery", True):
                recovered.append((name, count, eps))
            events_state[task_id] = {"state": "ok", "last_alert_ts": 0}

    if problems:
        notify_events_drop(problems, events_cfg["window_minutes"],
                            tg_token, tg_chat_id, tg_events_topic_id)
    if recovered:
        notify_events_recovered(recovered, events_cfg["window_minutes"],
                                 tg_token, tg_chat_id, tg_events_topic_id)


# =========================================================================
# Мониторинг источников (event_src.host) по каждой задаче группы
# =========================================================================

def build_pdql_group_query(task_id, group_field="event_src.host", limit=10000):
    task_id_escaped = str(task_id).replace('"', '\\"')
    return (
        f'filter(task_id = "{task_id_escaped}") | '
        f'select(time, {group_field}, text) | sort(time desc) | '
        f'group(key: [{group_field}], agg: COUNT(*) as Cnt) | '
        f'sort(Cnt desc) | limit({limit})'
    )


def build_events_ui_url(url_template, host, task_id, time_from_ts, time_to_ts):
    """Строит ссылку на страницу 'События' в UI MP SIEM для конкретной
    задачи (список событий, отфильтрованных по task_id, за то же окно).
    Формат подтверждён реальной ссылкой с вкладки задачи:
      https://<host>/#/events/view?groupId=-1&filterId=-1&
        where=task_id%20%3D%20<id>&period=range&start=<ms>&end=<ms>"""
    where = f"task_id = {task_id}"
    where_encoded = urllib.parse.quote(where, safe="")
    start_ms = int(time_from_ts) * 1000
    end_ms = int(time_to_ts) * 1000
    try:
        url = url_template.format(
            host=host,
            task_id=task_id,
            where=where_encoded,
            start=start_ms,
            end=end_ms,
        )
    except Exception as e:
        log.warning("[sources] Не удалось собрать ссылку на UI по шаблону events_ui_url_template: %s", e)
        return ""
    return url.replace("&", "&amp;")


def get_source_group_counts_grouped(task_id, time_from_ts, time_to_ts, group_field="event_src.host", limit=10000):
    """Агрегация источников через /api/events/v3/events/aggregation (сырой
    PDQL-текст в поле filter). Возвращает (counts, ok)."""
    pdql = build_pdql_group_query(task_id, group_field, limit)
    payload = {
        "filter": pdql,
        "timeFrom": int(time_from_ts),
        "timeTo": int(time_to_ts),
    }
    r = requests.post(
        BASE + "/api/events/v3/events/aggregation",
        headers=HEADERS,
        json=payload,
        verify=False,
        timeout=120,
    )
    if r.status_code >= 400:
        log.warning("[sources] /events/aggregation вернул HTTP %s (task_id=%s): %s",
                    r.status_code, task_id, r.text[:800])
        return {}, False

    data = r.json()

    errors = data.get("errors") or []
    if errors:
        log.debug("[sources] task_id=%s: предупреждения API (%s)",
                   task_id, "; ".join(e.get("error", {}).get("message", str(e)) for e in errors))

    rows = data.get("rows") or []
    counts = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        groups = row.get("groups") or []
        values = row.get("values") or []
        if not groups:
            continue
        src = groups[0]
        if isinstance(src, list):
            src = src[0] if src else None
        if src is None:
            continue
        cnt = values[0] if values else 0
        try:
            cnt = int(cnt)
        except (TypeError, ValueError):
            cnt = 0
        src = str(src)
        counts[src] = counts.get(src, 0) + cnt

    if data.get("hasMoreResults"):
        log.warning("[sources] task_id=%s: hasMoreResults=true — источников больше, чем limit=%s, "
                    "часть могла не попасть в выборку", task_id, limit)

    return counts, True


def get_source_group_counts_raw_paginated(task_id, time_from_ts, time_to_ts, group_field, limit=10000, max_pages=5):
    """Запасной путь (если /events/aggregation недоступен): постраничная
    выгрузка сырых событий с подсчётом на своей стороне, с небольшим
    потолком страниц, чтобы не зависать на очень больших объёмах."""
    where = f'task_id = "{task_id}"'

    try:
        real_total = get_events_count(where, time_from_ts, time_to_ts)
    except Exception as e:
        log.warning("[sources] task_id=%s: не удалось получить totalCount (%s)", task_id, e)
        real_total = None

    pages_needed = max_pages
    if real_total:
        pages_needed = min(max_pages, max(1, -(-real_total // limit)))

    counts = {}
    total_events = 0
    token = None
    last_errors_logged = False

    for page in range(pages_needed):
        payload = {
            "filter": {
                "aggregateBy": [],
                "aliases": None,
                "distributeBy": [],
                "groupBy": [],
                "orderBy": [],
                "select": [group_field],
                "top": None,
                "where": where,
            },
            "groupValues": [],
            "timeFrom": int(time_from_ts),
            "timeTo": int(time_to_ts),
        }
        if token:
            payload["token"] = token

        r = requests.post(
            BASE + "/api/events/v2/events",
            headers=HEADERS,
            params={"limit": limit},
            json=payload,
            verify=False,
            timeout=120,
        )
        if r.status_code >= 400:
            log.error("[sources] API вернул HTTP %s (task_id=%s, page=%s): %s",
                       r.status_code, task_id, page, r.text[:500])
        r.raise_for_status()
        data = r.json()

        errors = data.get("errors") or []
        if errors and not last_errors_logged:
            log.debug("[sources] task_id=%s: предупреждения API (%s)",
                       task_id, "; ".join(e.get("error", {}).get("message", str(e)) for e in errors))
            last_errors_logged = True

        events = data.get("events") or []
        new_token = data.get("token")

        for ev in events:
            if not isinstance(ev, dict):
                continue
            v = ev.get(group_field)
            if isinstance(v, list):
                v = v[0] if v else None
            if v is None:
                continue
            v = str(v)
            counts[v] = counts.get(v, 0) + 1

        total_events += len(events)

        if real_total and total_events >= real_total:
            break
        if not events or len(events) < limit or not new_token or new_token == token:
            break
        token = new_token

    if real_total and total_events < real_total:
        pct = 100.0 * total_events / real_total
        log.warning("[sources] task_id=%s (fallback без /aggregation): получено %s из %s событий (%.1f%%) — "
                    "список источников заведомо неполный", task_id, total_events, real_total, pct)

    return counts


def get_source_group_counts(task_id, time_from_ts, time_to_ts, group_field="event_src.host", limit=10000, fallback_max_pages=5):
    try:
        counts, ok = get_source_group_counts_grouped(task_id, time_from_ts, time_to_ts, group_field, limit=limit)
    except Exception as e:
        log.warning("[sources] task_id=%s: ошибка запроса к /events/aggregation (%s), пробую запасной путь", task_id, e)
        counts, ok = {}, False

    if ok:
        return counts

    log.warning("[sources] task_id=%s: /events/aggregation не сработал, использую запасной "
                "постраничный сбор (ограничен %s страницами)", task_id, fallback_max_pages)
    return get_source_group_counts_raw_paginated(task_id, time_from_ts, time_to_ts, group_field,
                                                  limit=limit, max_pages=fallback_max_pages)


def init_sources_db(db_path):
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS source_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT NOT NULL,
            task_name TEXT NOT NULL,
            source TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            collected_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_source_stats_task_source ON source_stats(task_id, source)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_source_stats_collected ON source_stats(collected_at)")
    conn.commit()
    return conn


def cleanup_old_stats(conn, retention_days):
    cutoff = (datetime.utcnow() - timedelta(days=retention_days)).isoformat()
    with SOURCES_DB_LOCK:
        cur = conn.execute("DELETE FROM source_stats WHERE collected_at < ?", (cutoff,))
        conn.commit()
    if cur.rowcount:
        log.info("[sources] Удалено %s устаревших записей статистики (старше %s дней)", cur.rowcount, retention_days)
    return cur.rowcount


def save_source_counts(conn, task_id, task_name, counts, collected_at):
    rows = [(task_id, task_name, src, cnt, collected_at) for src, cnt in counts.items()]
    with SOURCES_DB_LOCK:
        conn.executemany(
            "INSERT INTO source_stats (task_id, task_name, source, event_count, collected_at) VALUES (?, ?, ?, ?, ?)",
            rows
        )
        conn.commit()


def is_business_day(d):
    return d.weekday() < 5


def business_days_between(start_date, end_date):
    if end_date <= start_date:
        return 0
    count = 0
    d = start_date + timedelta(days=1)
    while d <= end_date:
        if is_business_day(d):
            count += 1
        d += timedelta(days=1)
    return count


def is_work_time(cfg, now_dt):
    if cfg.get("work_days_only", True) and now_dt.weekday() >= 5:
        return False
    start_str = cfg.get("work_start")
    end_str = cfg.get("work_end")
    if not start_str or not end_str:
        return True
    try:
        sh, sm = (int(x) for x in start_str.strip().split(":"))
        eh, em = (int(x) for x in end_str.strip().split(":"))
    except Exception:
        return True
    start_t = now_dt.replace(hour=sh, minute=sm, second=0, microsecond=0)
    end_t = now_dt.replace(hour=eh, minute=em, second=0, microsecond=0)
    return start_t <= now_dt <= end_t


def is_report_due(cfg, now_dt):
    rt = cfg.get("report_time")
    if not rt:
        return False
    try:
        rh, rm = (int(x) for x in rt.strip().split(":"))
    except Exception:
        return False
    report_t = now_dt.replace(hour=rh, minute=rm, second=0, microsecond=0)
    return now_dt >= report_t


def collect_sources_stats(tasks_info, sources_cfg, conn):
    """Собирает статистику источников по каждой задаче и пишет её в БД.
    Возвращает список результатов вида {"task_name", "source_count",
    "ui_url"}, где source_count=None означает "не удалось получить
    данные об источниках"."""
    now_ts = int(time.time())
    window_seconds = sources_cfg["collect_window_hours"] * 3600
    time_from = now_ts - window_seconds
    time_to = now_ts
    collected_at = datetime.utcnow().isoformat()

    results = []

    for t in tasks_info:
        task_id = t["id"]
        task_name = t["name"]

        ui_url = build_events_ui_url(
            sources_cfg["events_ui_url_template"], HOST, task_id, time_from, time_to
        )

        try:
            counts = get_source_group_counts(
                task_id, time_from, time_to, sources_cfg["group_field"],
                fallback_max_pages=sources_cfg.get("fallback_max_pages", 5)
            )
        except Exception as e:
            log.error("[sources] Ошибка получения статистики источников для '%s': %s", task_name, e)
            results.append({"task_name": task_name, "source_count": None, "ui_url": ui_url})
            continue

        if not counts:
            log.warning(
                "[sources] '%s' — источники не найдены за последние %s ч "
                "(либо задача не шлёт события, либо формат ответа не распознан — см. DEBUG-лог)",
                task_name, sources_cfg["collect_window_hours"]
            )
            results.append({"task_name": task_name, "source_count": None, "ui_url": ui_url})
            continue

        save_source_counts(conn, task_id, task_name, counts, collected_at)
        top_src = sorted(counts.items(), key=lambda x: -x[1])[:5]
        top_str = ", ".join(f"{s}={c}" for s, c in top_src)
        log.info("[sources] '%s' — собрано %s источников за %s ч (топ: %s)",
                  task_name, len(counts), sources_cfg["collect_window_hours"], top_str)
        results.append({"task_name": task_name, "source_count": len(counts), "ui_url": ui_url})

    return results


def build_sources_summary(results, window_hours):
    """Формирует текст сводного сообщения 'Общая статистика' по итогам
    одного цикла сбора статистики источников. Имя задачи — кликабельная
    ссылка на список событий этой задачи в UI MP SIEM за то же окно.
    Задачи, для которых не удалось получить данные, помечаются отдельно."""
    lines = [
        "📊 <b>Общая статистика источников</b>",
        f"⏱ <b>Окно сбора:</b> последние {window_hours} ч",
        "",
    ]
    total_sources = 0
    for r in sorted(results, key=lambda x: x["task_name"].lower()):
        name_escaped = html.escape(r["task_name"])
        if r.get("ui_url"):
            name_html = f'<a href="{r["ui_url"]}">{name_escaped}</a>'
        else:
            name_html = f"<b>{name_escaped}</b>"

        if r["source_count"] is None:
            lines.append(f"🧩 {name_html} — отсутствуют данные об источниках")
        else:
            lines.append(f"🧩 {name_html} — {r['source_count']} источников")
            total_sources += r["source_count"]
    lines.append("")
    lines.append(f"Σ Всего источников (сумма по задачам): {total_sources}")
    return "\n".join(lines)


def collect_sources_stats_background(tasks_info, sources_cfg, conn, tg_token, tg_chat_id, tg_sources_topic_id):
    try:
        results = collect_sources_stats(tasks_info, sources_cfg, conn)
        cleanup_old_stats(conn, sources_cfg["retention_days"])

        if sources_cfg.get("notify_summary") and tg_token and tg_chat_id:
            summary_text = build_sources_summary(results, sources_cfg["collect_window_hours"])
            send_tg_message(tg_token, tg_chat_id, summary_text, topic_id=tg_sources_topic_id)
    except Exception as e:
        log.error("[sources] Ошибка фонового сбора статистики источников: %s", e)
    finally:
        log.debug("[sources] Фоновый сбор статистики источников завершён")


def build_stale_sources_report(conn, tasks_info, threshold, mode="business_days"):
    """Ищет источники, у которых с последнего снимка с событиями прошло
    больше threshold единиц времени. mode:
      - "business_days" (боевой режим) — threshold в рабочих днях (пн-пт,
        простой календарь без праздников), считается по календарным датам.
      - "minutes" (только для ручной проверки через --report-now
        --stale-minutes) — threshold в минутах, считается по точному
        времени последнего снимка, удобно для быстрого теста без
        ожидания реального устаревания."""
    now_dt = datetime.utcnow()
    task_names = {t["id"]: t["name"] for t in tasks_info}

    with SOURCES_DB_LOCK:
        cur = conn.execute("""
            SELECT task_id, task_name, source, MAX(collected_at) AS last_seen
            FROM source_stats
            WHERE event_count > 0
            GROUP BY task_id, source
        """)
        rows = cur.fetchall()

    problems = []
    for task_id, task_name, source, last_seen in rows:
        try:
            last_dt = datetime.fromisoformat(last_seen)
        except Exception:
            continue

        if mode == "minutes":
            elapsed = (now_dt - last_dt).total_seconds() / 60.0
            is_stale = elapsed > threshold
            elapsed_display = round(elapsed, 1)
        else:
            elapsed = business_days_between(last_dt.date(), now_dt.date())
            is_stale = elapsed > threshold
            elapsed_display = elapsed

        if is_stale:
            problems.append({
                "task_id": task_id,
                "task_name": task_names.get(task_id, task_name),
                "source": source,
                "last_seen": last_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "elapsed": elapsed_display,
                "mode": mode,
            })
    problems.sort(key=lambda p: (-p["elapsed"], p["task_name"], p["source"]))
    return problems


def write_stale_sources_csv(problems, csv_dir, mode="business_days"):
    os.makedirs(csv_dir, exist_ok=True)
    elapsed_col = "minutes_no_logs" if mode == "minutes" else "business_days_no_logs"
    suffix = "_test_minutes" if mode == "minutes" else ""
    fname = os.path.join(csv_dir, f"stale_sources_{datetime.now().strftime('%Y%m%d_%H%M%S')}{suffix}.csv")
    with open(fname, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(["task_name", "task_id", "source", "last_event_date", elapsed_col])
        for p in problems:
            writer.writerow([p["task_name"], p["task_id"], p["source"], p["last_seen"], p["elapsed"]])
    return fname


def run_daily_stale_report(tasks_info, sources_cfg, conn, tg_token, tg_chat_id, tg_topic_id, threshold=None, mode="business_days"):
    if threshold is None:
        threshold = sources_cfg["stale_business_days"]

    problems = build_stale_sources_report(conn, tasks_info, threshold, mode=mode)

    unit_label = "мин" if mode == "minutes" else "раб. дней"
    if not problems:
        log.info("[sources] Молчащих источников (> %s %s без логов) не найдено", threshold, unit_label)
        return

    csv_path = write_stale_sources_csv(problems, sources_cfg["csv_dir"], mode=mode)
    log.info("[sources] Сформирован отчёт %s (%s источников)", csv_path, len(problems))

    if sources_cfg.get("report_via_telegram") and tg_token and tg_chat_id:
        test_prefix = "🧪 <b>[ТЕСТ, режим минут]</b> " if mode == "minutes" else ""
        caption = (
            f"{test_prefix}📄 <b>Молчащие источники</b> (&gt;{threshold} {unit_label} без логов): "
            f"{len(problems)} шт."
        )
        send_tg_message(tg_token, tg_chat_id, caption, topic_id=tg_topic_id)
        send_tg_document(tg_token, tg_chat_id, csv_path,
                          caption=f"stale_sources_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                          topic_id=tg_topic_id)


def load_sources_config(cfg):
    enabled = cfg.getboolean("sources", "enabled", fallback=False)
    return {
        "enabled": enabled,
        "db_path": cfg.get("sources", "db_path", fallback="siem_sources.db"),
        "group_field": cfg.get("sources", "group_field", fallback="event_src.host"),
        "collect_interval_hours": cfg.getint("sources", "collect_interval_hours", fallback=4),
        "collect_window_hours": cfg.getint("sources", "collect_window_hours", fallback=4),
        "work_start": cfg.get("sources", "work_start", fallback="09:00"),
        "work_end": cfg.get("sources", "work_end", fallback="18:00"),
        "work_days_only": cfg.getboolean("sources", "work_days_only", fallback=True),
        "stale_business_days": cfg.getint("sources", "stale_business_days", fallback=2),
        "retention_days": cfg.getint("sources", "retention_days", fallback=90),
        "report_time": cfg.get("sources", "report_time", fallback="09:30"),
        "csv_dir": cfg.get("sources", "csv_dir", fallback="reports"),
        "report_via_telegram": cfg.getboolean("sources", "report_via_telegram", fallback=True),
        "fallback_max_pages": cfg.getint("sources", "fallback_max_pages", fallback=5),
        "notify_summary": cfg.getboolean("sources", "notify_summary", fallback=False),
        "events_ui_url_template": cfg.get(
            "sources", "events_ui_url_template",
            fallback="https://{host}/#/events/view?groupId=-1&filterId=-1&where={where}&period=range&start={start}&end={end}"
        ),
    }


# =========================================================================
# Мониторинг статусов задач (как было)
# =========================================================================

def notify_status_change(task_name, old_status, new_status, tg_token, tg_chat_id, tg_topic_id=None):
    text = (
        f"📡 <b>Статус задачи изменился</b>\n"
        f"🧩 <b>Задача:</b> {task_name}\n"
        f"➡️ {old_status} → {new_status}"
    )
    send_tg_message(tg_token, tg_chat_id, text, topic_id=tg_topic_id)


def notify_restart(task_name, task_id, tg_token, tg_chat_id, tg_topic_id=None):
    text = (
        f"♻️ <b>Задача перезапущена</b>\n"
        f"🧩 <b>Задача:</b> {task_name}\n"
        f"🆔 <b>ID:</b> {task_id}"
    )
    send_tg_message(tg_token, tg_chat_id, text, topic_id=tg_topic_id)


def notify_bot_started(group_name, restart, interval, events_cfg, sources_cfg, tg_token, tg_chat_id, tg_topic_id=None):
    text = (
        f"🟢 <b>Мониторинг MP SIEM запущен</b>\n"
        f"👥 <b>Группа:</b> {group_name}\n"
        f"♻️ <b>Перезапуск:</b> {'включён' if restart else 'выключен'}\n"
        f"⏱ <b>Интервал проверки статусов:</b> {interval} сек\n"
    )
    if events_cfg["enabled"]:
        text += (
            f"📉 <b>Мониторинг потока событий:</b> включён "
            f"(окно {events_cfg['window_minutes']} мин, порог {events_cfg['min_eps']} eps, "
            f"проверка каждые {events_cfg['check_interval']} сек)\n"
        )
        if events_cfg.get("custom_eps_map"):
            custom_list = ", ".join(f"{n}={v}" for n, v in events_cfg["custom_eps_map"].items())
            text += f"🎯 <b>Кастомные пороги:</b> {custom_list}\n"
        if events_cfg.get("quiet_enabled"):
            qh = f"{events_cfg.get('quiet_start') or '-'}–{events_cfg.get('quiet_end') or '-'}"
            wk = ", выходные целиком" if events_cfg.get("quiet_skip_weekends") else ""
            text += f"🌙 <b>Тихие часы:</b> {qh}{wk}\n"
    else:
        text += "📉 <b>Мониторинг потока событий:</b> выключен\n"

    if sources_cfg["enabled"]:
        text += (
            f"🗂 <b>Мониторинг источников:</b> включён "
            f"(снимок каждые {sources_cfg['collect_interval_hours']} ч в рабочее время "
            f"{sources_cfg['work_start']}-{sources_cfg['work_end']} пн-пт, "
            f"порог молчания {sources_cfg['stale_business_days']} раб. дн., "
            f"отчёт в {sources_cfg['report_time']}, хранение статистики {sources_cfg['retention_days']} дн."
        )
        if sources_cfg.get("notify_summary"):
            text += ", сводка после каждого сбора включена"
        text += ")\n"
    else:
        text += "🗂 <b>Мониторинг источников:</b> выключен\n"

    send_tg_message(tg_token, tg_chat_id, text, topic_id=tg_topic_id)


def monitor_group(group_name, restart=False, interval=60, once=False,
                   tg_token="", tg_chat_id="", tg_topic_id=None,
                   events_cfg=None, tg_events_topic_id=None, events_verbose=False,
                   sources_cfg=None, sources_conn=None, tg_sources_topic_id=None):
    last_status_map = {}
    events_state = {}
    last_events_check_ts = 0.0
    last_sources_collect_ts = 0.0
    last_sources_report_date = None
    sources_first_run_done = False
    sources_thread = None

    if events_cfg is None:
        events_cfg = {"enabled": False}
    if sources_cfg is None:
        sources_cfg = {"enabled": False}

    while True:
        try:
            raw_tasks = get_tasks()
            tasks_info = filter_by_group(build_tasks_info(raw_tasks), group_name)

            for t in tasks_info:
                task_id = t["id"]
                name = t["name"]
                st = t["_status"].lower()

                prev_status = last_status_map.get(task_id)

                if prev_status is None:
                    last_status_map[task_id] = st
                elif prev_status != st:
                    notify_status_change(name, prev_status, st, tg_token, tg_chat_id, tg_topic_id)
                    last_status_map[task_id] = st

                if st in ("failed", "stopped", "finished") and restart:
                    try:
                        if start_task(task_id):
                            notify_restart(name, task_id, tg_token, tg_chat_id, tg_topic_id)
                    except Exception as e:
                        log.error("Ошибка перезапуска '%s': %s", name, e)

            if events_cfg["enabled"] and tasks_info:
                now = time.time()
                if now - last_events_check_ts >= events_cfg["check_interval"]:
                    check_events_stream(
                        tasks_info, events_cfg, events_state,
                        tg_token, tg_chat_id, tg_events_topic_id,
                        verbose=events_verbose,
                    )
                    last_events_check_ts = now

            if sources_cfg["enabled"] and tasks_info and sources_conn is not None:
                now = time.time()
                now_dt = datetime.now()
                collect_interval_seconds = sources_cfg["collect_interval_hours"] * 3600

                sources_thread_busy = sources_thread is not None and sources_thread.is_alive()

                should_collect = not sources_first_run_done
                if not should_collect and (now - last_sources_collect_ts >= collect_interval_seconds):
                    should_collect = is_work_time(sources_cfg, now_dt)

                if should_collect and sources_thread_busy:
                    log.debug("[sources] Предыдущий фоновый сбор ещё не завершён — пропускаю запуск нового")
                elif should_collect:
                    tasks_snapshot = list(tasks_info)
                    sources_thread = threading.Thread(
                        target=collect_sources_stats_background,
                        args=(tasks_snapshot, sources_cfg, sources_conn, tg_token, tg_chat_id, tg_sources_topic_id),
                        daemon=True,
                        name="sources-collect",
                    )
                    sources_thread.start()
                    last_sources_collect_ts = now
                    sources_first_run_done = True
                    log.info("[sources] Запущен фоновый сбор статистики источников (не блокирует проверку статусов)")

                today_str = now_dt.strftime("%Y-%m-%d")
                if is_report_due(sources_cfg, now_dt) and last_sources_report_date != today_str:
                    try:
                        run_daily_stale_report(
                            tasks_info, sources_cfg, sources_conn,
                            tg_token, tg_chat_id, tg_sources_topic_id
                        )
                    except Exception as e:
                        log.error("[sources] Ошибка формирования суточного отчёта: %s", e)
                    last_sources_report_date = today_str

        except Exception as e:
            log.error("Ошибка мониторинга: %s", e)

        if once:
            break

        time.sleep(interval)


def load_events_config(cfg):
    enabled = cfg.getboolean("events", "enabled", fallback=False)
    return {
        "enabled": enabled,
        "check_interval": cfg.getint("events", "check_interval", fallback=60),
        "window_minutes": cfg.getint("events", "window_minutes", fallback=5),
        "min_eps": cfg.getfloat("events", "min_eps", fallback=0.5),
        "match_field": cfg.get("events", "match_field", fallback="task_id"),
        "match_operator": cfg.get("events", "match_operator", fallback="="),
        "match_value_source": cfg.get("events", "match_value_source", fallback="id"),
        "repeat_alert_seconds": cfg.getint("events", "repeat_alert_minutes", fallback=30) * 60,
        "notify_recovery": cfg.getboolean("events", "notify_recovery", fallback=True),
        "custom_eps_map": load_custom_eps_map(cfg),
        "quiet_enabled": cfg.getboolean("events", "quiet_enabled", fallback=False),
        "quiet_start": cfg.get("events", "quiet_start", fallback=None),
        "quiet_end": cfg.get("events", "quiet_end", fallback=None),
        "quiet_skip_weekends": cfg.getboolean("events", "quiet_skip_weekends", fallback=False),
        "quiet_timezone": cfg.get("events", "quiet_timezone", fallback=None) or None,
    }


def get_cli_arg_value(flag_name):
    """Возвращает значение аргумента командной строки вида
    '--flag N' или '--flag=N', либо None, если флаг не передан."""
    for i, arg in enumerate(sys.argv):
        if arg == flag_name and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
        if arg.startswith(flag_name + "="):
            return arg.split("=", 1)[1]
    return None


def main():
    global TELEGRAM_PROXIES

    cfg = configparser.ConfigParser()
    cfg.read(CONFIG_FILE, encoding="utf-8")

    group_name = cfg.get("monitor", "group")
    restart = cfg.getboolean("monitor", "restart", fallback=False)
    interval = cfg.getint("monitor", "interval", fallback=60)
    once = cfg.getboolean("monitor", "once", fallback=False)

    tg_enabled = cfg.getboolean("telegram", "enabled", fallback=False)

    tg_token = ""
    tg_chat_id = ""
    tg_topic_id = None
    tg_events_topic_id = None
    tg_sources_topic_id = None

    if tg_enabled:
        tg_token = cfg.get("telegram", "token", fallback="")
        tg_chat_id = cfg.get("telegram", "chat_id", fallback="")

        if cfg.getboolean("telegram", "topic", fallback=False):
            tg_topic_id = cfg.get("telegram", "topic_id", fallback=None)

        if cfg.getboolean("telegram", "events_topic", fallback=False):
            tg_events_topic_id = cfg.get("telegram", "events_topic_id", fallback=None)
        else:
            tg_events_topic_id = tg_topic_id

        if cfg.getboolean("telegram", "sources_topic", fallback=False):
            tg_sources_topic_id = cfg.get("telegram", "sources_topic_id", fallback=None)
        else:
            tg_sources_topic_id = tg_topic_id

    TELEGRAM_PROXIES = build_telegram_proxies(cfg)

    events_cfg = load_events_config(cfg)
    sources_cfg = load_sources_config(cfg)

    if "--check-events" in sys.argv:
        raw_tasks = get_tasks()
        tasks_info = filter_by_group(build_tasks_info(raw_tasks), group_name)
        log.info("=== Диагностика потока событий (без отправки в TG) ===")
        check_events_stream(tasks_info, events_cfg, {}, "", "", None, verbose=True, ignore_quiet=True)
        return

    if "--check-sources" in sys.argv:
        raw_tasks = get_tasks()
        tasks_info = filter_by_group(build_tasks_info(raw_tasks), group_name)
        now_ts = int(time.time())
        window_seconds = sources_cfg["collect_window_hours"] * 3600
        log.info("=== Диагностика источников (без записи в БД и без TG) ===")
        for t in tasks_info:
            log.info("--- Задача '%s' (id=%s) ---", t["name"], t["id"])
            try:
                counts = get_source_group_counts(
                    t["id"], now_ts - window_seconds, now_ts, sources_cfg["group_field"],
                    fallback_max_pages=sources_cfg.get("fallback_max_pages", 5)
                )
                if not counts:
                    log.warning("   Источники не найдены — см. предупреждения/DEBUG-лог выше")
                for src, cnt in sorted(counts.items(), key=lambda x: -x[1])[:30]:
                    log.info("   %s -> %s", src, cnt)
            except Exception as e:
                log.error("   Ошибка: %s", e)
        return

    if "--dump-tasks" in sys.argv:
        raw_tasks = get_tasks()
        tasks_info = filter_by_group(build_tasks_info(raw_tasks), group_name)
        log.info("=== Сырой JSON задач группы '%s' ===", group_name)
        for t in tasks_info:
            log.info("--- Задача '%s' (id=%s) ---", t["name"], t["id"])
            log.info(json.dumps(t["_raw"], ensure_ascii=False, indent=2))
        return

    # Диагностика/ручной прогон: python3 siem-tasks-bot.py --report-now [--stale-days N | --stale-minutes N]
    # Формирует и ОТПРАВЛЯЕТ по-настоящему (CSV локально + Telegram, если
    # report_via_telegram=true) отчёт по молчащим источникам на основе уже
    # накопленных в SQLite данных.
    #   --stale-days N     — режим "рабочие дни" (как в проде), но с
    #                         временным порогом N вместо значения из config.ini.
    #   --stale-minutes N  — режим "минуты": источник считается молчащим,
    #                         если с последнего снимка прошло больше N минут
    #                         РЕАЛЬНОГО времени (а не календарных рабочих
    #                         дней) — удобно для мгновенной проверки отчёта
    #                         сразу после первого сбора статистики, не
    #                         дожидаясь ни рабочих дней, ни смены даты.
    # Если не указан ни один из флагов — используется боевой режим
    # (рабочие дни, порог из config.ini).
    if "--report-now" in sys.argv:
        if not sources_cfg["enabled"]:
            log.error("[sources] Мониторинг источников выключен в config.ini ([sources] enabled=false) — нечего отчитывать")
            return

        stale_days_override = get_cli_arg_value("--stale-days")
        stale_minutes_override = get_cli_arg_value("--stale-minutes")

        threshold = None
        mode = "business_days"

        if stale_minutes_override is not None:
            try:
                threshold = float(stale_minutes_override)
                mode = "minutes"
                log.info("=== --report-now: тестовый режим МИНУТ, порог=%s мин ===", threshold)
            except ValueError:
                log.error("--stale-minutes должен быть числом, получено: %s", stale_minutes_override)
                return
        elif stale_days_override is not None:
            try:
                threshold = int(stale_days_override)
                mode = "business_days"
                log.info("=== --report-now: временный порог stale_business_days=%s (в config.ini: %s) ===",
                          threshold, sources_cfg["stale_business_days"])
            except ValueError:
                log.error("--stale-days должен быть целым числом, получено: %s — использую значение из config.ini", stale_days_override)

        sources_conn = init_sources_db(sources_cfg["db_path"])
        raw_tasks = get_tasks()
        tasks_info = filter_by_group(build_tasks_info(raw_tasks), group_name)

        log.info("=== Формирование отчёта по молчащим источникам вручную (--report-now) ===")
        run_daily_stale_report(
            tasks_info, sources_cfg, sources_conn,
            tg_token, tg_chat_id, tg_sources_topic_id,
            threshold=threshold, mode=mode
        )
        log.info("=== --report-now завершён ===")
        return

    sources_conn = None
    if sources_cfg["enabled"]:
        sources_conn = init_sources_db(sources_cfg["db_path"])
        log.info("[sources] БД статистики источников: %s", sources_cfg["db_path"])

    notify_bot_started(
        group_name,
        restart,
        interval,
        events_cfg,
        sources_cfg,
        tg_token,
        tg_chat_id,
        tg_topic_id
    )

    monitor_group(
        group_name=group_name,
        restart=restart,
        interval=interval,
        once=once,
        tg_token=tg_token,
        tg_chat_id=tg_chat_id,
        tg_topic_id=tg_topic_id,
        events_cfg=events_cfg,
        tg_events_topic_id=tg_events_topic_id,
        events_verbose=False,
        sources_cfg=sources_cfg,
        sources_conn=sources_conn,
        tg_sources_topic_id=tg_sources_topic_id,
    )


if __name__ == "__main__":
    main()
