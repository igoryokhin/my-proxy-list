#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import json
import time
import base64
import os
import requests
import re
from urllib.parse import urlparse, parse_qs, unquote
import platform
import shutil
import sys
from typing import Optional, List, Tuple

# -------------------- НАСТРОЙКИ --------------------
urls = [
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vmess_configs.txt"
]

TMP_DIR = "tmp_configs"
os.makedirs(TMP_DIR, exist_ok=True)

# Количество параллельных воркеров (регулируйте)
CONCURRENT_LIMIT = 10

# Таймаут на TCP подключение (в секундах)
TCP_TIMEOUT = 4.0

# Пинг-категории
ping_categories = {
    "vmess": {"0-20": [], "21-50": [], "51-100": [], "101-300": []},
    "vless": {"0-20": [], "21-50": [], "51-100": [], "101-300": []},
    "shadowsocks": {"0-20": [], "21-50": [], "51-100": [], "101-300": []}
}

# -------------------- УТИЛИТЫ ЗАГРУЗКИ --------------------
def download_configs() -> List[str]:
    configs = []
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; proxy-checker/1.0)"})
    for url in urls:
        try:
            resp = session.get(url, timeout=20)
            if resp.status_code != 200:
                print(f"[WARN] {url} -> status {resp.status_code}, пропуск")
                continue
            lines = [line.strip() for line in resp.text.splitlines() if line.strip()]
            lines = [ln for ln in lines if not ln.startswith("#")]
            configs.extend(lines)
            print(f"[INFO] Загружено {len(lines)} строк из {url}")
        except Exception as e:
            print(f"[ERROR] Ошибка при скачивании {url}: {e}")
    # убираем дубликаты, сохраняя порядок
    seen = set()
    unique = []
    for item in configs:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique

# -------------------- БАЗОВОЕ ДЕКОДИРОВАНИЕ --------------------
def _b64_decode_auto(s: str) -> Optional[bytes]:
    try:
        s = s.strip()
        s = re.sub(r"\s+", "", s)
        pad = len(s) % 4
        if pad:
            s += "=" * (4 - pad)
        return base64.b64decode(s, validate=False)
    except Exception:
        return None

def decode_vmess(link: str) -> Optional[dict]:
    try:
        payload = link[len("vmess://"):].strip()
        payload = payload.split()[0].split('#')[0]
        raw = _b64_decode_auto(payload)
        if not raw:
            return None
        decoded = raw.decode('utf-8', errors='ignore')
        j = json.loads(decoded)
        # Приведём к виду с outbounds.vnext для удобного извлечения
        if isinstance(j, dict) and "vnext" in j:
            vnext = j["vnext"]
        else:
            vnext = [{
                "address": j.get("add") or j.get("con") or j.get("host"),
                "port": int(j.get("port", 0)) if j.get("port") else 0,
                "users": [{
                    "id": j.get("id") or j.get("uuid"),
                    "alterId": int(j.get("aid", 0)) if j.get("aid", 0) else 0,
                    "security": j.get("scy", "auto")
                }]
            }]
        return {
            "outbounds": [{
                "protocol": "vmess",
                "settings": {"vnext": vnext}
            }]
        }
    except Exception:
        return None

def decode_vless(link: str) -> Optional[dict]:
    try:
        parsed = urlparse(link)
        server = parsed.hostname
        port = parsed.port or 0
        uuid = parsed.username
        params = parse_qs(parsed.query)
        network = params.get('type', ['tcp'])[0]
        security = params.get('security', ['none'])[0]
        return {
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": server,
                        "port": int(port),
                        "users": [{"id": uuid}]
                    }]
                },
                "streamSettings": {
                    "network": network,
                    "security": security
                }
            }]
        }
    except Exception:
        return None

def decode_ss(link: str) -> Optional[dict]:
    try:
        raw = link[len("ss://"):].strip()
        raw = raw.split()[0].split('#')[0]
        # base64 формат или прямой
        if ":" not in raw or ("@" not in raw and re.match(r"^[A-Za-z0-9+/=]+$", raw)):
            decoded = _b64_decode_auto(raw)
            if not decoded:
                return None
            raw = decoded.decode('utf-8', errors='ignore')
        if "@" in raw:
            url_like = "ss://" + raw
            p = urlparse(url_like)
            method = unquote(p.username) if p.username else None
            password = unquote(p.password) if p.password else None
            server = p.hostname
            port = p.port
        else:
            m = re.match(r"(?P<method>[^:]+):(?P<pw>[^@]+)@(?P<host>[^:]+):(?P<port>\d+)", raw)
            if not m:
                return None
            method = m.group("method")
            password = m.group("pw")
            server = m.group("host")
            port = int(m.group("port"))
        return {
            "outbounds": [{
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": server,
                        "port": int(port) if port else 0,
                        "method": method,
                        "password": password
                    }]
                }
            }]
        }
    except Exception:
        return None

# -------------------- ИЗВЛЕЧЕНИЕ TARGET (HOST:PORT) ИЗ CONFIG --------------------
def extract_targets_from_config(config: dict) -> List[Tuple[str, int]]:
    """
    Ищет адреса и порты в структуре конфига (поддерживает vnext для vmess/vless и servers для shadowsocks).
    Возвращает список (host, port).
    """
    targets = []
    try:
        outs = config.get("outbounds", []) if isinstance(config, dict) else []
        for out in outs:
            proto = (out.get("protocol") or "").lower()
            settings = out.get("settings", {}) or {}
            if proto in ("vmess", "vless"):
                vnext = settings.get("vnext") or []
                if isinstance(vnext, dict):
                    # случай, если vnext не список
                    vnext = [vnext]
                for vn in vnext:
                    addr = vn.get("address") or vn.get("host")
                    port = vn.get("port")
                    if addr and port:
                        try:
                            targets.append((addr, int(port)))
                        except Exception:
                            pass
            elif proto == "shadowsocks":
                servers = settings.get("servers", []) or []
                for s in servers:
                    addr = s.get("address") or s.get("host")
                    port = s.get("port")
                    if addr and port:
                        try:
                            targets.append((addr, int(port)))
                        except Exception:
                            pass
            else:
                # общее: попробовать найти address/port в settings
                if isinstance(settings, dict):
                    if "servers" in settings and isinstance(settings["servers"], list):
                        for s in settings["servers"]:
                            addr = s.get("address") or s.get("host")
                            port = s.get("port")
                            if addr and port:
                                try:
                                    targets.append((addr, int(port)))
                                except Exception:
                                    pass
                    else:
                        # прямые поля
                        addr = settings.get("address") or settings.get("host")
                        port = settings.get("port")
                        if addr and port:
                            try:
                                targets.append((addr, int(port)))
                            except Exception:
                                pass
        # Дополнительные проверки: если targets пусты, попытаемся найти в корне
        if not targets and isinstance(config, dict):
            # например, config может быть минимальным описанием сервера
            addr = config.get("address") or config.get("host")
            port = config.get("port")
            if addr and port:
                try:
                    targets.append((addr, int(port)))
                except Exception:
                    pass
    except Exception:
        pass
    return targets

# -------------------- TCP PING --------------------
async def tcp_ping(host: str, port: int, timeout: float) -> Optional[int]:
    """
    Пытается установить TCP соединение к host:port.
    Возвращает RTT в миллисекундах, или None при неудаче.
    """
    start = time.time()
    try:
        coro = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(coro, timeout=timeout)
        # успешно подключились — аккуратно закроем
        try:
            writer.close()
            # wait_closed может не присутствовать в некоторых реализациях, обернём в try
            if hasattr(writer, "wait_closed"):
                await writer.wait_closed()
        except Exception:
            pass
        rtt_ms = int((time.time() - start) * 1000)
        return rtt_ms
    except Exception:
        return None

# -------------------- SAVE UTIL --------------------
def save_results_to_files():
    """Сохраняет все категории в файлы."""
    for protocol, categories in ping_categories.items():
        for category, proxies_list in categories.items():
            txt_filename = f"{protocol}_ping_{category}_working_proxies.txt"
            b64_filename = f"{protocol}_ping_{category}_working_proxies_base64.txt"
            try:
                if proxies_list:
                    with open(txt_filename, "w", encoding="utf-8") as txt_file:
                        for p in proxies_list:
                            txt_file.write(p + "\n")
                    with open(b64_filename, "w", encoding="utf-8") as b64_file:
                        for p in proxies_list:
                            b64_file.write(base64.b64encode(p.encode()).decode() + "\n")
                    print(f"[INFO] Сохранено {len(proxies_list)} {protocol} прокси в категории {category}ms -> {txt_filename}")
                else:
                    # Удаляем старые файлы, чтобы не мешали (опционально)
                    try:
                        if os.path.exists(txt_filename):
                            os.remove(txt_filename)
                        if os.path.exists(b64_filename):
                            os.remove(b64_filename)
                    except Exception:
                        pass
            except Exception as e:
                print(f"[ERROR] Не удалось сохранить файлы для {protocol} {category}: {e}")

# -------------------- ПРОВЕРКА ОДНОГО ПРОКСИ --------------------
async def check_proxy(proxy_str: str, idx: int, protocol: str):
    """
    Декодирует строчку (vmess/vless/ss/JSON), извлекает targets (host:port) и делает tcp_ping.
    При первом успешном подключении добавляет proxy_str в соответствующую категорию.
    """
    try:
        config = None
        if protocol == "vmess" and proxy_str.startswith("vmess://"):
            config = decode_vmess(proxy_str)
        elif protocol == "vless" and proxy_str.startswith("vless://"):
            config = decode_vless(proxy_str)
        elif protocol == "shadowsocks" and proxy_str.startswith("ss://"):
            config = decode_ss(proxy_str)
        else:
            # возможен уже JSON-конфиг
            try:
                parsed = json.loads(proxy_str)
                if isinstance(parsed, dict):
                    config = parsed
            except Exception:
                # неизвестный формат
                return

        if not config:
            return

        targets = extract_targets_from_config(config)
        if not targets:
            return

        # попытаемся подключиться к каждому target (обычно 1)
        for host, port in targets:
            rtt = await tcp_ping(host, port, timeout=TCP_TIMEOUT)
            if isinstance(rtt, int):
                # классификация
                if rtt <= 20:
                    ping_categories[protocol]["0-20"].append(proxy_str)
                elif rtt <= 50:
                    ping_categories[protocol]["21-50"].append(proxy_str)
                elif rtt <= 100:
                    ping_categories[protocol]["51-100"].append(proxy_str)
                elif rtt <= 300:
                    ping_categories[protocol]["101-300"].append(proxy_str)
                # при первом успешном target — прекращаем
                return
        # если дошли сюда — ни один target не ответил
    except Exception as e:
        # не ломаем воркеры
        print(f"[ERROR] check_proxy exception idx={idx}: {e}")

# -------------------- WORKER & MAIN --------------------
async def worker(worker_id: int, queue: asyncio.Queue, counter: dict):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break
        idx, proxy = item
        lower = proxy.lower() if isinstance(proxy, str) else ""
        protocol = None
        if lower.startswith("vmess://"):
            protocol = "vmess"
        elif lower.startswith("vless://"):
            protocol = "vless"
        elif lower.startswith("ss://"):
            protocol = "shadowsocks"
        else:
            try:
                parsed = json.loads(proxy)
                protocol = parsed.get("outbounds", [{}])[0].get("protocol", "")
                if protocol not in ping_categories:
                    protocol = None
            except Exception:
                protocol = None

        if protocol:
            await check_proxy(proxy, idx, protocol)

        counter['done'] += 1
        if counter['done'] % 500 == 0:
            print(f"[INFO] Прогресс: обработано {counter['done']} прокси")
        queue.task_done()

async def main():
    proxies = download_configs()
    print(f"[INFO] Всего получено прокси-строк: {len(proxies)}")

    q = asyncio.Queue()
    for idx, p in enumerate(proxies):
        await q.put((idx, p))

    worker_count = min(CONCURRENT_LIMIT, max(1, len(proxies)))
    print(f"[INFO] Запускаем {worker_count} воркеров")

    counter = {"done": 0}
    workers = [asyncio.create_task(worker(i, q, counter)) for i in range(worker_count)]

    await q.join()

    # сигнал завершения воркерам
    for _ in workers:
        await q.put(None)
    await asyncio.gather(*workers)

    # Сохраняем результаты
    save_results_to_files()

    # Краткая сводка
    total_found = sum(len(cat) for proto in ping_categories.values() for cat in proto.values())
    print(f"[INFO] Готово. Найдено рабочих прокси: {total_found}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[INFO] Прервано пользователем")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
