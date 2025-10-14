#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import subprocess
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
from typing import Optional

# -------------------- НАСТРОЙКИ --------------------
# Список ссылок с конфигами (можно изменить)
urls = [
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/ss_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vmess_configs.txt"
]

TMP_DIR = "tmp_configs"
os.makedirs(TMP_DIR, exist_ok=True)

# Ограничение параллельности (можно менять)
CONCURRENT_LIMIT = 10
SEM = asyncio.Semaphore(CONCURRENT_LIMIT)

# Пинг-категории
ping_categories = {
    "vmess": {"0-20": [], "21-50": [], "51-100": [], "101-300": []},
    "vless": {"0-20": [], "21-50": [], "51-100": [], "101-300": []},
    "shadowsocks": {"0-20": [], "21-50": [], "51-100": [], "101-300": []}
}

# -------------------- ПУТЬ К XRAY --------------------
def get_xray_path() -> str:
    # Первым делом — переменная окружения XRAY_PATH
    env_path = os.environ.get("XRAY_PATH")
    if env_path:
        return env_path

    # Проверим в PATH
    for name in ("xray", "xray.exe"):
        found = shutil.which(name)
        if found:
            return found

    # Windows: потенциальные стандартные места
    if platform.system() == "Windows":
        possible_paths = [
            r"C:\Program Files\Xray\xray.exe",
            r"C:\xray\xray.exe",
            r"C:\Users\%USERNAME%\Downloads\Xray-windows-64\xray.exe"
        ]
        for p in possible_paths:
            p_expanded = os.path.expandvars(p)
            if os.path.exists(p_expanded):
                return p_expanded
        return "xray.exe"
    # Unix: предполагаем что 'xray' в PATH
    return "xray"

XRAY_PATH = get_xray_path()

# -------------------- ЗАГРУЗКА КОНФИГОВ --------------------
def download_configs():
    configs = []
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; proxy-checker/1.0)"
    })
    for url in urls:
        try:
            resp = session.get(url, timeout=15)
            if resp.status_code != 200:
                print(f"[WARN] {url} -> status {resp.status_code}, пропуск")
                continue
            lines = [line.strip() for line in resp.text.splitlines() if line.strip()]
            # Игнорируем комментарии
            lines = [ln for ln in lines if not ln.startswith("#")]
            configs.extend(lines)
            print(f"[INFO] Загружено {len(lines)} строк из {url}")
        except Exception as e:
            print(f"[ERROR] Ошибка при скачивании {url}: {e}")
    # убираем дубликаты, сохраняем порядок
    seen = set()
    unique = []
    for item in configs:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique

# -------------------- ДЕКОДЕРЫ --------------------
def _b64_decode_auto(s: str) -> Optional[bytes]:
    """Попытка base64 декодирования с учётом padding."""
    try:
        s = s.strip()
        # убираем переносы и пробелы
        s = re.sub(r"\s+", "", s)
        pad = len(s) % 4
        if pad:
            s += "=" * (4 - pad)
        return base64.b64decode(s, validate=False)
    except Exception:
        return None

def decode_vmess(link: str) -> Optional[dict]:
    try:
        # vmess://<base64>
        payload = link[len("vmess://"):].strip()
        # иногда в конце идёт комментарий после пробела или '#'
        payload = payload.split()[0].split('#')[0]
        raw = _b64_decode_auto(payload)
        if not raw:
            return None
        decoded = raw.decode('utf-8', errors='ignore')
        # Иногда в файле уже JSON лежит без base64
        if decoded.strip().startswith('{'):
            j = json.loads(decoded)
        else:
            j = json.loads(decoded)
        # Преобразуем в минимально валидный config для xray/v2ray
        return {
            "log": {"loglevel": "error"},
            "outbounds": [{
                "protocol": "vmess",
                "settings": {"vnext": [j.get("vnext", [])] } if isinstance(j, dict) and "vnext" in j else {
                    "vnext": [{
                        "address": j.get("add") or j.get("con") or j.get("host"),
                        "port": int(j.get("port", 0)) if j.get("port") else 0,
                        "users": [{
                            "id": j.get("id") or j.get("uuid"),
                            "alterId": int(j.get("aid", 0)) if j.get("aid", 0) else 0,
                            "security": j.get("scy", "auto")
                        }]
                    }]
                }
            }]
        }
    except Exception:
        return None

def decode_vless(link: str) -> Optional[dict]:
    try:
        # vless://<uuid>@host:port?type=...&security=...
        parsed = urlparse(link)
        server = parsed.hostname
        port = parsed.port or 0
        uuid = parsed.username
        params = parse_qs(parsed.query)
        network = params.get('type', ['tcp'])[0]
        security = params.get('security', ['none'])[0]
        config = {
            "log": {"loglevel": "error"},
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
        return config
    except Exception:
        return None

def decode_ss(link: str) -> Optional[dict]:
    try:
        # Формат 1: ss://<base64> (base64 содержит method:password@host:port)
        # Формат 2: ss://method:password@host:port
        raw = link[len("ss://"):].strip()
        raw = raw.split()[0].split('#')[0]
        # Если base64 в начале (обычно если содержит ':')
        # Попробуем base64-декодировать первую часть (до @ если есть)
        # Если строка содержит '@' до '/', то считаем что это не base64
        if ":" not in raw or ("@" not in raw and re.match(r"^[A-Za-z0-9+/=]+$", raw)):
            # base64 вариант
            decoded = _b64_decode_auto(raw)
            if not decoded:
                return None
            decoded = decoded.decode('utf-8', errors='ignore')
            # decoded -> method:password@host:port
            raw = decoded
        # теперь raw должен иметь вид method:password@host:port
        # убрать возможный протоколную часть перед @
        # parse через urlparse, дополнив схемы
        if "@" in raw:
            # ensure scheme to use urlparse
            url_like = "ss://" + raw
            p = urlparse(url_like)
            method = unquote(p.username) if p.username else None
            password = unquote(p.password) if p.password else None
            server = p.hostname
            port = p.port
        else:
            # fallback: split manually
            m = re.match(r"(?P<method>[^:]+):(?P<pw>[^@]+)@(?P<host>[^:]+):(?P<port>\d+)", raw)
            if not m:
                return None
            method = m.group("method")
            password = m.group("pw")
            server = m.group("host")
            port = int(m.group("port"))
        config = {
            "log": {"loglevel": "error"},
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
        return config
    except Exception:
        return None

# -------------------- Утилиты --------------------
def save_temp_config(config: dict, filename: str) -> Optional[str]:
    try:
        path = os.path.join(TMP_DIR, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
        return path
    except Exception as e:
        print(f"[ERROR] Не удалось сохранить временный конфиг {filename}: {e}")
        return None

# -------------------- ПРОВЕРКА ПРОКСИ --------------------
async def check_proxy(proxy: str, idx: int, protocol: str):
    async with SEM:
        config = None
        protocol_key = protocol  # vmess|vless|shadowsocks
        try:
            if protocol == "vmess" and proxy.startswith('vmess://'):
                config = decode_vmess(proxy)
            elif protocol == "vless" and proxy.startswith('vless://'):
                config = decode_vless(proxy)
            elif protocol == "shadowsocks" and proxy.startswith('ss://'):
                config = decode_ss(proxy)
            else:
                # возможно уже JSON-строка
                try:
                    parsed = json.loads(proxy)
                    if isinstance(parsed, dict):
                        config = parsed
                except Exception:
                    # невалидный формат
                    return
            if not config:
                return

            config_path = save_temp_config(config, f"proxy_{idx}.json")
            if not config_path:
                return

            start = time.time()
            # Запускаем Xray (async), даём ему немного времени и убиваем
            # Используем: xray run -c config.json (в большинстве билдов есть подкоманда run)
            # Если у вас другой синтаксис, установите XRAY_PATH переменную окружения и/или измените args.
            args = [XRAY_PATH, "run", "-c", config_path]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            except FileNotFoundError:
                # Попробуем без 'run' (на старых сборках)
                args = [XRAY_PATH, "-c", config_path]
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *args,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                except Exception as e:
                    print(f"[ERROR] Не удалось запустить Xray: {e}")
                    return
            except Exception as e:
                print(f"[ERROR] Не удалось запустить Xray: {e}")
                return

            # даём инициализироваться
            await asyncio.sleep(2)

            # завершаем процесс
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass

            ping_ms = int((time.time() - start) * 1000)

            if ping_ms <= 300:
                if ping_ms <= 20:
                    ping_categories[protocol_key]["0-20"].append(proxy)
                elif ping_ms <= 50:
                    ping_categories[protocol_key]["21-50"].append(proxy)
                elif ping_ms <= 100:
                    ping_categories[protocol_key]["51-100"].append(proxy)
                else:
                    ping_categories[protocol_key]["101-300"].append(proxy)

        except Exception as e:
            print(f"[ERROR] Ошибка при проверке прокси (idx={idx}): {e}")
        finally:
            # удаляем временный конфиг если создан
            try:
                if 'config_path' in locals() and config_path and os.path.exists(config_path):
                    os.remove(config_path)
            except Exception:
                pass

# -------------------- MAIN --------------------
async def main():
    proxies = download_configs()
    print(f"[INFO] Всего получено прокси-строк: {len(proxies)}")
    tasks = []

    for idx, proxy in enumerate(proxies):
        if not proxy:
            continue
        lower = proxy.lower()
        if lower.startswith('vmess://'):
            tasks.append(asyncio.create_task(check_proxy(proxy, idx, "vmess")))
        elif lower.startswith('vless://'):
            tasks.append(asyncio.create_task(check_proxy(proxy, idx, "vless")))
        elif lower.startswith('ss://'):
            tasks.append(asyncio.create_task(check_proxy(proxy, idx, "shadowsocks")))
        else:
            # возможно уже JSON-конфиг
            try:
                parsed = json.loads(proxy)
                protocol = parsed.get('outbounds', [{}])[0].get('protocol', '')
                if protocol in ping_categories:
                    tasks.append(asyncio.create_task(check_proxy(proxy, idx, protocol)))
            except Exception:
                # нераспознанная строка
                continue

    # ждём завершения всех задач (ограничение параллельности внутри check_proxy)
    if tasks:
        for i in range(0, len(tasks), 50):
            batch = tasks[i:i+50]
            await asyncio.gather(*batch)
            print(f"[INFO] Завершена партия: {min(i+50, len(tasks))} / {len(tasks)}")
    else:
        print("[INFO] Нет задач для проверки.")

    # Сохраняем результаты в файлы
    for protocol, categories in ping_categories.items():
        for category, proxies in categories.items():
            if proxies:
                txt_filename = f"{protocol}_ping_{category}_working_proxies.txt"
                b64_filename = f"{protocol}_ping_{category}_working_proxies_base64.txt"
                try:
                    with open(txt_filename, "w", encoding="utf-8") as txt_file:
                        for p in proxies:
                            txt_file.write(p + "\n")
                    with open(b64_filename, "w", encoding="utf-8") as b64_file:
                        for p in proxies:
                            b64_file.write(base64.b64encode(p.encode()).decode() + "\n")
                    print(f"[INFO] Сохранено {len(proxies)} {protocol} прокси в категории {category}ms -> {txt_filename}")
                except Exception as e:
                    print(f"[ERROR] Не удалось сохранить файлы для {protocol} {category}: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] Прервано пользователем")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
