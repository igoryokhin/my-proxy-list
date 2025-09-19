import asyncio
import subprocess
import json
import time
import base64
import os
import requests
import re
from urllib.parse import urlparse, parse_qs

# Список ссылок с конфигами
urls = [
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/ss_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vmess_configs.txt"
]

# Категории пинга
ping_categories = {
    "vmess": {"0-20": [], "21-50": [], "51-100": [], "101-300": []},
    "vless": {"0-20": [], "21-50": [], "51-100": [], "101-300": []},
    "shadowsocks": {"0-20": [], "21-50": [], "51-100": [], "101-300": []}
}

# Папка для временных конфигов
TMP_DIR = "tmp_configs"
os.makedirs(TMP_DIR, exist_ok=True)

def download_configs():
    configs = []
    for url in urls:
        try:
            resp = requests.get(url, timeout=10)
            lines = [line.strip() for line in resp.text.splitlines() if line.strip()]
            configs.extend(lines)
        except:
            print(f"Ошибка при скачивании {url}")
    return configs

def decode_vmess(link):
    try:
        base64_str = link[8:]
        pad = len(base64_str) % 4
        if pad:
            base64_str += '=' * (4 - pad)
        decoded = base64.b64decode(base64_str).decode('utf-8')
        return json.loads(decoded)
    except:
        return None

def decode_vless(link):
    try:
        parsed = urlparse(link)
        server = parsed.hostname
        port = parsed.port
        uuid = parsed.username
        params = parse_qs(parsed.query)
        
        config = {
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": server,
                        "port": port,
                        "users": [{"id": uuid}]
                    }]
                },
                "streamSettings": {
                    "network": params.get('type', ['tcp'])[0],
                    "security": params.get('security', ['none'])[0]
                }
            }]
        }
        return config
    except:
        return None

def decode_ss(link):
    try:
        parsed = urlparse(link)
        method = parsed.username
        password = parsed.password
        server = parsed.hostname
        port = parsed.port
        
        config = {
            "outbounds": [{
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": server,
                        "port": port,
                        "method": method,
                        "password": password
                    }]
                }
            }]
        }
        return config
    except:
        return None

def save_temp_config(config, filename):
    try:
        path = os.path.join(TMP_DIR, filename)
        with open(path, "w") as f:
            json.dump(config, f)
        return path
    except:
        return None

async def check_proxy(proxy, idx, protocol):
    config = None
    
    if protocol == "vmess" and proxy.startswith('vmess://'):
        config = decode_vmess(proxy)
    elif protocol == "vless" and proxy.startswith('vless://'):
        config = decode_vless(proxy)
    elif protocol == "shadowsocks" and proxy.startswith('ss://'):
        config = decode_ss(proxy)
    else:
        try:
            config = json.loads(proxy)
        except:
            return
    
    if not config:
        return
        
    config_path = save_temp_config(config, f"proxy_{idx}.json")
    if not config_path:
        return
        
    try:
        start = time.time()
        process = await asyncio.create_subprocess_exec(
            "xray", "run", "-config", config_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await asyncio.sleep(2)
        process.terminate()
        await process.wait()
        
        ping = int((time.time() - start) * 1000)
        
        if ping <= 300:
            if ping <= 20:
                ping_categories[protocol]["0-20"].append(proxy)
            elif ping <= 50:
                ping_categories[protocol]["21-50"].append(proxy)
            elif ping <= 100:
                ping_categories[protocol]["51-100"].append(proxy)
            else:
                ping_categories[protocol]["101-300"].append(proxy)
                
    except Exception as e:
        print(f"Ошибка при проверке прокси: {e}")
    finally:
        if os.path.exists(config_path):
            os.remove(config_path)

async def main():
    proxies = download_configs()
    
    tasks = []
    for idx, proxy in enumerate(proxies):
        if proxy.startswith('vmess://'):
            tasks.append(check_proxy(proxy, idx, "vmess"))
        elif proxy.startswith('vless://'):
            tasks.append(check_proxy(proxy, idx, "vless"))
        elif proxy.startswith('ss://'):
            tasks.append(check_proxy(proxy, idx, "shadowsocks"))
        else:
            try:
                config = json.loads(proxy)
                protocol = config.get('outbounds', [{}])[0].get('protocol', '')
                if protocol in ping_categories:
                    tasks.append(check_proxy(proxy, idx, protocol))
            except:
                continue
    
    await asyncio.gather(*tasks)
    
    for protocol, categories in ping_categories.items():
        for category, proxies in categories.items():
            if proxies:
                txt_filename = f"{protocol}_ping_{category}_working_proxies.txt"
                b64_filename = f"{protocol}_ping_{category}_working_proxies_base64.txt"
                
                with open(txt_filename, "w") as txt_file:
                    for proxy in proxies:
                        txt_file.write(proxy + "\n")
                
                with open(b64_filename, "w") as b64_file:
                    for proxy in proxies:
                        b64_file.write(base64.b64encode(proxy.encode()).decode() + "\n")

if __name__ == "__main__":
    asyncio.run(main())