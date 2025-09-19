import asyncio
import subprocess
import json
import time
import base64
import os
import requests

# Список ссылок с конфигами
urls = [
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/ss_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vmess_configs.txt"
]

# Тестовый URL
TEST_URL = "https://www.cloudflare.com"

# Категории пинга
ping_categories = {
    "0-20": [],
    "21-50": [],
    "51-100": [],
    "101-300": []
}

# Папка для временных конфигов
TMP_DIR = "tmp_configs"
os.makedirs(TMP_DIR, exist_ok=True)

# Функция скачивания всех конфигов
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

# Сохраняем временный JSON конфиг для v2ray
def save_temp_config(proxy, filename):
    try:
        cfg = json.loads(proxy)
        path = os.path.join(TMP_DIR, filename)
        with open(path, "w") as f:
            json.dump(cfg, f)
        return path
    except:
        return None

# Проверка одного прокси через v2ray/xray CLI
async def check_proxy(proxy, idx):
    config_path = save_temp_config(proxy, f"proxy_{idx}.json")
    if not config_path:
        return
    try:
        start = time.time()
        # Запуск v2ray/xray с временным конфигом
        subprocess.run(
            ["v2ray", "-config", config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10
        )
        ping = int((time.time() - start) * 1000)
        if ping <= 300:
            if ping <= 20:
                ping_categories["0-20"].append(proxy)
            elif ping <= 50:
                ping_categories["21-50"].append(proxy)
            elif ping <= 100:
                ping_categories["51-100"].append(proxy)
            else:
                ping_categories["101-300"].append(proxy)
    except subprocess.TimeoutExpired:
        return
    finally:
        os.remove(config_path)

# Главная асинхронная функция
async def main():
    proxies = download_configs()
    tasks = [check_proxy(proxy, idx) for idx, proxy in enumerate(proxies)]
    await asyncio.gather(*tasks)

    # Сохраняем отдельные файлы для каждой категории
    for category, prox_list in ping_categories.items():
        txt_filename = f"ping_{category}_working_proxies.txt"
        b64_filename = f"ping_{category}_working_proxies_base64.txt"
        with open(txt_filename, "w") as txt_file, open(b64_filename, "w") as b64_file:
            for proxy in prox_list:
                txt_file.write(proxy + "\n")
                b64_file.write(base64.b64encode(proxy.encode()).decode() + "\n")

if __name__ == "__main__":
    asyncio.run(main())
