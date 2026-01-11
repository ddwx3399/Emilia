# create by mayumi v.1
"""
NOte add lib re
"""
import socket
import ssl
import json
import concurrent.futures
import re
# >>> ADD
import requests
# <<< ADD

# >>> ADD: dynv6 support imports
import urllib.request
from threading import Event
# <<< ADD

IP_RESOLVER = "speed.cloudflare.com"
PATH_RESOLVER = "/meta"
PROXY_FILE = "Data/ProxyIsp.txt"
OUTPUT_FILE = "Data/alive.txt"

active_proxies = []  # List untuk menyimpan proxy aktif

# >>> ADD: dynv6 config
DYNV6_HOSTNAME = "proxyipmy.dns.army"
DYNV6_TOKEN = "sKzuT7Sowr-uTpQSuS-JmY5ejAQTy8"
dynv6_updated = Event()
# <<< ADD

def check(host, path, proxy):
    """Melakukan koneksi SSL ke host tertentu dan mengambil respons JSON."""
    payload = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240\r\n"
        "Connection: close\r\n\r\n"
    )

    ip = proxy.get("ip", host)
    port = int(proxy.get("port", 443))

    conn = None
    try:
        ctx = ssl.create_default_context()
        conn = socket.create_connection((ip, port), timeout=5)
        conn = ctx.wrap_socket(conn, server_hostname=host)

        conn.sendall(payload.encode())

        resp = b""
        while True:
            data = conn.recv(4096)
            if not data:
                break
            resp += data

        resp = resp.decode("utf-8", errors="ignore")
        headers, body = resp.split("\r\n\r\n", 1)

        return json.loads(body)
    except (json.JSONDecodeError, ValueError):
        print(f"Error parsing JSON dari {ip}:{port}")
    except (socket.error, ssl.SSLError) as e:
        print(f"Error koneksi: {e}")
    finally:
        if conn:
            conn.close()

    return {}

def clean_org_name(org_name): #Menghapus karakter yang tidak diinginkan dari nama organisasi.
    return re.sub(r'[^a-zA-Z0-9\s]', '', org_name) if org_name else org_name

# >>> ADD: dynv6 update function
def update_dynv6(ip):
    url = "http://dynv6.com/api/update"
    params = {
        "hostname": DYNV6_HOSTNAME,
        "token": DYNV6_TOKEN,
        "ipv4": ip
    }
    try:
        r = requests.get(url, params=params, timeout=10)
        if r.status_code == 200:
            print(f"✅ dynv6 更新成功 → {ip}")
            print(f"返回内容: {r.text.strip()}")
            return True              # <<< ADD
        else:
            print(f"❌ dynv6 更新失败，状态码: {r.status_code}")
            return False             # <<< ADD
    except Exception as e:
        print(f"❌ dynv6 请求异常: {e}")
        return False                 # <<< ADD
# <<< ADD
# <<< ADD

def process_proxy(proxy_line):
    proxy_line = proxy_line.strip()
    if not proxy_line:
        return

    try:
        ip, port, country, org = proxy_line.split(",")
        proxy_data = {"ip": ip, "port": port}

        ori, pxy = [
            check(IP_RESOLVER, PATH_RESOLVER, {}),
            check(IP_RESOLVER, PATH_RESOLVER, proxy_data)
        ]

        if ori and pxy and ori.get("clientIp") != pxy.get("clientIp"):
            
            org_name = clean_org_name(pxy.get("asOrganization"))
            proxy_country = pxy.get("country")

            proxy_entry = f"{ip},{port},{country},{org_name}"
            print(f"CF PROXY LIVE!: {proxy_entry}")
            active_proxies.append(proxy_entry)

        else:
            print(f"CF PROXY DEAD!: {ip}:{port}")

    except ValueError:
        print(f"Format baris proxy tidak valid: {proxy_line}. Pastikan formatnya ip,port,country,org")
    except Exception as e:
        print(f"Error saat memproses proxy {proxy_line}: {e}")

# Kosongkan file sebelum memulai scan
open(OUTPUT_FILE, "w").close()
print(f"File {OUTPUT_FILE} telah dikosongkan sebelum proses scan dimulai.")

# Membaca daftar proxy dari file
try:
    with open(PROXY_FILE, "r") as f:
        proxies = f.readlines()
except FileNotFoundError:
    print(f"File tidak ditemukan: {PROXY_FILE}")
    exit()

max_workers = 20

with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
    futures = [executor.submit(process_proxy, proxy_line) for proxy_line in proxies]
    concurrent.futures.wait(futures)

# Setelah semua proxy diproses, simpan ke file
if active_proxies:
    with open(OUTPUT_FILE, "w") as f_me:
        f_me.write("\n".join(active_proxies) + "\n")
    print(f"Semua proxy aktif disimpan ke {OUTPUT_FILE}")

# ------------------------------
# >>> ADD: dynv6 更新逻辑，读取 OUTPUT_FILE
# ------------------------------
try:
    with open(OUTPUT_FILE, "r") as f_alive:
        lines = f_alive.readlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ip, port, country, org = line.split(",")
            if country.strip().upper() == "SG" and port.strip() == "443" and not dynv6_updated.is_set():
                print(f"Found first SG proxy with port 443 in alive.txt: {ip}:{port}")
                if update_dynv6(ip):
                    print(f"\033[94m✔ First SG proxy updated to dynv6: {ip}\033[0m")
                    dynv6_updated.set()
                break
        except ValueError:
            continue
except FileNotFoundError:
    print(f"File not found: {OUTPUT_FILE}")
# <<< ADD

print("Pengecekan proxy selesai.")
