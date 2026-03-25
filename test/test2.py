import time

import requests
from requests.adapters import HTTPAdapter
import socket
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CustomHTTPAdapter(HTTPAdapter):
    def __init__(self, ip, *args, **kwargs):
        self.ip = ip
        super().__init__(*args, **kwargs)

    def get_connection(self, url, proxies=None):
        conn = super().get_connection(url, proxies)
        hostname = url.split('://')[1].split('/')[0].split(':')[0]
        conn.poolmanager.connection_pool_kw['server_hostname'] = hostname
        conn.poolmanager.connection_pool_kw['socket_options'] = [
            (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ]
        conn.poolmanager.connection_pool_kw['source_address'] = (self.ip, 0)
        return conn


def download(ip, port=443):
    url = f"https://{ip}:{port}/__down?bytes={1024 * 1024 * 1024}"
    headers = {'Host': 'speed.cloudflare.com'}

    session = requests.Session()
    adapter = CustomHTTPAdapter(ip)
    session.mount("https://", adapter)

    try:
        start_time = time.time()
        with session.get(url, headers=headers, stream=True, timeout=10, verify=False) as resp:
            data_len = 0
            for chunk in resp.iter_content(1024):
                if time.time() - start_time <= 5:
                    data_len += len(chunk)
                else:
                    data_len += len(chunk)
                    break

            elapsed_time = time.time() - start_time
            return data_len / elapsed_time
    except Exception as e:
        print(f"Request Error: {e}")
        return 0.00


def main():
    ip = '154.88.6.244'  # 替换为所需的 IP 地址
    port = 443  # 替换为所需的端口
    result = download(ip, port)
    print(f"下载速度: {result:.2f} 字节/秒")


if __name__ == "__main__":
    main()
