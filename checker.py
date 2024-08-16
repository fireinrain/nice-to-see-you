import concurrent.futures as futures
import datetime
import json
import random
import re
import urllib3
import aiohttp
import asyncio
import time
import socket
import notify
from aiohttp import ClientTimeout, TCPConnector
from redis_tool import r
import requests
import locations

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

pool_executor = futures.ThreadPoolExecutor()


def random_sleep(max_sleep: int = 1):
    sleep_time = random.uniform(0, max_sleep)
    # 生成一个介于 0 和 1 之间的随机小数
    time.sleep(sleep_time)


def is_valid_ipv4(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if pattern.match(ip):
        # Further check to ensure each segment is between 0 and 255
        segments = ip.split('.')
        if all(0 <= int(segment) <= 255 for segment in segments):
            return True
    return False


def get_ip_address(domain_str: str) -> str:
    try:
        # 获取IPv4地址
        ipv4 = socket.gethostbyname(domain_str)
        print(f"IPv4 address of {domain_str}: {ipv4}")
        return ipv4
    except socket.gaierror:
        print(f"Could not resolve {domain_str} to an IPv4 address")

    try:
        # 获取IPv6地址
        ipv6_info = socket.getaddrinfo(domain_str, None, socket.AF_INET6)
        ipv6_addresses = [info[4][0] for info in ipv6_info]
        # 去重
        ipv6_addresses = list(set(ipv6_addresses))
        for ipv6 in ipv6_addresses:
            print(f"IPv6 address of {domain_str}: {ipv6}")
        return ipv6_addresses[0]
    except socket.gaierror:
        print(f"Could not resolve {domain_str} to an IPv6 address")
    return ""


class IPChecker:
    @staticmethod
    def check_port_open(host: socket, port: str | int) -> bool:
        sock = None
        port = int(port)
        try:
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set timeout to 1 second
            sock.settimeout(2.5)
            # Connect to the host and port
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f">>> Port {port} is open on {host}")
                return True
            else:
                print(f">>> Port {port} is closed on {host}")

        except Exception as e:
            print(f"Error checking port: {e}")
        finally:
            sock.close()
        return False

    @staticmethod
    def check_port_open_with_retry(host: socket, port: str | int, retry: int = 1) -> bool:
        for i in range(retry):
            with_retry = IPChecker.check_port_open(host, port)
            if with_retry:
                return True
            random_sleep(15)
        return False

    @staticmethod
    def check_band_with_gfw_with_retry(host: str, port: str | int, check_count: int) -> bool:
        host = host.strip()
        if check_count <= 0:
            raise ValueError("min_pass must be smaller than check_count")
        for i in range(check_count):
            gfw = IPChecker.check_baned_with_gfw(host, port)
            if not gfw:
                return False
            time.sleep(15)
        # 使用v2接口再次检测一下
        ipv_ = is_valid_ipv4(host)
        if not ipv_:
            host = get_ip_address(host)
        is_ban = IPChecker.check_baned_with_gfw_v2(host, port)
        if not is_ban:
            return False
        return True

    # 检测ip端口是否被gfw ban
    @staticmethod
    def check_baned_with_gfw(host: str, port: str | int) -> bool:

        request_url = f"https://www.toolsdaquan.com/toolapi/public/ipchecking/{host}/{port}"
        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "zh,en;q=0.9,zh-TW;q=0.8,zh-CN;q=0.7,ja;q=0.6",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Referer": "https://www.toolsdaquan.com/ipcheck/",
            "Sec-Ch-Ua": "\"Google Chrome\";v=\"111\", \"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"111\"",
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": "\"macOS\"",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "X-Requested-With": "XMLHttpRequest"
        }
        random_user_agent = IPChecker.get_random_user_agent()
        headers['User-Agent'] = random_user_agent

        try:
            resp = requests.get(request_url, headers=headers)
            resp.raise_for_status()

            response_data = resp.json()

            if response_data['icmp'] == "success" and response_data['tcp'] == "success":
                print(f">>> ip: {host}:{port} is ok in China!")
                return False
            else:
                print(f">>> ip: {host}:{port} is banned in China!")
                return True
        except Exception as e:
            print(">>> Error request for ban check:", e, "check_baned_with_gfw")
            return True

    @staticmethod
    def check_baned_with_gfw_v2(host: str, port: str | int) -> bool:
        import subprocess
        import json

        # 1716887992202
        timestamp_ = int(datetime.datetime.timestamp(datetime.datetime.now()) * 1000)
        data = {
            "idName": f"itemblockid{timestamp_}",
            "ip": f"{host}"
        }
        random_user_agent = IPChecker.get_random_user_agent()

        curl_command = [
            'curl', 'https://www.vps234.com/ipcheck/getdata/',
            '-H', 'Accept: */*',
            '-H', 'Accept-Language: zh,en;q=0.9,zh-TW;q=0.8,zh-CN;q=0.7,ja;q=0.6',
            '-H', 'Cache-Control: no-cache',
            '-H', 'Connection: keep-alive',
            '-H', 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
            '-H', 'Origin: https://www.vps234.com',
            '-H', 'Pragma: no-cache',
            '-H', 'Referer: https://www.vps234.com/ipchecker/',
            '-H', 'Sec-Fetch-Dest: empty',
            '-H', 'Sec-Fetch-Mode: cors',
            '-H', 'Sec-Fetch-Site: same-origin',
            '-H',
            f'User-Agent: {random_user_agent}',
            '-H', 'X-Requested-With: XMLHttpRequest',
            '-H', 'sec-ch-ua: "Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            '-H', 'sec-ch-ua-mobile: ?0',
            '-H', 'sec-ch-ua-platform: "macOS"',
            '--data-raw', f'idName={data["idName"]}&ip={data["ip"]}'
        ]

        try:
            # Execute the curl command
            result = subprocess.run(curl_command, capture_output=True, text=True)

            # Print the output
            # print(result.stdout)
            response_data = json.loads(str(result.stdout))

            if response_data['data']['data']['innerTCP'] == True and response_data['data']['data'][
                'outTCP'] == True:
                print(f">>> ip: {host}:{port} is ok in China!")
                return False
            else:
                print(f">>> ip: {host}:{port} is banned in China!")
                return True
        except Exception as e:
            print(">>> Error request for ban check:", e, "check_baned_with_gfw_v2")
            return True

    @staticmethod
    def get_random_user_agent() -> str:
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"
        ]

        return random.choice(user_agents)

    @staticmethod
    def detect_cloudflare_location(ip_addr: str, port: int | str, body: str, tcpDuration: str) -> dict | None:
        # {"ip": "60.246.230.77", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific",
        # "city": "Hong Kong", "network_latency": "152 ms", "download_speed": "0 kB/s"}
        if 'uag=Mozilla/5.0' in body:
            matches = re.findall('colo=([A-Z]+)', body)
            if matches:
                dataCenter = matches[0]  # Get the first match
                loc = locations.CloudflareLocationMap.get(dataCenter)
                if loc:
                    print(f"发现有效IP {ip_addr} 端口 {port} 位置信息 {loc['city']} 延迟 {tcpDuration} 毫秒,速度未知")
                    # Append a dictionary to resultChan to simulate adding to a channel
                    return {
                        "ip": ip_addr,
                        "port": port,
                        "enable_tls": 'true',
                        "data_center": dataCenter,
                        "region": loc['region'],
                        "city": loc['city'],
                        "latency": f"{tcpDuration} ms",

                    }
                print(f"发现有效IP {ip_addr} 端口 {port} 位置信息未知 延迟 {tcpDuration} 毫秒,速度未知")
                # Append a dictionary with some empty fields to resultChan
                return {
                    "ip": ip_addr,
                    "port": port,
                    "enable_tls": "true",
                    "data_center": dataCenter,
                    "region": "",
                    "city": "",
                    "latency": f"{tcpDuration} ms",
                }

        return None


class CustomResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    async def resolve(self, host, port=0, family=socket.AF_INET):
        return [{
            'hostname': host,
            'host': self.ip,
            'port': self.port,
            'family': family,
            'proto': 0,
            'flags': 0,
        }]

    async def close(self):
        pass


async def cf_speed_download(ip: str, port: int) -> (float, {}):
    url_string = f"https://speed.cloudflare.com/__down?bytes={1024 * 1024 * 1024}"
    trace_url = f"https://speed.cloudflare.com/cdn-cgi/trace"
    timeout = ClientTimeout(total=60)

    resolver = CustomResolver(ip, port)
    connector = TCPConnector(resolver=resolver)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        try:
            async with session.get(url_string) as response:
                data_len = 0
                start_time = time.monotonic()
                while True:
                    chunk = await response.content.read(1024)
                    if not chunk:
                        break
                    elapsed_time = time.monotonic() - start_time
                    if elapsed_time <= 5:
                        data_len += len(chunk)
                    else:
                        data_len += len(chunk)
                        break
                # print("data_len: ", data_len)
                # print("elapsed_time: ", elapsed_time)
                if elapsed_time - 5.0 < 0:
                    download_speed = 0.00
                else:
                    download_speed = data_len / elapsed_time

            headers = {
                'Host': 'speed.cloudflare.com',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36'
            }
            start_time = time.time()
            async with session.get(trace_url, headers=headers) as response:
                resp_text = await response.text()
                total_duration = f'{(time.time() - start_time) * 1000:.2f}'

                location = IPChecker.detect_cloudflare_location(ip, port, resp_text, str(total_duration))
                location['download_speed'] = f"{(download_speed / 1024.0):.2f} kB/s"

            return download_speed, location
        except Exception as e:
            print(f"An error occurred: {e}")
            return 0.00, {}


async def check_if_cf_proxy(ip: str, port: int) -> (bool, {}):
    url = f"http://{ip}:{port}/cdn-cgi/trace"

    host = url.replace("http://", "").replace("/cdn-cgi/trace", "")
    headers = {
        "User-Agent": "curl/7.64.1",
        "Host": host,
    }
    timeout = aiohttp.ClientTimeout(total=3.5)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            async with session.get(url, headers=headers, allow_redirects=False, ssl=False) as response:
                text = await response.text()
                # print(response_text_)
            if (
                    "400 The plain HTTP request was sent to HTTPS port" in text and "cloudflare" in text) or "visit_scheme=http" in text:
                speed, location = await cf_speed_download(ip, port)
                # 兼容有些事代理ip 但是不可测速
                if location != {} and location['city'] != "" or speed - 0.1 > 0:
                    return True, location
        except Exception as e:
            print(f"Request Error: {e}")
    return False, {}


def clean_dead_ip():
    # 发送TG消息开始
    msg_info = f"CleanGFW-Ban ip"
    telegram_notify = notify.pretty_telegram_notify("🧹🧹CleanGFW-Ban-IP运行开始",
                                                    f"clean-ban-ip gfw",
                                                    msg_info)
    telegram_notify = notify.clean_str_for_tg(telegram_notify)
    success = notify.send_telegram_message(telegram_notify)

    if success:
        print(">>> Start clean ip message sent successfully!")
    else:
        print(">>> Start clean ip message failed to send.")

    keys = r.hkeys('snifferx-result')
    dont_need_dc = ['North America', 'Europe']
    # For each key, get the value and store in Cloudflare KV
    remove_counts = 0
    for key in keys:
        value = r.hget('snifferx-result', key)

        # Prepare the data for Cloudflare KV
        # kv_key = key.decode('utf-8')
        kv_value = json.loads(value.decode('utf-8'))

        ip = kv_value['ip']
        port = kv_value['port']
        # tls = kv_value['enable_tls']
        # datacenter = kv_value['data_center']
        region = kv_value['region']
        city = kv_value['city']
        key_str = str(key)

        # 判断当前是否为周日 如果是 则进行gfw ban检测
        today = datetime.datetime.today()
        is_sunday = today.weekday() == 6

        if is_sunday:
            baned_with_gfw = IPChecker.check_band_with_gfw_with_retry(ip, port, 2)
            print(f"Proxy id: {ip}:{port} gfwban status: {baned_with_gfw}")

            time.sleep(5)
            if baned_with_gfw:
                print(f">>> 当前优选IP端口已被墙: {key_str},进行移除...")
                print(f">>> 原始记录: {key}--{kv_value}")
                r.hdel('snifferx-result', key)
                remove_counts += 1
                continue

        # 排除fofacn 的ip # 排除上海阿里云 它奇葩的禁止国外ping和tcp
        if 'fofa-cn' in key_str and port == 443 and city == 'Tokyo':
            print(f">>> fofa-cn 数据:{key_str},暂时做跳过处理...")
            continue

        # 不主动删除fofa的数据
        if 'fofa' in key_str:
            # 对于国内来说访问的city几乎都是
            print(f">>> fofa find 数据:{key_str},暂时做跳过处理...")
            continue

        if region in dont_need_dc and '906' not in key_str:
            # delete ip 主动删除US EU的ip 不做通断检测
            r.hdel('snifferx-result', key)
            remove_counts += 1
            print(f">>> 普通US/EU IP数据,当前不做通断检测，直接删除: {key_str} {kv_value}")
            continue
        port_open = IPChecker.check_port_open_with_retry(ip, port, 5)
        if not port_open:
            print(f">>> 当前优选IP端口已失效: {ip}:{port},进行移除...")
            print(f">>> 原始记录: {key_str}--{kv_value}")
            r.hdel('snifferx-result', key)
            remove_counts += 1
            continue

    # 获取剩余ip数量
    new_keys = r.hkeys('snifferx-result')
    end_msg_info = f"IP移除统计信息: {remove_counts},剩余可用IP数: {len(new_keys)}"
    telegram_notify = notify.pretty_telegram_notify("🎉🎉CleanGFW-Ban-IP运行结束",
                                                    f"clean-ban-ip gfw",
                                                    end_msg_info)
    telegram_notify = notify.clean_str_for_tg(telegram_notify)
    success = notify.send_telegram_message(telegram_notify)

    if success:
        print(">>> Start fofa find message sent successfully!")
    else:
        print(">>> Start fofa find message failed to send.")


def recover_init_data():
    results = [(b'4760:219.76.13.166:443',
                '{"ip": "219.76.13.166", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "152 ms", "download_speed": "13962 kB/s"}'),
               (b'fofa-cn:52.80.181.167:8433',
                '{"ip": "52.80.181.167",  "port": 8433,  "enable_tls": true,  "data_center": "SJC",  "region": "North America",  "city": "San Jose",  "latency": "929.74 ms",  "download_speed": "6171.83 kB/s"}'),
               (b'fofa-kr:14.6.44.199:11290',
                '{"ip": "14.6.44.199", "port": 11290, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "739.06 ms", "download_speed": "6772.99 kB/s"}'),
               (b'fofa-cn:61.93.47.11:50000',
                '{"ip": "61.93.47.11", "port": 50000, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "708.70 ms", "download_speed": "10722.08 kB/s"}'),
               (b'fofa-hk:47.76.189.102:8443',
                '{"ip": "47.76.189.102", "port": 8443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "490.03 ms", "download_speed": "15321.65 kB/s"}'),
               (b'fofa-sg:46.137.239.196:40000',
                '{"ip": "46.137.239.196", "port": 40000, "enable_tls": true, "data_center": "SIN", "region": "Asia Pacific", "city": "Singapore", "latency": "544.50 ms", "download_speed": "11894.75 kB/s"}'),
               (b'3462:1.162.54.166:443',
                '{"ip": "1.162.54.166", "port": 443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "network_latency": "192 ms", "download_speed": "3843 kB/s"}'),
               (b'4760:219.76.13.177:443',
                '{"ip": "219.76.13.177", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "152 ms", "download_speed": "13879 kB/s"}'),
               (b'fofa-tw:34.80.130.102:2233',
                '{"ip": "34.80.130.102", "port": 2233, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "latency": "156.62 ms", "download_speed": "8912.30 kB/s"}'),
               (b'fofa-jp:150.230.206.237:9710',
                '{"ip": "150.230.206.237", "port": 9710, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "533.43 ms", "download_speed": "13680.45 kB/s"}'),
               (b'fofa-jp:34.146.127.156:9993',
                '{"ip": "34.146.127.156", "port": 9993, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "340.58 ms", "download_speed": "22423.27 kB/s"}'),
               (b'fofa-jp:35.78.91.23:443',
                '{"ip": "35.78.91.23", "port": 443, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "347.61 ms", "download_speed": "22634.25 kB/s"}'),
               (b'fofa-cn:43.139.123.51:9003',
                '{"ip": "43.139.123.51",  "port": 9003,  "enable_tls": true,  "data_center": "LAX",  "region": "North America",  "city": "Los Angeles",  "latency": "737.86 ms",  "download_speed": "528.87 kB/s"}'),
               (b'fofa-cn:52.80.181.167:8433',
                '{"ip": "52.80.181.167", "port": 8433, "enable_tls": true, "data_center": "SJC", "region": "North America", "city": "San Jose", "latency": "929.74 ms", "download_speed": "6171.83 kB/s"}'),
               (b'fofa-hk:47.76.203.101:8443',
                '{"ip": "47.76.203.101", "port": 8443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "476.00 ms", "download_speed": "16526.78 kB/s"}'),
               (b'fofa-cn:139.224.43.79:443',
                '{"ip": "139.224.43.79", "port": 443, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "1231.36 ms", "download_speed": "998.17 kB/s"}'),
               (b'4609:180.94.183.57:443',
                '{"ip": "180.94.183.57", "port": 443, "enable_tls": true, "data_center": "MFM", "region": "Asia Pacific", "city": "Macau", "network_latency": "155 ms", "download_speed": "3046 kB/s"}'),
               (b'fofa-cn:47.100.162.175:443',
                '{"ip": "47.100.162.175", "port": 443, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "300.07 ms", "download_speed": "1104.49 kB/s"}'),
               (b'fofa-sg:45.76.147.187:9992',
                '{"ip": "45.76.147.187", "port": 9992, "enable_tls": true, "data_center": "SIN", "region": "Asia Pacific", "city": "Singapore", "latency": "543.56 ms", "download_speed": "13046.72 kB/s"}'),
               (b'fofa-kr:144.24.78.162:443',
                '{"ip": "144.24.78.162", "port": 443, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "435.16 ms", "download_speed": "8350.52 kB/s"}'),
               (b'fofa-cn:47.100.162.123:443',
                '{"ip": "47.100.162.123", "port": 443, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "309.58 ms", "download_speed": "839.56 kB/s"}'),
               (b'fofa-hk:47.76.62.62:8443',
                '{"ip": "47.76.62.62", "port": 8443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "497.57 ms", "download_speed": "4307.52 kB/s"}'),
               (b'4609:180.94.183.57:443',
                '{"ip": "180.94.183.57", "port": 443, "enable_tls": true, "data_center": "MFM", "region": "Asia Pacific", "city": "Macau", "network_latency": "155 ms", "download_speed": "3046 kB/s"}'),
               (b'fofa-jp:168.138.46.67:443',
                '{"ip": "168.138.46.67", "port": 443, "enable_tls": true, "data_center": "KIX", "region": "Asia Pacific", "city": "Osaka", "latency": "506.00 ms", "download_speed": "5310.25 kB/s"}'),
               (b'4760:219.76.13.177:443',
                '{"ip": "219.76.13.177", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "152 ms", "download_speed": "13879 kB/s"}'),
               (b'fofa-kr:61.84.63.225:10065',
                '{"ip": "61.84.63.225", "port": 10065, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "428.97 ms", "download_speed": "7697.56 kB/s"}'),
               (b'fofa-jp:150.230.206.237:9710',
                '{"ip": "150.230.206.237", "port": 9710, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "533.43 ms", "download_speed": "13680.45 kB/s"}'),
               (b'4760:219.76.13.183:443',
                '{"ip": "219.76.13.183", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "152 ms", "download_speed": "3803 kB/s"}'),
               (b'fofa-kr:185.249.135.14:8081',
                '{"ip": "185.249.135.14", "port": 8081, "enable_tls": true, "data_center": "RUH", "region": "Middle East", "city": "Riyadh", "latency": "771.62 ms", "download_speed": "4010.04 kB/s"}'),
               (b'fofa-hk:47.76.254.36:80',
                '{"ip": "47.76.254.36", "port": 80, "enable_tls": true, "data_center": "KUL", "region": "Asia Pacific", "city": "Kuala Lumpur", "latency": "607.99 ms", "download_speed": "4161.34 kB/s"}'),
               (b'4609:60.246.174.169:443',
                '{"ip": "60.246.174.169", "port": 443, "enable_tls": true, "data_center": "MFM", "region": "Asia Pacific", "city": "Macau", "network_latency": "157 ms", "download_speed": "3871 kB/s"}'),
               (b'135377:152.32.168.249:443',
                '{"ip": "152.32.168.249", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "210 ms", "download_speed": "122 kB/s"}'),
               (b'fofa-cn:139.196.224.73:443',
                '{"ip": "139.196.224.73", "port": 443, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "238.28 ms", "download_speed": "2749.35 kB/s"}'),
               (b'fofa-cn:47.238.36.250:80',
                '{"ip": "47.238.36.250", "port": 80, "enable_tls": true, "data_center": "KUL", "region": "Asia Pacific", "city": "Kuala Lumpur", "latency": "736.96 ms", "download_speed": "4035.18 kB/s"}'),
               (b'3462:111.250.8.123:443',
                '{"ip": "111.250.8.123", "port": 443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "network_latency": "135 ms", "download_speed": "9289 kB/s"}'),
               (b'fofa-cn:46.3.105.217:10043',
                '{"ip": "46.3.105.217", "port": 10043, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "615.06 ms", "download_speed": "11012.35 kB/s"}'),
               (b'fofa-hk:8.210.21.65:443',
                '{"ip": "8.210.21.65", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "503.01 ms", "download_speed": "12053.96 kB/s"}'),
               (b'fofa-jp:35.72.1.229:10084',
                '{"ip": "35.72.1.229", "port": 10084, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "200.33 ms", "download_speed": "981.51 kB/s"}'),
               (b'fofa-kr:185.249.135.14:8081',
                '{"ip": "185.249.135.14", "port": 8081, "enable_tls": true, "data_center": "RUH", "region": "Middle East", "city": "Riyadh", "latency": "771.62 ms", "download_speed": "4010.04 kB/s"}'),
               (b'fofa-jp:34.146.127.156:9993',
                '{"ip": "34.146.127.156", "port": 9993, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "340.58 ms", "download_speed": "22423.27 kB/s"}'),
               (b'fofa-us:154.17.0.80:564',
                '{"ip": "154.17.0.80", "port": 564, "enable_tls": true, "data_center": "LAX", "region": "North America", "city": "Los Angeles", "latency": "34.99 ms", "download_speed": "60315.80 kB/s"}'),
               (b'906:154.17.228.99:443',
                '{"ip": "154.17.228.99", "port": 443, "enable_tls": true, "data_center": "LAX", "region": "North America", "city": "Los Angeles", "network_latency": "8 ms", "download_speed": "116976 kB/s"}'),
               (b'fofa-hk:47.76.254.36:80',
                '{"ip": "47.76.254.36", "port": 80, "enable_tls": true, "data_center": "KUL", "region": "Asia Pacific", "city": "Kuala Lumpur", "latency": "607.99 ms", "download_speed": "4161.34 kB/s"}'),
               (b'fofa-cn:43.139.123.51:9011',
                '{"ip": "43.139.123.51", "port": 9011, "enable_tls": true, "data_center": "KIX", "region": "Asia Pacific", "city": "Osaka", "latency": "279.14 ms", "download_speed": "543.08 kB/s"}'),
               (b'fofa-tw:35.201.203.106:443',
                '{"ip": "35.201.203.106", "port": 443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "latency": "433.90 ms", "download_speed": "18135.21 kB/s"}'),
               (b'4760:42.2.108.170:443',
                '{"ip": "42.2.108.170", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "211 ms", "download_speed": "8201 kB/s"}'),
               (b'fofa-us:65.75.194.18:19888',
                '{"ip": "65.75.194.18", "port": 19888, "enable_tls": true, "data_center": "SJC", "region": "North America", "city": "San Jose", "latency": "59.09 ms", "download_speed": "125807.83 kB/s" }'),
               (b'fofa-kr:61.101.106.148:30012',
                '{"ip": "61.101.106.148", "port": 30012, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "419.03 ms", "download_speed": "6831.82 kB/s"}'),
               (b'fofa-cn:101.132.47.83:443',
                '{"ip": "101.132.47.83", "port": 443, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "1300.16 ms", "download_speed": "2010.85 kB/s"}'),
               (b'4760:219.76.13.186:443',
                '{"ip": "219.76.13.186", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "148 ms", "download_speed": "14373 kB/s"}'),
               (b'fofa-kr:112.187.50.212:10051',
                '{"ip": "112.187.50.212", "port": 10051, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "445.75 ms", "download_speed": "7268.16 kB/s"}'),
               (b'fofa-tw:36.234.139.46:10039',
                '{"ip": "36.234.139.46", "port": 10039, "enable_tls": true, "data_center": "KHH", "region": "Asia Pacific", "city": "Kaohsiung City", "latency": "5585.72 ms", "download_speed": "286.65 kB/s"}'),
               (b'fofa-tw:35.221.159.149:9993',
                '{"ip": "35.221.159.149", "port": 9993, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "latency": "444.19 ms", "download_speed": "17420.37 kB/s"}'),
               (b'fofa-cn:46.3.105.217:10043',
                '{"ip": "46.3.105.217", "port": 10043, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "615.06 ms", "download_speed": "11012.35 kB/s"}'),
               (b'31898:140.238.12.52:8443',
                '{"ip": "140.238.12.52", "port": 8443, "enable_tls": "true", "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "network_latency": "130 ms", "download_speed": "15358 kB/s"}'),
               (b'fofa-cn:8.210.21.65:443',
                '{"ip": "8.210.21.65", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "607.15 ms", "download_speed": "8363.76 kB/s"}'),
               (b'3462:111.247.40.230:443',
                '{"ip": "111.247.40.230", "port": 443, "enable_tls": true, "data_center": "KHH", "region": "Asia Pacific", "city": "Kaohsiung City", "network_latency": "138 ms", "download_speed": "5437 kB/s"}'),
               (b'fofa-us:154.17.0.80:564',
                '{"ip": "154.17.0.80", "port": 564, "enable_tls": true, "data_center": "LAX", "region": "North America", "city": "Los Angeles", "latency": "34.99 ms", "download_speed": "60315.80 kB/s"}'),
               (b'fofa-hk:46.3.105.217:10040',
                '{"ip": "46.3.105.217", "port": 10040, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "473.69 ms", "download_speed": "15398.43 kB/s"}'),
               (b'fofa-kr:218.144.220.44:30012',
                '{"ip": "218.144.220.44", "port": 30012, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "708.03 ms", "download_speed": "5222.06 kB/s"}'),
               (b'fofa-sg:cdn.eliteclub.space:443',
                '{"ip": "cdn.eliteclub.space", "port": 443, "enable_tls": true, "data_center": "SIN", "region": "Asia Pacific", "city": "Singapore", "latency": "361.47 ms", "download_speed": "6507.33 kB/s"}'),
               (b'3462:111.247.40.230:443',
                '{"ip": "111.247.40.230", "port": 443, "enable_tls": true, "data_center": "KHH", "region": "Asia Pacific", "city": "Kaohsiung City", "network_latency": "138 ms", "download_speed": "5437 kB/s"}'),
               (b'fofa-hk:46.3.105.217:10040',
                '{"ip": "46.3.105.217", "port": 10040, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "473.69 ms", "download_speed": "15398.43 kB/s"}'),
               (b'fofa-cn:47.100.162.123:443',
                '{"ip": "47.100.162.123", "port": 443, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "309.58 ms", "download_speed": "839.56 kB/s"}'),
               (b'fofa-cn:47.76.254.36:80',
                '{"ip": "47.76.254.36", "port": 80, "enable_tls": true, "data_center": "KUL", "region": "Asia Pacific", "city": "Kuala Lumpur", "latency": "732.89 ms", "download_speed": "4079.37 kB/s"}'),
               (b'fofa-kr:221.160.59.152:30001',
                '{"ip": "221.160.59.152", "port": 30001, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "468.84 ms", "download_speed": "7504.51 kB/s"}'),
               (b'fofa-kr:220.71.115.70:30012',
                '{"ip": "220.71.115.70", "port": 30012, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "534.93 ms", "download_speed": "6141.29 kB/s"}'),
               (b'fofa-hk:46.3.105.217:10043',
                '{"ip": "46.3.105.217", "port": 10043, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "483.90 ms", "download_speed": "14627.27 kB/s"}'),
               (b'fofa-kr:14.46.27.152:10255',
                '{"ip": "14.46.27.152", "port": 10255, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "504.47 ms", "download_speed": "7396.62 kB/s"}'),
               (b'4760:42.2.108.170:443',
                '{"ip": "42.2.108.170", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "211 ms", "download_speed": "8201 kB/s"}'),
               (b'4760:219.76.13.180:443',
                '{"ip": "219.76.13.180", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "152 ms", "download_speed": "14023 kB/s"}'),
               (b'fofa-kr:221.159.179.128:50000',
                '{"ip": "221.159.179.128", "port": 50000, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "1460.24 ms", "download_speed": "6610.69 kB/s"}'),
               (b'fofa-us:65.75.194.18:19888',
                '{"ip": "65.75.194.18","port": 19888, "enable_tls": true, "data_center": "SJC", "region": "North America", "city": "San Jose", "latency": "59.09 ms", "download_speed": "125807.83 kB/s"}'),
               (b'fofa-jp:168.138.46.67:443',
                '{"ip": "168.138.46.67", "port": 443, "enable_tls": true, "data_center": "KIX", "region": "Asia Pacific", "city": "Osaka", "latency": "506.00 ms", "download_speed": "5310.25 kB/s"}'),
               (b'fofa-cn:8.210.21.65:443',
                '{"ip": "8.210.21.65", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "607.15 ms", "download_speed": "8363.76 kB/s"}'),
               (b'fofa-kr:125.134.61.143:10050',
                '{"ip": "125.134.61.143", "port": 10050, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "1480.16 ms", "download_speed": "5680.58 kB/s"}'),
               (b'fofa-tw:36.234.139.46:10039',
                '{"ip": "36.234.139.46", "port": 10039, "enable_tls": true, "data_center": "KHH", "region": "Asia Pacific", "city": "Kaohsiung City", "latency": "5585.72 ms", "download_speed": "286.65 kB/s"}'),
               (b'fofa-kr:193.123.253.18:8081',
                '{"ip": "193.123.253.18", "port": 8081, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "524.16 ms", "download_speed": "17092.47 kB/s"}'),
               (b'fofa-kr:61.101.106.148:30012',
                '{"ip": "61.101.106.148", "port": 30012, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "419.03 ms", "download_speed": "6831.82 kB/s"}'),
               (b'fofa-hk:38.47.121.93:8081',
                '{"ip": "38.47.121.93", "port": 8081, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "348.44 ms", "download_speed": "17753.52 kB/s"}'),
               (b'3462:118.167.224.232:443',
                '{"ip": "118.167.224.232", "port": 443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "network_latency": "188 ms", "download_speed": "10429 kB/s"}'),
               (b'906:154.17.228.99:443',
                '{"ip": "154.17.228.99", "port": 443, "enable_tls": true, "data_center": "LAX", "region": "North America", "city": "Los Angeles", "network_latency": "8 ms", "download_speed": "116976 kB/s"}'),
               (b'fofa-cn:82.156.163.115:12000',
                '{"ip": "82.156.163.115", "port": 12000, "enable_tls": true, "data_center": "LAX", "region": "North America", "city": "Los Angeles", "latency": "622.92 ms", "download_speed": "559.18 kB/s"}'),
               (b'fofa-kr:112.187.50.212:10051',
                '{"ip": "112.187.50.212", "port": 10051, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "445.75 ms", "download_speed": "7268.16 kB/s"}'),
               (b'fofa-cn:183.24.11.130:8523',
                '{"ip": "183.24.11.130", "port": 8523, "enable_tls": true, "data_center": "SJC", "region": "North America", "city": "San Jose", "latency": "749.29 ms", "download_speed": "5623.28 kB/s"}'),
               (b'fofa-kr:101.235.8.74:25010',
                '{"ip": "101.235.8.74", "port": 25010, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "515.78 ms", "download_speed": "302.72 kB/s"}'),
               (b'3462:61.231.59.209:8443',
                '{"ip": "61.231.59.209", "port": 8443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "network_latency": "135 ms", "download_speed": "5537 kB/s"}'),
               (b'fofa-hk:141.98.234.8:8443',
                '{"ip": "141.98.234.8", "port": 8443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "468.58 ms", "download_speed": "16176.93 kB/s"}'),
               (b'fofa-cn:42.200.229.110:7',
                '{"ip": "42.200.229.110", "port": 7, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "latency": "801.88 ms", "download_speed": "10157.83 kB/s"}'),
               (b'fofa-cn:47.100.162.175:443',
                '{"ip": "47.100.162.175", "port": 443, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "300.07 ms", "download_speed": "1104.49 kB/s"}'),
               (b'fofa-kr:218.144.220.44:30012',
                '{"ip": "218.144.220.44", "port": 30012, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "708.03 ms", "download_speed": "5222.06 kB/s"}'),
               (b'fofa-tw:35.201.203.106:443',
                '{"ip": "35.201.203.106", "port": 443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "latency": "433.90 ms", "download_speed": "18135.21 kB/s"}'),
               (b'fofa-hk:47.76.62.62:8443',
                '{"ip": "47.76.62.62", "port": 8443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "497.57 ms", "download_speed": "4307.52 kB/s"}'),
               (b'906:154.17.230.139:443',
                '{"ip": "154.17.230.139", "port": 443, "enable_tls": true, "data_center": "LAX", "region": "North America", "city": "Los Angeles", "network_latency": "8 ms", "download_speed": "113518 kB/s"}'),
               (b'fofa-cn:35.221.159.149:9993',
                '{"ip": "35.221.159.149", "port": 9993, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "latency": "585.94 ms", "download_speed": "11767.74 kB/s"}'),
               (b'fofa-cn:82.156.163.115:12000',
                '{"ip": "82.156.163.115", "port": 12000, "enable_tls": true, "data_center": "LAX", "region": "North America", "city": "Los Angeles", "latency": "622.92 ms", "download_speed": "559.18 kB/s" }'),
               (b'906:154.17.30.93:443',
                '{"ip": "154.17.30.93", "port": 443, "enable_tls": true, "data_center": "LAX", "region": "North America", "city": "Los Angeles", "network_latency": "8 ms", "download_speed": "118907 kB/s"}'),
               (b'3462:1.162.35.103:443',
                '{"ip": "1.162.35.103", "port": 443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "network_latency": "201 ms", "download_speed": "3377 kB/s"}'),
               (b'31898:140.238.12.52:8443',
                '{"ip": "140.238.12.52", "port": 8443, "enable_tls": "true", "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "network_latency": "130 ms", "download_speed": "15358 kB/s"}'),
               (b'135377:128.1.132.82:443',
                '{"ip": "128.1.132.82", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "211 ms", "download_speed": "115 kB/s"}'),
               (b'fofa-hk:61.93.47.11:50000',
                '{"ip": "61.93.47.11", "port": 50000, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "566.48 ms", "download_speed": "13907.41 kB/s"}'),
               (b'906:154.21.95.27:8443',
                '{"ip": "154.21.95.27", "port": 8443, "enable_tls": true, "data_center": "LAX", "region": "North America", "city": "Los Angeles", "network_latency": "14 ms", "download_speed": "178790 kB/s"}'),
               (b'3462:1.162.54.166:443',
                '{"ip": "1.162.54.166", "port": 443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "network_latency": "192 ms", "download_speed": "3843 kB/s"}'),
               (b'fofa-hk:141.98.234.8:8443',
                '{"ip": "141.98.234.8", "port": 8443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "468.58 ms", "download_speed": "16176.93 kB/s"}'),
               (b'fofa-cn:61.93.47.11:50000',
                '{"ip": "61.93.47.11", "port": 50000, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "708.70 ms", "download_speed": "10722.08 kB/s"}'),
               (b'4760:219.76.13.180:443',
                '{"ip": "219.76.13.180", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "152 ms", "download_speed": "14023 kB/s"}'),
               (b'4760:219.76.13.186:443',
                '{"ip": "219.76.13.186", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "148 ms", "download_speed": "14373 kB/s"}'),
               (b'fofa-sg:8.222.181.117:443',
                '{"ip": "8.222.181.117", "port": 443, "enable_tls": true, "data_center": "SIN", "region": "Asia Pacific", "city": "Singapore", "latency": "544.50 ms", "download_speed": "11894.75 kB/s"}'),
               (b'135377:128.1.132.82:443',
                '{"ip": "128.1.132.82", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "211 ms", "download_speed": "115 kB/s"}'),
               (b'3462:1.162.35.103:443',
                '{"ip": "1.162.35.103", "port": 443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "network_latency": "201 ms", "download_speed": "3377 kB/s"}'),
               (b'fofa-sg:cdn.eliteclub.space:443',
                '{"ip": "cdn.eliteclub.space", "port": 443, "enable_tls": true, "data_center": "SIN", "region": "Asia Pacific", "city": "Singapore", "latency": "361.47 ms", "download_speed": "6507.33 kB/s"}'),
               (b'fofa-tw:35.221.159.149:9993',
                '{"ip": "35.221.159.149", "port": 9993, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "latency": "444.19 ms", "download_speed": "17420.37 kB/s"}'),
               (b'135377:152.32.168.249:443',
                '{"ip": "152.32.168.249", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "210 ms", "download_speed": "122 kB/s"}'),
               (b'fofa-hk:38.47.121.93:8081',
                '{"ip": "38.47.121.93", "port": 8081, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "348.44 ms", "download_speed": "17753.52 kB/s"}'),
               (b'fofa-kr:61.84.63.225:10065',
                '{"ip": "61.84.63.225", "port": 10065, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "428.97 ms", "download_speed": "7697.56 kB/s"}'),
               (b'4760:219.76.13.166:443',
                '{"ip": "219.76.13.166", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "152 ms", "download_speed": "13962 kB/s"}'),
               (b'fofa-kr:118.42.45.16:10050',
                '{"ip": "118.42.45.16", "port": 10050, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "1464.78 ms", "download_speed": "7476.04 kB/s"}'),
               (b'fofa-sg:13.229.119.35:88',
                '{"ip": "13.229.119.35", "port": 88, "enable_tls": true, "data_center": "SIN", "region": "Asia Pacific", "city": "Singapore", "latency": "288.33 ms", "download_speed": "7540.46 kB/s"}'),
               (b'906:154.17.30.93:443',
                '{"ip": "154.17.30.93", "port": 443, "enable_tls": true, "data_center": "LAX", "region": "North America", "city": "Los Angeles", "network_latency": "8 ms", "download_speed": "118907 kB/s"}'),
               (b'3462:118.167.224.232:443',
                '{"ip": "118.167.224.232", "port": 443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "network_latency": "188 ms", "download_speed": "10429 kB/s"}'),
               (b'906:154.17.230.139:443',
                '{"ip": "154.17.230.139", "port": 443, "enable_tls": true, "data_center": "LAX", "region": "North America", "city": "Los Angeles", "network_latency": "8 ms", "download_speed": "113518 kB/s"}'),
               (b'135377:118.26.38.134:443',
                '{"ip": "118.26.38.134", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "215 ms", "download_speed": "61 kB/s"}'),
               (b'4785:45.12.89.178:443',
                '{"ip": "45.12.89.178", "port": 443, "enable_tls": true, "data_center": "KIX", "region": "Asia Pacific", "city": "Osaka", "network_latency": "151 ms", "download_speed": "4908 kB/s"}'),
               (b'fofa-hk:47.238.36.250:80',
                '{"ip": "47.238.36.250", "port": 80, "enable_tls": true, "data_center": "KUL", "region": "Asia Pacific", "city": "Kuala Lumpur", "latency": "604.13 ms", "download_speed": "4151.99 kB/s"}'),
               (b'fofa-hk:46.3.105.217:10043',
                '{"ip": "46.3.105.217", "port": 10043, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "483.90 ms", "download_speed": "14627.27 kB/s"}'),
               (b'135377:118.26.38.134:443',
                '{"ip": "118.26.38.134", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "215 ms", "download_speed": "61 kB/s"}'),
               (b'fofa-cn:47.99.152.144:8888',
                '{"ip": "47.99.152.144", "port": 8888, "enable_tls": true, "data_center": "IAD", "region": "North America", "city": "Ashburn", "latency": "722.80 ms", "download_speed": "472.82 kB/s"}'),
               (b'fofa-sg:13.229.119.35:88',
                '{"ip": "13.229.119.35", "port": 88, "enable_tls": true, "data_center": "SIN", "region": "Asia Pacific", "city": "Singapore", "latency": "288.33 ms", "download_speed": "7540.46 kB/s"}'),
               (b'fofa-cn:106.55.177.58:3396',
                '{"ip": "106.55.177.58", "port": 3396, "enable_tls": true, "data_center": "SJC", "region": "North America", "city": "San Jose", "latency": "548.45 ms", "download_speed": "1093.65 kB/s"}'),
               (b'fofa-cn:47.76.254.36:80',
                '{"ip": "47.76.254.36", "port": 80, "enable_tls": true, "data_center": "KUL", "region": "Asia Pacific", "city": "Kuala Lumpur", "latency": "732.89 ms", "download_speed": "4079.37 kB/s"}'),
               (b'fofa-sg:13.215.179.186:10002',
                '{"ip": "13.215.179.186", "port": 10002, "enable_tls": true, "data_center": "SIN", "region": "Asia Pacific", "city": "Singapore", "latency": "645.10 ms", "download_speed": "6356.43 kB/s"}'),
               (b'4760:219.76.13.181:443',
                '{"ip": "219.76.13.181", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "152 ms", "download_speed": "14076 kB/s"}'),
               (b'fofa-sg:8.222.181.117:443',
                '{"ip": "8.222.181.117", "port": 443, "enable_tls": true, "data_center": "SIN", "region": "Asia Pacific", "city": "Singapore", "latency": "544.50 ms", "download_speed": "11894.75 kB/s"}'),
               (b'906:154.17.224.138:443',
                '{"ip": "154.17.224.138", "port": 443, "enable_tls": true, "data_center": "LAX", "region": "North America", "city": "Los Angeles", "network_latency": "8 ms", "download_speed": "114823 kB/s"}'),
               (b'fofa-tw:34.80.130.102:2233',
                '{"ip": "34.80.130.102", "port": 2233, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "latency": "156.62 ms", "download_speed": "8912.30 kB/s"}'),
               (b'fofa-jp:13.231.236.95:8443',
                '{"ip": "13.231.236.95", "port": 8443, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "269.44 ms", "download_speed": "5107.68 kB/s"}'),
               (b'fofa-kr:220.71.115.70:30012',
                '{"ip": "220.71.115.70", "port": 30012, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "534.93 ms", "download_speed": "6141.29 kB/s"}'),
               (b'fofa-hk:47.238.36.250:80',
                '{"ip": "47.238.36.250", "port": 80, "enable_tls": true, "data_center": "KUL", "region": "Asia Pacific", "city": "Kuala Lumpur", "latency": "604.13 ms", "download_speed": "4151.99 kB/s"}'),
               (b'fofa-kr:125.134.61.143:10050',
                '{"ip": "125.134.61.143", "port": 10050, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "1480.16 ms", "download_speed": "5680.58 kB/s"}'),
               (b'135377:165.154.41.40:443',
                '{"ip": "165.154.41.40", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "network_latency": "210 ms", "download_speed": "116 kB/s"}'),
               (b'3462:36.226.242.119:443',
                '{"ip": "36.226.242.119", "port": 443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "network_latency": "173 ms", "download_speed": "5076 kB/s"}'),
               (b'fofa-cn:43.139.123.51:9003',
                '{"ip": "43.139.123.51", "port": 9003, "enable_tls": true, "data_center": "LAX", "region": "North America", "city": "Los Angeles", "latency": "737.86 ms", "download_speed": "528.87 kB/s"}'),
               (b'3462:111.250.8.123:443',
                '{"ip": "111.250.8.123", "port": 443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "network_latency": "135 ms", "download_speed": "9289 kB/s"}'),
               (b'3462:36.226.242.119:443',
                '{"ip": "36.226.242.119", "port": 443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "network_latency": "173 ms", "download_speed": "5076 kB/s"}'),
               (b'4785:45.12.89.178:443',
                '{"ip": "45.12.89.178", "port": 443, "enable_tls": true, "data_center": "KIX", "region": "Asia Pacific", "city": "Osaka", "network_latency": "151 ms", "download_speed": "4908 kB/s"}'),
               (b'fofa-kr:14.46.27.152:10255',
                '{"ip": "14.46.27.152", "port": 10255, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "504.47 ms", "download_speed": "7396.62 kB/s"}'),
               (b'4609:60.246.174.169:443',
                '{"ip": "60.246.174.169", "port": 443, "enable_tls": true, "data_center": "MFM", "region": "Asia Pacific", "city": "Macau", "network_latency": "157 ms", "download_speed": "3871 kB/s"}'),
               (b'3462:61.231.59.209:8443',
                '{"ip": "61.231.59.209", "port": 8443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "network_latency": "135 ms", "download_speed": "5537 kB/s"}'),
               (b'fofa-jp:35.72.1.229:10084',
                '{"ip": "35.72.1.229", "port": 10084, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "200.33 ms", "download_speed": "981.51 kB/s"}'),
               (b'fofa-sg:13.215.179.186:10002',
                '{"ip": "13.215.179.186", "port": 10002, "enable_tls": true, "data_center": "SIN", "region": "Asia Pacific", "city": "Singapore", "latency": "645.10 ms", "download_speed": "6356.43 kB/s"}'),
               (b'fofa-cn:101.132.47.83:443',
                '{"ip": "101.132.47.83", "port": 443, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "1300.16 ms", "download_speed": "2010.85 kB/s"}'),
               (b'3462:36.226.250.153:443',
                '{"ip": "36.226.250.153", "port": 443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "network_latency": "176 ms", "download_speed": "5430 kB/s"}'),
               (b'3462:36.226.250.153:443',
                '{"ip": "36.226.250.153", "port": 443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "network_latency": "176 ms", "download_speed": "5430 kB/s"}'),
               (b'fofa-sg:46.137.239.196:40000',
                '{"ip": "46.137.239.196", "port": 40000, "enable_tls": true, "data_center": "SIN", "region": "Asia Pacific", "city": "Singapore", "latency": "544.50 ms", "download_speed": "11894.75 kB/s"}'),
               (b'fofa-cn:35.221.159.149:9993',
                '{"ip": "35.221.159.149", "port": 9993, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "latency": "585.94 ms", "download_speed": "11767.74 kB/s"}'),
               (b'906:154.21.95.27:8443',
                '{"ip": "154.21.95.27", "port": 8443, "enable_tls": true, "data_center": "LAX", "region": "North America", "city": "Los Angeles", "network_latency": "14 ms", "download_speed": "178790 kB/s"}'),
               (b'3462:111.247.40.226:443',
                '{"ip": "111.247.40.226", "port": 443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "network_latency": "138 ms", "download_speed": "6180 kB/s"}'),
               (b'fofa-jp:13.231.236.95:8443',
                '{"ip": "13.231.236.95", "port": 8443, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "269.44 ms", "download_speed": "5107.68 kB/s"}'),
               (b'fofa-hk:8.210.21.65:443',
                '{"ip": "8.210.21.65", "port": 443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "503.01 ms", "download_speed": "12053.96 kB/s"}'),
               (b'fofa-hk:42.200.229.110:7',
                '{"ip": "42.200.229.110", "port": 7, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "latency": "634.73 ms", "download_speed": "14243.06 kB/s"}'),
               (b'fofa-hk:61.93.47.11:50000',
                '{"ip": "61.93.47.11", "port": 50000, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "566.48 ms", "download_speed": "13907.41 kB/s"}'),
               (b'fofa-kr:101.235.8.74:25010',
                '{"ip": "101.235.8.74", "port": 25010, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "515.78 ms", "download_speed": "302.72 kB/s"}'),
               (b'906:154.17.224.138:443',
                '{"ip": "154.17.224.138", "port": 443, "enable_tls": true, "data_center": "LAX", "region": "North America", "city": "Los Angeles", "network_latency": "8 ms", "download_speed": "114823 kB/s"}'),
               (b'fofa-hk:47.76.203.101:8443',
                '{"ip": "47.76.203.101", "port": 8443, "enable_tls": true, "data_center": "HKG", "region": "Asia Pacific", "city": "Hong Kong", "latency": "476.00 ms", "download_speed": "16526.78 kB/s"}'),
               (b'fofa-sg:45.76.147.187:9992',
                '{"ip": "45.76.147.187", "port": 9992, "enable_tls": true, "data_center": "SIN", "region": "Asia Pacific", "city": "Singapore", "latency": "543.56 ms", "download_speed": "13046.72 kB/s"}'),
               (b'fofa-cn:183.24.11.130:8523',
                '{"ip": "183.24.11.130", "port": 8523, "enable_tls": true, "data_center": "SJC", "region": "North America", "city": "San Jose", "latency": "749.29 ms", "download_speed": "5623.28 kB/s"}'),
               (b'fofa-jp:35.78.91.23:443',
                '{"ip": "35.78.91.23", "port": 443, "enable_tls": true, "data_center": "NRT", "region": "Asia Pacific", "city": "Tokyo", "latency": "347.61 ms", "download_speed": "22634.25 kB/s"}'),
               (b'3462:111.247.40.226:443',
                '{"ip": "111.247.40.226", "port": 443, "enable_tls": true, "data_center": "TPE", "region": "Asia Pacific", "city": "Taipei", "network_latency": "138 ms", "download_speed": "6180 kB/s"}'),
               (b'fofa-cn:106.55.177.58:3396',
                '{"ip": "106.55.177.58", "port": 3396, "enable_tls": true, "data_center": "SJC", "region": "North America", "city": "San Jose", "latency": "548.45 ms", "download_speed": "1093.65 kB/s"}'),
               (b'fofa-kr:144.24.78.162:443',
                '{"ip": "144.24.78.162", "port": 443, "enable_tls": true, "data_center": "ICN", "region": "Asia Pacific", "city": "Seoul", "latency": "435.16 ms", "download_speed": "8350.52 kB/s"}'),
               (b'fofa-cn:47.238.36.250:80',
                '{"ip": "47.238.36.250", "port": 80, "enable_tls": true, "data_center": "KUL", "region": "Asia Pacific", "city": "Kuala Lumpur", "latency": "736.96 ms", "download_speed": "4035.18 kB/s"}')]
    unique_key = {}
    for pair in results:
        unique_key[pair[0]] = pair[1]
    print(len(unique_key))
    r.delete("snifferx-result")

    for key, value in unique_key.items():
        try:
            loads = json.loads(value)
            dumps = json.dumps(loads)
            print(dumps)
            print(str(key, 'utf-8'))
            new_key = str(key, 'utf-8')
            r.hset('snifferx-result', new_key, dumps)
        except Exception as e:
            print(f"error: {key},{value}")


if __name__ == '__main__':
    clean_dead_ip()
    # recover_init_data()
