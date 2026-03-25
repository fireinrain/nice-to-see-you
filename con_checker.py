import concurrent.futures as futures
import csv
import datetime
import json
import random
import re
from collections import defaultdict

import urllib3
import aiohttp
import asyncio
import time
import socket
import tg_notify
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
    # TODO 该方法暂时无法使用
    def check_baned_with_gfw(host: str, port: str | int) -> bool:
        request_url = f"https://api.ycwxgzs.com/ipcheck/index.php"
        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "zh,en;q=0.9,zh-TW;q=0.8,zh-CN;q=0.7,ja;q=0.6",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Origin": "https://ip112.cn",
            "Referer": "https://ip112.cn/",
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
        r = {
            "ip": f"{host}",
            "port": f"{port}",
        }
        try:
            resp = requests.post(request_url, data=r, headers=headers)
            resp.raise_for_status()

            response_data = resp.json()

            if "端口可用" in response_data['tcp']:
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
    url_string = f"https://speed.cloudflare.com/__down?bytes={99999999}"
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
    telegram_notify = tg_notify.pretty_telegram_notify("🧹🧹CleanGFW-Ban-IP运行开始",
                                                    f"clean-ban-ip gfw",
                                                    msg_info)
    telegram_notify = tg_notify.clean_str_for_tg(telegram_notify)
    success = tg_notify.send_telegram_message(telegram_notify)

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
        if not value:
            r.hdel('snifferx-result', key)
            continue

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
        if 'fofa-cn' in key_str and (city == 'Tokyo' or city == 'San Jose'):
            print(f">>> fofa-cn 数据:{key_str},暂时做跳过处理...")
            continue

        # 不主动删除fofa的数据
        # if 'fofa' in key_str:
        #     # 对于国内来说访问的city几乎都是
        #     print(f">>> fofa find 数据:{key_str},暂时做跳过处理...")
        #     continue

        # 保留906 25820(it7) 并且fofa-us的数据
        if region in dont_need_dc and ('906' not in key_str and '25820' not in key_str and 'fofa-us' not in key_str):
            # delete ip 主动删除US EU的ip 不做通断检测
            r.hdel('snifferx-result', key)
            remove_counts += 1
            print(f">>> 普通US/EU IP数据,当前不做通断检测，直接删除: {key_str} {kv_value}")
            continue
        port_open = IPChecker.check_port_open_with_retry(ip, port, 3)
        if not port_open:
            print(f">>> 当前优选IP端口已失效: {ip}:{port},进行移除...")
            print(f">>> 原始记录: {key_str}--{kv_value}")
            r.hdel('snifferx-result', key)
            remove_counts += 1
            continue

    # 获取剩余ip数量
    new_keys = r.hkeys('snifferx-result')
    ip_counts = len(new_keys)
    # 写入记录
    write_ip_report2csv(ip_counts)
    write_ip_report2json(ip_counts)
    print(f"写入记录成功:{ip_counts}")
    end_msg_info = f"IP移除统计信息: {remove_counts},剩余可用IP数: {ip_counts}"
    telegram_notify = tg_notify.pretty_telegram_notify("🎉🎉CleanGFW-Ban-IP运行结束",
                                                    f"clean-ban-ip gfw",
                                                    end_msg_info)
    telegram_notify = tg_notify.clean_str_for_tg(telegram_notify)
    success = tg_notify.send_telegram_message(telegram_notify)

    if success:
        print(">>> Start fofa find message sent successfully!")
    else:
        print(">>> Start fofa find message failed to send.")


def write_ip_report2csv(ip_counts: int):
    current_date_str = datetime.datetime.today().strftime('%Y-%m-%d')
    # report_data = f'{current_date_str},{ip_counts}'
    reader = None
    with open('report.csv', mode='r', newline='') as file:
        reader = list(csv.reader(file))

        # Check if the last row's date matches the specified date
        if reader[-1][0] == current_date_str:
            reader[-1] = [current_date_str, ip_counts]
        else:
            reader.append([current_date_str, ip_counts])
    # Write the updated data back to the CSV file
    with open('report.csv', mode='w', newline='') as file:
        datas = [f'{i[0]},{i[1]}' for i in reader]
        data_str = '\n'.join(datas)
        file.write(data_str)


def write_ip_report2json(ip_counts: int):
    data_center_count = defaultdict(int)
    keys = r.hkeys('snifferx-result')
    # For each key, get the value and store in Cloudflare KV
    for key in keys:
        value = r.hget('snifferx-result', key)

        # Prepare the data for Cloudflare KV
        # kv_key = key.decode('utf-8')
        kv_value = json.loads(value.decode('utf-8'))

        data_center = kv_value['data_center']
        data_center_count[data_center] += 1
    data_center_count = dict(data_center_count)
    print(f"current region report: {data_center_count}")

    current_date_str = datetime.datetime.today().strftime('%Y-%m-%d')
    with open('report.json', 'r') as f:
        report_json = f.read()
        json_loads = json.loads(report_json)

    last_record = json_loads[-1]
    last_record_date_ = last_record['date']
    if last_record_date_ == current_date_str:
        json_loads[-1] = {
            'date': current_date_str,
            'counts': ip_counts,
            'detail': data_center_count
        }
    else:
        d = {
            'date': current_date_str,
            'counts': ip_counts,
            'detail': data_center_count
        }
        json_loads.append(d)

    data_dumps = json.dumps(json_loads)
    # print(data_dumps)
    with open('report.json', 'w') as f:
        f.write(data_dumps)
        f.flush()
    # 导入数据作为api结果
    export_result_json_data()


def export_result_json_data():
    key = "snifferx-result"
    # 东八区
    tz = datetime.timezone(datetime.timedelta(hours=8))
    now = datetime.datetime.now(tz)
    time_str = now.strftime("%Y-%m-%d %H:%M:%S")
    try:
        # 1️⃣ 获取整个 hash
        data = r.hgetall(key)

        result_list = []

        # 2️⃣ 遍历 value
        for field, value in data.items():
            try:
                # value 是 JSON 字符串 → 转 dict
                # asn 数据
                key_str = str(field)
                asn = key_str.split(":")[0]
                obj = json.loads(value)
                obj["asn"] = asn
                # 最后检查时间
                obj["last_check"] = time_str
                result_list.append(obj)
            except Exception as e:
                print(f"解析失败: {field}", e)

        # 3️⃣ 写入文件
        with open("result.json", "w", encoding="utf-8") as f:
            json.dump(result_list, f, ensure_ascii=False, indent=2)
        print(f"✅ 导出完成，共 {len(result_list)} 条")
    except Exception as e:
        print("❌ 导出失败:", e)


if __name__ == '__main__':
    clean_dead_ip()
    # write_ip_report2csv(44)
    # write_ip_report2json(401)
    # gfw = IPChecker.check_baned_with_gfw("cloud3.131433.xyz", "22")
    # print(gfw)
