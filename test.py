import os
import ssl
from datetime import datetime

import OpenSSL
import redis


def test_env_injection():
    redis_host = os.getenv("REDIS_HOST", "127.0.0.1")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    redis_pass = os.getenv("REDIS_PASS", "mypass")

    print("Environment injection")
    print(redis_host)
    print(redis_port)
    print(redis_pass)

    # 初始化 Redis 连接
    r = redis.Redis(
        host=redis_host,
        port=redis_port,
        password=redis_pass,
        db=0,
        ssl=False
    )
    ping = r.ping()
    print(f"Resp from redis: {ping}")


def test_ip_file():
    from main import parse_masscan_output
    parse_masscan_output("masscan_results/45.59.184.0-24_temp.txt", "masscan_results/45.59.184.0-24_ip.txt")


def get_current_weekday_plus():
    now = datetime.now()
    current_time = now.time()
    current_day = now.weekday()  # Monday is 0, Sunday is 6

    # Define time ranges
    morning_start = datetime.strptime("01:00", "%H:%M").time()
    morning_end = datetime.strptime("11:00", "%H:%M").time()
    afternoon_start = datetime.strptime("12:00", "%H:%M").time()
    afternoon_end = datetime.strptime("23:00", "%H:%M").time()

    # Check each day and time range
    for day in range(7):  # 0 to 6, representing Monday to Sunday
        if current_day == day:
            if morning_start <= current_time < morning_end:
                return day * 2
            elif afternoon_start <= current_time < afternoon_end:
                return day * 2 + 1

    # If not in any specified range, return -1 or handle as needed
    return 0


import unittest
from unittest.mock import patch
import pytz

# class TestGetCurrentWeekdayPlus(unittest.TestCase):
#     @patch('datetime.datetime')
#     def test_monday_morning(self, mock_datetime):
#         eastern = pytz.timezone('US/Eastern')
#         mock_datetime.now.return_value = datetime(2023, 7, 24, 8, 0).replace(tzinfo=pytz.UTC).astimezone(
#             eastern)
#         self.assertEqual(get_current_weekday_plus(), 0)
#
#     @patch('datetime.datetime')
#     def test_monday_afternoon(self, mock_datetime):
#         eastern = pytz.timezone('US/Eastern')
#         mock_datetime.now.return_value = datetime(2023, 7, 24, 13, 0).replace(tzinfo=pytz.UTC).astimezone(
#             eastern)
#         self.assertEqual(get_current_weekday_plus(), 1)
#
#     @patch('datetime.datetime')
#     def test_sunday_morning(self, mock_datetime):
#         eastern = pytz.timezone('US/Eastern')
#         mock_datetime.now.return_value = datetime(2023, 7, 30, 9, 0).replace(tzinfo=pytz.UTC).astimezone(
#             eastern)
#         self.assertEqual(get_current_weekday_plus(), 12)
#
#     @patch('datetime.datetime')
#     def test_sunday_afternoon(self, mock_datetime):
#         eastern = pytz.timezone('US/Eastern')
#         mock_datetime.now.return_value = datetime(2023, 7, 30, 15, 0).replace(tzinfo=pytz.UTC).astimezone(
#             eastern)
#         self.assertEqual(get_current_weekday_plus(), 13)
#
#     @patch('datetime.datetime')
#     def test_edge_case_morning(self, mock_datetime):
#         eastern = pytz.timezone('US/Eastern')
#         mock_datetime.now.return_value = datetime(2023, 7, 25, 11, 59).replace(tzinfo=pytz.UTC).astimezone(
#             eastern)
#         self.assertEqual(get_current_weekday_plus(), 2)
#
#     @patch('datetime.datetime')
#     def test_edge_case_afternoon(self, mock_datetime):
#         eastern = pytz.timezone('US/Eastern')
#         mock_datetime.now.return_value = datetime(2023, 7, 25, 12, 0).replace(tzinfo=pytz.UTC).astimezone(
#             eastern)
#         self.assertEqual(get_current_weekday_plus(), 3)
#
#     @patch('datetime.datetime')
#     def test_midnight(self, mock_datetime):
#         eastern = pytz.timezone('US/Eastern')
#         mock_datetime.now.return_value = datetime(2023, 7, 26, 0, 0).replace(tzinfo=pytz.UTC).astimezone(
#             eastern)
#         self.assertEqual(get_current_weekday_plus(), 0)  # Assuming it falls outside the defined ranges
#

import requests
import socket


def new_check_cf_proxy(ip: str, port: int | str) -> str | bool:
    """
    向给定IP和端口发送GET请求，返回特定响应或超时指示。

    参数:
    ip: 表示IP地址的字符串。
    port: 表示端口号的整数。

    返回:
    表示结果的字符串（'https_error' 或 'timeout'）。
    """
    url = f"http://{ip}:{port}/cdn-cgi/trace"
    try:
        # 禁用重定向，并设置超时为 1.5 秒
        response = requests.get(url, timeout=3, allow_redirects=False, verify=False)
        if (
                "400 The plain HTTP request was sent to HTTPS port" in response.text and "cloudflare" in response.text) or "visit_scheme=http" in response.text:
            return True

        # if response.status_code == 403 and '403 Forbidden' in response.text:
        #     return True
    except requests.exceptions.Timeout:
        return False
    except requests.exceptions.RequestException:
        return False
    return False


import socket
import ipaddress


def check_ssl(ip_str: str, port_str: str | int) -> bool:
    ip = ip_str
    port = str(port_str)

    # 创建SSL上下文，允许TLS 1.2和TLS 1.3
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as secure_sock:
                # 获取证书
                cert = secure_sock.getpeercert(binary_form=True)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)

                # 检查证书的主题和颁发者
                subject = dict(x509.get_subject().get_components())
                issuer = dict(x509.get_issuer().get_components())

                # 检查常见的Cloudflare证书特征
                if b'cloudflare' in subject.get(b'O', b'').lower() or b'cloudflare' in issuer.get(b'O', b'').lower():
                    return True

                # 检查证书扩展中的Cloudflare特征
                for i in range(x509.get_extension_count()):
                    ext = x509.get_extension(i)
                    if 'cloudflare' in str(ext).lower():
                        return True

    except (socket.timeout, ConnectionRefusedError, ssl.SSLError):
        pass  # 忽略连接错误

    return False


def is_cloudflare_proxy(ip, port):
    # Cloudflare's IPv4 ranges (this list may not be exhaustive)
    cloudflare_ranges = [
        '173.245.48.0/20',
        '103.21.244.0/22',
        '103.22.200.0/22',
        '103.31.4.0/22',
        '141.101.64.0/18',
        '108.162.192.0/18',
        '190.93.240.0/20',
        '188.114.96.0/20',
        '197.234.240.0/22',
        '198.41.128.0/17',
        '162.158.0.0/15',
        '104.16.0.0/12',
        '172.64.0.0/13',
        '131.0.72.0/22'
    ]

    # Check if the IP is in Cloudflare's ranges
    ip_obj = ipaddress.ip_address(ip)
    in_cloudflare_range = any(ip_obj in ipaddress.ip_network(cf_range) for cf_range in cloudflare_ranges)

    if in_cloudflare_range:
        return True

    # Check if the IP resolves to a Cloudflare domain
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if 'cloudflare' in hostname.lower():
            return True
    except socket.herror:
        pass  # Ignore if reverse DNS lookup fails

    # Additional check: try to connect to the IP:port
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            sock.send(b"GET / HTTP/1.1\r\nHost: speed.cloudflare.com\r\n\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            if 'cloudflare' in response.lower():
                ssl_check = check_ssl(ip, port)
                if ssl_check:
                    return True
    except (socket.timeout, ConnectionRefusedError):
        pass  # Ignore connection errors

    return False


if __name__ == '__main__':
    # refresh_markdown("ports_results")
    # test_env_injection()

    # test_ip_file()

    # print(get_current_weekday_plus())
    # unittest.main()

    # proxy_ip = "47.56.196.176"
    # proxy_port = "9443"
    # proxy_ip = '8.218.8.142'
    # proxy_port = '8443'
    #
    # result = new_check_cf_proxy(proxy_ip, proxy_port)
    # if result:
    #     print("The proxy appears to be valid for speed.cloudflare.com")
    # else:
    #     print("The proxy does not appear to be valid for speed.cloudflare.com")

    # 测试ip
    # ips = [('43.156.143.198', 40809), ('219.76.13.166', 443), ('146.56.37.60', 20017), ('58.145.73.59', '18078'),
    #        ('14.6.44.199', 11290), ('211.75.243.91', 16764)]
    # # Example usage
    # for ipinfo in ips:
    #     ip = ipinfo[0]
    #     port = ipinfo[1]
    #     if is_cloudflare_proxy(ip, port):
    #         print(f"{ip}:{port} is likely a Cloudflare reverse proxy.")
    #     else:
    #         print(f"{ip}:{port} is not a Cloudflare reverse proxy.")

    is_ip_but_timeout = [('8.222.134.170', 2096), ('8.210.21.65', 443), ('8.217.64.226', 443)]
    for ipinfo in is_ip_but_timeout:
        ip = ipinfo[0]
        port = ipinfo[1]
        if is_cloudflare_proxy(ip, port):
            print(f"{ip}:{port} is likely a Cloudflare reverse proxy.")
        else:
            print(f"{ip}:{port} is not a Cloudflare reverse proxy.")
