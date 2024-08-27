import csv
import datetime
import json
import os
import shutil
import subprocess
import sys
import time
from collections import namedtuple

from checker import IPChecker
from redis_tool import r

import notify
from asn import CountryASN
import requests
import cloudflare


# 获取所有 CIDR 列表
def get_cidr_ips(asn):
    # 确保 asn 目录存在
    asn_dir = "asn"
    os.makedirs(asn_dir, exist_ok=True)

    file_path = os.path.join(asn_dir, f"{asn}")

    # 检查是否存在对应的 ASN 文件
    if os.path.exists(file_path):
        # 如果文件存在，读取文件内容
        with open(file_path, 'r') as file:
            cidrs = json.load(file)
        print(f"CIDR data for ASN {asn} loaded from file.")
    else:
        # 如果文件不存在，请求 API 数据
        url = f'https://api.bgpview.io/asn/{asn}/prefixes'
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Cookie": "cf_clearance=QGTGcYnHuiA.9rho9oE4t8qMiyEOZbTbSISclJRmL2A-1720255983-1.0.1.1-Mf0yAeogUfsanJBjw3qpZKalVLAfsN8AyPnjlQDzT0PvEFBOO7Ypp9NyQ4WCWHIAaeCAYaqpVE_Aa6z3s8AIpA; _ga=GA1.2.16443840.1721715301; _gid=GA1.2.1729940749.1721936545; _ga_7YFHLCZHVM=GS1.2.1721936545.5.1.1721937177.55.0.0"
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        cidrs = [prefix['prefix'] for prefix in data['data']['ipv4_prefixes']]

        # 将数据写入文件
        with open(file_path, 'w') as file:
            json.dump(cidrs, file)
        print(f"CIDR data for ASN {asn} fetched from API and saved to file.")

    return cidrs


# 将 CIDR 列表存入 Redis
def store_cidrs_in_redis(asn) -> []:
    cidrs = get_cidr_ips(asn)
    return cidrs


# 使用 Masscan 扫描所有 IP 的端口
def scan_ip_range(cidr, output_file, scan_ports="443"):
    cmd = ["masscan", cidr, f"-p{scan_ports}", "--rate=20000", "--wait=3", "-oL", output_file]
    print(f"Executing command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("Scan completed successfully.")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error executing masscan: {e}")
        print(f"Exit status: {e.returncode}")
        print(f"Standard output: {e.stdout}")
        print(f"Standard error: {e.stderr}")


def iptest_snifferx(input_file: str, output_file: str) -> str | None:
    # ./iptest -file=ip.txt -max=100 -outfile=AS4609-20000-25000.csv -speedtest=3 -tls=1
    cmd = ["./love-you", f"-file={input_file}", f"-max=100", f"-outfile={output_file}", "-speedtest=3", "-tls=1"]
    print(f"Executing command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("IPTest completed successfully.")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error executing masscan: {e}")
        print(f"Exit status: {e.returncode}")
        print(f"Standard output: {e.stdout}")
        print(f"Standard error: {e.stderr}")
    if os.path.exists(output_file):
        return output_file
    return None


# 解析 Masscan 输出并统计端口
def parse_masscan_output(file_path: str, ip_text_file: str):
    ip_port_list = []
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('open'):
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[2]
                    ip = parts[3]
                    ip_port_list.append(ip + " " + port)
    with open(ip_text_file, "w") as f:
        f.write("\n".join(ip_port_list))
        f.flush()
    return ip_text_file


def store_ip_port_result_in_redis(asn, iptests: []):
    for server in iptests:
        ip = server["ip"]
        port = server["port"]
        # TODO 判断是否有问题 0.00 kB/s
        # 修改为0.00 可能会造成一些能用的IP被遗漏
        # 如果设置为0 会导致有些看似可用的IP被误用
        # 目前设置为宁愿遗漏
        if server["download_speed"] == '0.00 kB/s':
            continue
        server_info_json = json.dumps(server)

        r.hsetnx('snifferx-cfcdn', f'{asn}:{ip}:{port}', server_info_json)
        # 添加到cf dns 记录
        cloudflare.add_dns_record('A', cloudflare.hostname, f'{ip}')

        time.sleep(1)


def server_info_to_dict(server_info):
    return {
        "ip": server_info.ip,
        "port": server_info.port,
        "enable_tls": server_info.enable_tls,
        "data_center": server_info.data_center,
        "region": server_info.region,
        "city": server_info.city,
        "network_latency": server_info.network_latency,
        "download_speed": server_info.download_speed
    }


def scan_and_store_results(asn, scan_ports):
    os.makedirs("masscan_results", exist_ok=True)
    batch = get_cidr_ips(asn)
    if not batch:
        return
    cidrs = " ".join(batch)
    output_file = f"masscan_results/{batch[0].replace('/', '-')}_temp.txt"
    scan_ip_range(cidrs, output_file, scan_ports)
    ip_text_file = f"masscan_results/{batch[0].replace('/', '-')}_ip.txt"
    ip_port_file = parse_masscan_output(output_file, ip_text_file)
    ip_test_file = f"masscan_results/{batch[0].replace('/', '-')}_iptest.csv"
    snifferx = iptest_snifferx(ip_port_file, ip_test_file)
    if snifferx:
        # parse result and store to redis
        iptests = parse_result_csv(snifferx)
        store_ip_port_result_in_redis(asn, iptests)
        print(f"当前搜索到ip数量: {len(iptests)}")

    print(f"当前节点任务已经完成: {datetime.datetime.now()}")
    clear_directory("masscan_results")


# 最多返回6行数据
def parse_result_csv(result_csv_file: str) -> []:
    ServerInfo = namedtuple("ServerInfo", ["ip", "port", "enable_tls", "data_center",
                                           "region", "city", "network_latency", "download_speed"])

    with open(result_csv_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip the header row

        data = []
        for row in reader:
            server_info = ServerInfo(
                ip=row[0],
                port=int(row[1]),
                enable_tls=row[2].lower() == "true",
                data_center=row[3],
                region=row[4],
                city=row[5],
                network_latency=row[6],
                download_speed=row[7]
            )
            server_info_dict = server_info_to_dict(server_info)
            data.append(server_info_dict)
    # TODO 以HK JP TW KR SG 排序
    return data if len(data) < 25 else data[:25]


def clear_directory(folder_path):
    # 确保文件夹存在
    if os.path.exists(folder_path):
        # 遍历文件夹中的所有内容
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            try:
                # 如果是文件夹，则递归删除
                if os.path.isdir(file_path):
                    shutil.rmtree(file_path)
                # 如果是文件，则直接删除
                else:
                    os.remove(file_path)
            except Exception as e:
                print(f'Error: {e}')


def count_fields_containing_asn(hashmap_key, asn):
    count = 0
    cursor = 0

    while True:
        # 使用 HSCAN 命令获取一批 field
        cursor, fields = r.hscan(hashmap_key, cursor)

        # 计算包含 'abc' 的 field 数量
        count += sum(1 for field in fields if f'{asn}' in str(field))

        # 如果 cursor 为 0，说明遍历完成
        if cursor == 0:
            break

    return count


def run_task(asn_number: str):
    asn = asn_number

    scan_ports = '443'

    scan_and_store_results(asn, scan_ports)

    result_counts = count_fields_containing_asn("snifferx-cfcdn", asn)

    msg_info = f"CFCDN扫描结束: ASN{asn},结果数量: {result_counts}"
    telegram_notify = notify.pretty_telegram_notify("🎉🎉Open-Port-Sniffer(CFCDN)运行结束",
                                                    f"open-port-sniffer asn{asn} cfcdn",
                                                    msg_info)
    telegram_notify = notify.clean_str_for_tg(telegram_notify)
    success = notify.send_telegram_message(telegram_notify)

    if success:
        print("Finish scan message sent successfully!")
    else:
        print("Finish scan message failed to send.")


def delete_keys_containing_asn(hashmap_key, asn):
    # 获取 hashmap 中的所有 key
    all_keys = r.hkeys(hashmap_key)

    # 筛选出包含 'abc' 的 key
    keys_to_delete = [key for key in all_keys if asn in str(key)]

    # 如果有需要删除的 key
    if keys_to_delete:
        # 使用 HDEL 命令删除这些 key
        r.hdel(hashmap_key, *keys_to_delete)
        print(f"Deleted {len(keys_to_delete)} keys containing asn'{asn}'")
    else:
        print(f"No keys containing asn '{asn}' found")


# 搭配worker 展示结果
def main():
    asns = CountryASN['US']
    argv_ = sys.argv
    if len(argv_) <= 1:
        msg_info = f"CFCDN扫描开始: ASN{asns}"
        telegram_notify = notify.pretty_telegram_notify("🌞🌞Open-Port-Sniffer(CFCDN)运行开始",
                                                        f"open-port-sniffer asn{asns} cfcdn",
                                                        msg_info)
        telegram_notify = notify.clean_str_for_tg(telegram_notify)
        success = notify.send_telegram_message(telegram_notify)

        if success:
            print("Start scan message sent successfully!")
        else:
            print("Start scan message failed to send.")
        for asn in asns:
            run_task(asn)
        return
    else:
        if argv_[1] == "check":
            keys = r.hkeys('snifferx-cfcdn')
            for key in keys:
                value = r.hget('snifferx-cfcdn', key)

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
                port_open = IPChecker.check_port_open_with_retry(ip, port, 2)
                if not port_open:
                    print(f">>> 当前代理优选IP端口已失效: {ip}:{port},进行移除...")
                    print(f">>> 原始记录: {key_str}--{kv_value}")
                    r.hdel('snifferx-cfcdn', key)
                    cloudflare.remove_dns_record('A', cloudflare.hostname, ip)


if __name__ == "__main__":
    main()
