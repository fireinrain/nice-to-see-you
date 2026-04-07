import csv
import datetime
import json
import os
import shutil
import subprocess
import sys
import time
from collections import namedtuple
from asn import get_cidr_ips
from con_checker import IPChecker
from redis_tool import r
import socket
import ssl
import tg_notify
from asn import CountryASN
import requests
import cloudflare



def check_cf_edge_fast(ip: str, port: int, retries: int = 0) -> bool:
    """
    极速探测指定的 IP:Port 是否为 Cloudflare 边缘节点。

    :param ip: 目标 IP 地址
    :param port: 目标端口 (通常为 443)
    :param retries: 失败后的重试次数 (0 表示只测 1 次)
    :return: bool (True 表示有效 CF 节点，False 表示无效或死节点)
    """
    # 默认使用的探测域名和超时时间 (极速模式)
    domain = "www.cloudflare.com"
    timeout = 2.0

    # 1. 预先构建原生的 HTTP/1.1 GET 请求报文
    request_payload = (
        f"GET /cdn-cgi/trace HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode('utf-8')

    # 2. 预先配置 TLS 选项：跳过证书校验，准备注入 SNI
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    # 执行探测，包含重试机制
    for attempt in range(retries + 1):
        sock = None
        secure_sock = None
        try:
            # 3. 建立原生 TCP 连接，并设置绝对超时
            sock = socket.create_connection((ip, port), timeout=timeout)

            # 4. 包装为 TLS 连接，并强制注入我们想要的 SNI (Server Name Indication)
            secure_sock = ssl_context.wrap_socket(sock, server_hostname=domain)

            # 5. 发送 HTTP 报文
            secure_sock.sendall(request_payload)

            # 6. 极速读取响应 (限制最多读取 10KB 防恶意堵塞)
            response_data = b""
            while True:
                chunk = secure_sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if len(response_data) > 10240:
                    break

            response_text = response_data.decode('utf-8', errors='ignore')

            # 7. 严苛校验阶段 (照妖镜)
            # 7.1 必须是 HTTP 200 OK
            if not response_text.startswith("HTTP/1.1 200") and not response_text.startswith("HTTP/1.0 200"):
                continue

            # 7.2 响应头必须包含 Cloudflare
            if "server: cloudflare" not in response_text.lower():
                continue

            # 7.3 Trace 页面正文必须包含机房代码和我们在 Payload 里写的 UA
            if "colo=" in response_text and "uag=Mozilla/5.0" in response_text:
                return True

        except Exception:
            # 任何异常（连接超时、TLS 握手被重置、读超时）都被视为无效节点
            pass
        finally:
            # 8. 绝对保证文件描述符(FD)被释放，防止多线程时句柄耗尽
            if secure_sock:
                try:
                    secure_sock.close()
                except:
                    pass
            elif sock:
                try:
                    sock.close()
                except:
                    pass

    return False


# 域名 fwd.x.klee-node-xxxus.256800.xyz

# 获取所有 CIDR 列表

# 将 CIDR 列表存入 Redis
def store_cidrs_in_redis(asn) -> []:
    cidrs = get_cidr_ips(asn)
    return cidrs


# 使用 Masscan 扫描所有 IP 的端口
def scan_ip_range(cidr, output_file, scan_ports="443"):
    cmd = ["sudo", "masscan", cidr, f"-p{scan_ports}", "--rate=20000", "--wait=3", "-oL", output_file]
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
    keys = r.hkeys('snifferx-cfcdn')
    keys_list = [str(x) for x in keys]
    key_targets = ','.join(keys_list)
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

        if ip not in key_targets:
            r.hsetnx('snifferx-cfcdn', f'{asn}:{ip}:{port}', server_info_json)
            # 添加到cf dns 记录
            try:
                cloudflare.add_dns_record('A', cloudflare.hostname, f'{ip}')
                end_msg_info = f"CF优选域名: {cloudflare.hostname},添加IP: {ip}"
                telegram_notify = tg_notify.pretty_telegram_notify("🎉🎉CFCDNHost-添加IP运行结束",
                                                                   f"add-ip-host cfcdn",
                                                                   end_msg_info)
                telegram_notify = tg_notify.clean_str_for_tg(telegram_notify)
                tg_notify.send_telegram_message(telegram_notify)
            except Exception as e:
                print(f"add dns to cloudflare error: {e},当前ip是:{ip}")

            time.sleep(2)


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
    telegram_notify = tg_notify.pretty_telegram_notify("🎉🎉Open-Port-Sniffer(CFCDN)运行结束",
                                                       f"open-port-sniffer asn{asn} cfcdn",
                                                       msg_info)
    telegram_notify = tg_notify.clean_str_for_tg(telegram_notify)
    success = tg_notify.send_telegram_message(telegram_notify)

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
        telegram_notify = tg_notify.pretty_telegram_notify(
            "🌞🌞Open-Port-Sniffer(CFCDN,用于worker访问开启CF CDN网站)运行开始",
            f"open-port-sniffer asn{asns} cfcdn",
            msg_info)
        telegram_notify = tg_notify.clean_str_for_tg(telegram_notify)
        success = tg_notify.send_telegram_message(telegram_notify)

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
                # port_open = IPChecker.check_port_open_with_retry(ip, port, 2)
                is_cf_edge = check_cf_edge_fast(ip, port, 1)
                if not is_cf_edge:
                    print(f">>> 当前代理优选IP端口已失效: {ip}:{port},进行移除...")
                    print(f">>> 原始记录: {key_str}--{kv_value}")
                    r.hdel('snifferx-cfcdn', key)
                    try:
                        cloudflare.remove_dns_record('A', cloudflare.hostname, ip)
                    except Exception as e:
                        print(f"Delete DNS record failed: {e}")



# 清理误判的ip SNI欺诈
def clean_sni_fraud_ip():
    keys = ["snifferx-cfcdn", "snifferx-final-result", "snifferx-result"]

    for k in keys:
        print(f"\n==== 处理 {k} ====")

        # 1️⃣ 获取 Redis 所有 key
        hkeys = r.hkeys(k)

        # 2️⃣ 构建映射（避免 O(n²)）
        # ip:port -> 原始key
        ip_map = {}
        ip_lines = []

        for raw in hkeys:
            key_str = raw.decode() if isinstance(raw, bytes) else str(raw)

            parts = key_str.split(":")
            if len(parts) < 3:
                continue

            ip = parts[1]
            port = parts[2]

            ip_port = f"{ip}:{port}"
            ip_map[ip_port] = raw  # 保存原始key

            ip_lines.append(f"{ip} {port}\n")

        if not ip_lines:
            print("无数据，跳过")
            continue

        # 3️⃣ 写入扫描文件（避免覆盖）
        input_file = f"{k}_aip.txt"
        output_file = f"{k}_result.csv"

        with open(input_file, "w") as f:
            f.writelines(ip_lines)

        # 4️⃣ 执行扫描（跳过测速）
        result_file = iptest_snifferx2(input_file, output_file)

        # 5️⃣ 解析扫描结果
        result_csv_ = parse_result_csv2(result_file)

        # 6️⃣ 过滤有效 IP
        clean_data = []

        for result in result_csv_:
            ip = result.get("ip")
            port = result.get("port")

            if not ip or not port:
                continue

            ip_port = f"{ip}:{port}"

            if ip_port in ip_map:
                raw_key = ip_map[ip_port]

                data = r.hget(k, raw_key)
                clean_data.append((raw_key, data))

                print(f"✔ 可用IP: {k} -> {ip_port}")

        print(f"有效数量: {len(clean_data)}")

        # 7️⃣ 清空原 hash
        if hkeys:
            r.delete(k)
            print(f"已清空 {k}")

        # 8️⃣ 写回过滤后的数据
        if clean_data:
            pipe = r.pipeline()
            for raw_key, data in clean_data:
                pipe.hset(k, raw_key, data)
            pipe.execute()

            print(f"已写回 {len(clean_data)} 条数据")

        print(f"==== 完成 {k} ====")


def iptest_snifferx2(input_file: str, output_file: str) -> str | None:
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


def parse_result_csv2(result_csv_file: str) -> []:
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
    return data


if __name__ == "__main__":
    main()
    # clean_sni_fraud_ip()
    # ==========================================
    # 使用示例：
    # ==========================================
    # test_ip = "154.17.29.62"
    # test_port = 443
    #
    # print(f"正在探测 {test_ip}:{test_port} ...")
    #
    # # 测 1 次，如果失败再重试 1 次 (总共跑 2 次)
    # is_valid = check_cf_edge_fast(test_ip, test_port, retries=1)
    #
    # if is_valid:
    #     print("✅ 这是一个有效的 Cloudflare 边缘节点！")
    # else:
    #     print("❌ 无效节点或无法连接。")
