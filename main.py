import csv
import datetime
import json
import os
import random
import shutil
import subprocess
import sys
import time
import uuid
from collections import namedtuple
from asn import get_cidr_ips
from redis_tool import r
import pytz

import tg_notify
from asn import Wanted_ASN, ASN_Map
import redis
import requests

from log import logger


def acquire_lock_with_timeout(redis_client, lock_name, acquire_timeout=60 * 60, lock_timeout=60 * 60):
    identifier = str(uuid.uuid4())
    end = time.time() + acquire_timeout
    while time.time() < end:
        if redis_client.set(lock_name, identifier, nx=True, ex=lock_timeout):
            return identifier
        time.sleep(0.001)
    return False


def release_lock(redis_client, lock_name, identifier):
    while True:
        try:
            with redis_client.pipeline() as pipe:
                pipe.watch(lock_name)
                lock_value = redis_client.get(lock_name)
                if lock_value and lock_value.decode('utf-8') == identifier:
                    pipe.multi()
                    pipe.delete(lock_name)
                    pipe.execute()
                    return True
                pipe.unwatch()
                break
        except redis.WatchError:
            continue
    return False


# 获取所有 CIDR 列表

# 将 CIDR 列表存入 Redis
def store_cidrs_in_redis(asn, batch_ip_size):
    cidrs = get_cidr_ips(asn)

    def ip_count(cidr):
        ip, mask = cidr.split('/')
        mask = int(mask)
        return 2 ** (32 - mask) if mask < 32 else 1

    total_ips = sum(ip_count(cidr) for cidr in cidrs)

    if total_ips <= batch_ip_size:
        r.rpush(f"cidr_batches:{asn}", json.dumps(cidrs))
    else:
        batches = []
        current_batch = []
        current_batch_ip_count = 0
        for cidr in cidrs:
            cidr_ip_count = ip_count(cidr)
            if current_batch_ip_count + cidr_ip_count > batch_ip_size and current_batch:
                batches.append(current_batch)
                current_batch = []
                current_batch_ip_count = 0
            current_batch.append(cidr)
            current_batch_ip_count += cidr_ip_count

        if current_batch:
            batches.append(current_batch)

        # 如果批次数量大于 10，均匀分成十份
        if len(batches) > 10:
            total_cidrs = [cidr for batch in batches for cidr in batch]
            chunk_size = len(total_cidrs) // 10
            batches = [total_cidrs[i * chunk_size: (i + 1) * chunk_size] for i in range(10)]
            if len(total_cidrs) % 10 != 0:
                for i in range(len(total_cidrs) % 10):
                    batches[i].append(total_cidrs[-(i + 1)])

        for batch in batches:
            r.rpush(f"cidr_batches:{asn}", json.dumps(batch))


def ip_count(cidr):
    ip, mask = cidr.split('/')
    mask = int(mask)
    return 2 ** (32 - mask) if mask < 32 else 1


def split_large_batches(batches, batch_ip_size):
    new_batches = []
    for batch in batches:
        if len(new_batches) >= 10:
            new_batches.append(batch)
            continue
        current_batch = []
        current_batch_ip_count = 0
        for cidr in batch:
            cidr_ip_count = ip_count(cidr)
            if current_batch_ip_count + cidr_ip_count > batch_ip_size and current_batch:
                new_batches.append(current_batch)
                current_batch = []
                current_batch_ip_count = 0
                if len(new_batches) >= 10:
                    break
            current_batch.append(cidr)
            current_batch_ip_count += cidr_ip_count
        if current_batch:
            new_batches.append(current_batch)
        if len(new_batches) >= 10:
            break
    return new_batches


# 获取 CIDR 批次
def get_cidr_batch(asn):
    cidr_batch = r.lpop(f"cidr_batches:{asn}")
    if cidr_batch:
        return json.loads(cidr_batch)
    return []


def get_masscan_path():
    # 首先尝试 shutil.which
    masscan_path = shutil.which('masscan')
    if masscan_path:
        return masscan_path

    # 常见的安装位置
    common_paths = [
        '/usr/bin/masscan',
        '/usr/local/bin/masscan',
        '/usr/sbin/masscan',
        '/usr/local/sbin/masscan'
    ]

    # 检查常见位置
    for path in common_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    # 最后尝试 which 命令
    try:
        result = subprocess.run(['which', 'masscan'],
                                check=True,
                                capture_output=True,
                                text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        pass

    raise FileNotFoundError("Could not find masscan executable")


# 使用 Masscan 扫描所有 IP 的端口
def scan_ip_range(cidr, output_file, scan_ports="443"):
    cmd = ["sudo", "masscan", cidr, f"-p{scan_ports}", "--rate=20000", "--wait=3", "-oL", output_file]
    print(f"Executing command: {' '.join(cmd)}")
    try:
        masscan_path = get_masscan_path()
        print(f"masscan 所在目录: {masscan_path}")
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


# 将端口统计结果存储到 Redis
# def store_ip_port_result_in_redis(asn, iptests:[]):
#     lock_name = f"lock:snifferx-result:{asn}"
#     identifier = acquire_lock_with_timeout(r, lock_name)
#
#     if identifier:
#         try:
#             for server in iptests:
#                 ip = server['ip']
#                 port = server['port']
#                 server_info_json = json.dumps(server)
#                 r.hsetnx('snifferx-result', f'{asn}:{ip}:{port}', server_info_json)
#         finally:
#             release_lock(r, lock_name, identifier)
#     else:
#         print("Failed to acquire lock for updating port_counts")


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

        r.hsetnx('snifferx-result', f'{asn}:{ip}:{port}', server_info_json)


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
    while True:
        batch = get_cidr_batch(asn)
        if not batch:
            break
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

        time.sleep(3)  # 等待一会儿再获取下一个批次

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
            if row[7] == '0 kB/s':
                row[7] = '0.00 kB/s'
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
    return data if len(data) < 10 else data[:10]


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


def clean_duplicate_redis_data(asn: str):
    clean_key = f"clean_lock:{asn}"
    initialized_key = f"task_initialized:{asn}"
    exists = r.exists(initialized_key)
    if exists:
        return
        # 使用 Redis 的原子操作 set 配合 NX 选项
    if r.set(clean_key, "1", nx=True):
        try:
            keys_to_delete = r.keys(f'*{asn}*')

            # 删除这些键
            if keys_to_delete:
                r.delete(*keys_to_delete)
        except Exception as e:
            # 如果初始化过程中出现错误，删除标记键以允许重试
            r.delete(clean_key)
    else:
        print(f"Redis数据已被其他服务器清理 {asn}")


def initialize_task(asn, batch_ip_size):
    initialized_key = f"task_initialized:{asn}"

    # 使用 Redis 的原子操作 set 配合 NX 选项
    if r.set(initialized_key, "1", nx=True):
        try:
            store_cidrs_in_redis(asn, batch_ip_size)
            print(f"Task initialized for ASN {asn}")
        except Exception as e:
            # 如果初始化过程中出现错误，删除标记键以允许重试
            r.delete(initialized_key)
            print(f"Error initializing task for ASN {asn}: {e}")
            raise
    else:
        print(f"Task already initialized for ASN {asn}")


def mark_task_completed(asn, num_instances):
    lock_name = f"completion_lock:{asn}"
    identifier = acquire_lock_with_timeout(r, lock_name)
    if identifier:
        try:
            completed_key = f"completed_instances:{asn}"
            completed_instances = int(r.get(completed_key) or 0)
            if completed_instances < num_instances:
                r.incr(completed_key)
                logger.info("任务已完成...")
            else:
                logger.info("所有实例已经完成任务，不需要再增加计数")
        finally:
            release_lock(r, lock_name, identifier)


def is_task_completed(asn, num_instances):
    lock_name = f"lock:task_check:{asn}"
    identifier = acquire_lock_with_timeout(r, lock_name, acquire_timeout=10, lock_timeout=10)

    if not identifier:
        logger.warning(f"Failed to acquire lock for task check for ASN {asn}")
        return False

    try:
        completed_key = f"completed_instances:{asn}"
        completed_instances = int(r.get(completed_key) or 0)
        logger.info(f"Task completed: {completed_instances} instances")
        return completed_instances >= num_instances
    finally:
        release_lock(r, lock_name, identifier)


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


def run_find_task(asn_number: str):
    asn = asn_number
    clean_duplicate_redis_data(asn)
    # scan_ports = (
    #     '443,1443,2443,3443,4443,5443,6443,7443,8443,9443,'
    #     '10443,11443,12443,13443,14443,15443,16443,17443,18443,19443,'
    #     '20443,21443,22443,23443,24443,25443,26443,27443,28443,29443,'
    #     '30443,31443,32443,33443,34443,35443,36443,37443,38443,39443,'
    #     '40443,41443,42443,43443,44443,45443,46443,47443,48443,49443,'
    #     '50443,51443,52443,53443,54443,55443,56443,57443,58443,59443,'
    #     '60443,61443,62443,63443,64443,65443,23555')

    scan_ports = '443,2053,2083,2087,2096,8443,9443,23555'
    batch_ip_size = 100000  # Example batch size

    # 初始化任务，只需执行一次
    initialize_task(asn, batch_ip_size)

    # 等待十秒
    time.sleep(random.randint(1, 10))

    scan_and_store_results(asn, scan_ports)

    # 检查是否所有实例都完成任务
    num_instances = 10  # 假设有十台机器
    # 标记任务完成
    mark_task_completed(asn, num_instances)

    while True:
        if is_task_completed(asn, num_instances):
            # 如果是最后一台完成的机器，则生成图表和刷新 Markdown
            if r.incr(f"last_instance:{asn}") == 1:
                result_counts = count_fields_containing_asn("snifferx-result", asn)
                msg_info = f"扫描结束: ASN{asn},结果数量: {result_counts}"
                telegram_notify = tg_notify.pretty_telegram_notify("🎉🎉Open-Port-Sniffer运行结束",
                                                                   f"open-port-sniffer asn{asn}",
                                                                   msg_info)
                telegram_notify = tg_notify.clean_str_for_tg(telegram_notify)
                success = tg_notify.send_telegram_message(telegram_notify)

                if success:
                    print("Finish scan message sent successfully!")
                else:
                    print("Finish scan message failed to send.")
            break
        logger.info(f"等待其他节点完成任务(睡眠10s)...")
        time.sleep(10)


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


def get_current_weekday():
    # 获取当前日期和时间
    current_date = datetime.datetime.now()

    # 获取当前是星期几（0是周一，6是周日）
    weekday = current_date.weekday()

    # 如果是周日（原本返回6），我们保持不变
    # 其他天数保持不变（周一是0，周二是1，以此类推）
    return weekday


# 修改为默认美国东部时间
def get_current_weekday_plus():
    # Define the US Eastern time zone
    eastern = pytz.timezone('US/Eastern')

    # Get the current time in the US Eastern time zone
    now = datetime.datetime.now(eastern)
    current_time = now.time()
    current_day = now.weekday()  # Monday is 0, Sunday is 6

    # Define time ranges
    morning_start = datetime.datetime.strptime("00:01", "%H:%M").time()
    morning_end = datetime.datetime.strptime("11:59", "%H:%M").time()
    afternoon_start = datetime.datetime.strptime("12:00", "%H:%M").time()
    afternoon_end = datetime.datetime.strptime("23:59", "%H:%M").time()

    # Check each day and time range
    for day in range(7):  # 0 to 6, representing Monday to Sunday
        if current_day == day:
            if morning_start <= current_time < morning_end:
                return day * 2
            elif afternoon_start <= current_time < afternoon_end:
                return day * 2 + 1

    # If not in any specified range, return -1 or handle as needed
    return 0


def cleanup_old_asn_data(asn: str):
    keys_to_delete = r.keys(f'*{asn}*')
    # 删除这些键
    if keys_to_delete:
        r.delete(*keys_to_delete)
    # 移除snifferx-result hashmap中特有的asn 扫描结果
    delete_keys_containing_asn("snifferx-result", asn)
    print(f"清理上次运行asn数据成功...")
    # 发送TG消息开始
    msg_info = f"开始扫描: ASN{asn},IPv4规模: {ASN_Map.get(asn).split(',')[1]}"
    telegram_notify = tg_notify.pretty_telegram_notify("🔎🔎Open-Port-Sniffer运行开始",
                                                       f"open-port-sniffer asn{asn}",
                                                       msg_info)
    telegram_notify = tg_notify.clean_str_for_tg(telegram_notify)
    success = tg_notify.send_telegram_message(telegram_notify)

    if success:
        print("Start scan message sent successfully!")
    else:
        print("Start scan message failed to send.")


# 搭配worker 展示结果
def main():
    # 如果ip数量大于200个 则跳过执行
    keys = r.hkeys('snifferx-final-result')
    if len(keys) >= 256:
        raise Exception("当前反代IP数量充足，暂不需要扫描")
    weekday = get_current_weekday_plus()
    asn = Wanted_ASN[weekday]
    argv_ = sys.argv
    if len(argv_) <= 1:
        if ',' in asn:
            asn_split = asn.split(",")
            for asn_number in asn_split:
                run_find_task(asn_number)
        else:
            run_find_task(asn)
    else:
        if argv_[1] == "clean":
            if ',' in asn:
                asns = asn.split(",")
                for asn in asns:
                    cleanup_old_asn_data(asn)
            else:
                cleanup_old_asn_data(asn)


if __name__ == "__main__":
    main()
