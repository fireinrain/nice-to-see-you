import os
import time
import json
import math
import urllib.request

def fetch_and_parse_apnic(target_regions):
    url = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"
    print(f"正在从 APNIC 下载最新 IP 数据...\n{url}")

    # 初始化结果字典
    results = {region: {'ipv4': [], 'ipv6': []} for region in target_regions}

    # 获取并读取数据
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as response:
        lines = response.read().decode('utf-8').splitlines()

    print("数据下载完成，正在解析...")

    for line in lines:
        # 跳过注释和空行
        if line.startswith('#') or not line.strip():
            continue

        parts = line.split('|')
        # 确保行格式正确 (apnic|CC|type|start|value|date|status)
        if len(parts) < 7:
            continue

        registry, cc, ip_type, start_ip, value, date, status = parts[:7]

        # 只提取目标地区，并且状态为已分配(allocated)或已指派(assigned)的IP
        if cc in target_regions and status in ('allocated', 'assigned'):
            if ip_type == 'ipv4':
                # IPv4 的 value 是包含的 IP 总数
                ip_count = int(value)
                # 计算子网掩码前缀：32 - log2(IP数量)
                prefix_length = 32 - int(math.log2(ip_count))
                cidr = f"{start_ip}/{prefix_length}"
                results[cc]['ipv4'].append(cidr)

            elif ip_type == 'ipv6':
                # IPv6 的 value 直接就是前缀长度
                prefix_length = int(value)
                cidr = f"{start_ip}/{prefix_length}"
                results[cc]['ipv6'].append(cidr)

    return results


def save_to_files(results, output_dir="asia_ip_lists"):
    # 获取当前日期

    # 创建输出目录
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for region, types in results.items():
        for ip_type, cidr_list in types.items():
            if not cidr_list:
                continue

            filename = os.path.join(output_dir, f"{region.lower()}_{ip_type}.txt")
            with open(filename, 'w', encoding='utf-8') as f:
                f.write('\n'.join(cidr_list))
            print(f"已保存: {filename} (共 {len(cidr_list)} 条)")





class ASIACIDR:
    def __init__(self, cache_file='asia_ipv4_cidr.json', expire_days=30):
        """
        初始化 ASIACIDR 类
        :param cache_file: 本地缓存文件的路径
        :param expire_days: 缓存过期时间（天）
        """
        self.cache_file = cache_file
        self.expire_seconds = expire_days * 24 * 60 * 60
        # 默认关注的亚太地区代码
        self.target_regions = ['HK', 'SG', 'TW', 'KR', 'JP', 'MO']
        self.apnic_url = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"

        # 存放最终的 CIDR 数据，格式：{"HK": ["1.1.1.0/24", ...], ...}
        self.cidr_data = {}

        # 初始化时尝试加载或更新数据
        self._prepare_data()

    def _prepare_data(self):
        """检查缓存是否有效，无效则重新下载，有效则直接读取"""
        if self._is_cache_valid():
            print(f"[*] 发现本地有效缓存 ({self.cache_file})，正在读取...")
            self._load_from_cache()
        else:
            print(f"[*] 本地缓存不存在或已超过设定的过期时间，准备重新下载数据...")
            self._download_and_update()

    def _is_cache_valid(self):
        """判断本地缓存文件是否存在且未过期"""
        if not os.path.exists(self.cache_file):
            return False

        file_mtime = os.path.getmtime(self.cache_file)
        current_time = time.time()

        # 如果当前时间减去文件最后修改时间大于设定的过期秒数，则认为失效
        if (current_time - file_mtime) > self.expire_seconds:
            return False

        return True

    def _load_from_cache(self):
        """从本地 JSON 文件加载数据"""
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                self.cidr_data = json.load(f)
        except Exception as e:
            print(f"[!] 读取缓存失败: {e}，将尝试重新下载。")
            self._download_and_update()

    def _download_and_update(self):
        """从 APNIC 下载最新数据，解析为 CIDR，并覆盖本地缓存"""
        print(f"[*] 正在从 {self.apnic_url} 下载最新 IP 数据，请稍候...")

        # 初始化临时字典
        temp_data = {region: [] for region in self.target_regions}

        try:
            req = urllib.request.Request(self.apnic_url)
            with urllib.request.urlopen(req) as response:
                lines = response.read().decode('utf-8').splitlines()

            for line in lines:
                if line.startswith('#') or not line.strip():
                    continue

                parts = line.split('|')
                if len(parts) < 7:
                    continue

                registry, cc, ip_type, start_ip, value, date, status = parts[:7]

                # 只处理目标地区、IPv4 且状态为 allocated/assigned 的数据
                if cc in self.target_regions and ip_type == 'ipv4' and status in ('allocated', 'assigned'):
                    ip_count = int(value)
                    # 将 IP 数量转换为 CIDR 前缀长度：32 - log2(IP数量)
                    prefix_length = 32 - int(math.log2(ip_count))
                    cidr = f"{start_ip}/{prefix_length}"
                    temp_data[cc].append(cidr)

            self.cidr_data = temp_data

            # 将解析后的数据写入本地缓存文件
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cidr_data, f, indent=4)
            print(f"[*] 数据下载并解析完成，已更新本地缓存: {self.cache_file}")

        except Exception as e:
            print(f"[!] 下载或解析数据时发生错误: {e}")
            if not self.cidr_data:
                raise RuntimeError("无法获取 IP 数据且无可用缓存，程序中止。")

    def get_region_ipv4(self, region):
        """
        获取特定地区的 IPv4 CIDR 列表
        :param region: 国家/地区代码，如 'HK', 'SG'
        :return: 包含该地区所有 IPv4 CIDR 的列表
        """
        region_upper = region.upper()
        if region_upper not in self.cidr_data:
            print(f"[!] 警告：未找到地区 {region_upper} 的数据。支持的地区有: {', '.join(self.target_regions)}")
            return []
        return self.cidr_data[region_upper]

    def get_all_ipv4(self):
        """
        获取所有受支持地区的 IPv4 CIDR 列表
        :return: 包含所有目标地区 IPv4 CIDR 的一维列表
        """
        all_cidrs = []
        for region_cidrs in self.cidr_data.values():
            all_cidrs.extend(region_cidrs)
        return all_cidrs


# ==========================================
# 使用示例
# ==========================================
if __name__ == "__main__":
    # 初始化类，默认缓存文件为 asia_ipv4_cidr.json，过期时间 30 天
    asia_cidr = ASIACIDR(cache_file='asia_ipv4_cidr.json', expire_days=30)

    # 1. 获取特定地区的 CIDR (例如香港)
    hk_ips = asia_cidr.get_region_ipv4('HK')
    print(f"\n[+] 香港 (HK) 的 IPv4 网段数量: {len(hk_ips)}")
    print(f"    前 5 个网段示例: {hk_ips[:5]}")

    # 2. 获取所有地区的 CIDR
    all_ips = asia_cidr.get_all_ipv4()
    print(f"\n[+] 亚太 5 区 (HK, SG, TW, KR, JP,MO) 总 IPv4 网段数量: {len(all_ips)}")


    # # 需要获取的国家/地区代码 (ISO 3166-1 alpha-2 格式)
    # target_regions = ['HK', 'SG', 'TW', 'KR', 'JP', 'MO']
    #
    # # 抓取并解析
    # parsed_data = fetch_and_parse_apnic(target_regions)
    #
    # # 写入到当前目录下的 ip_lists 文件夹中
    # save_to_files(parsed_data)
    #
    # print("\n所有操作执行完毕！")