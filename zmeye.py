import asyncio
import json
import os

from zoomeyeai.sdk import ZoomEye

import con_checker
import tg_notify
from redis_tool import r

api_key = os.getenv("ZOOMEYE_API_KEY")

ZoomeyeRules = {
    'KR': 'title:"403"+country:"KR"+ssl:"cloudflare"-asn:"13335"-asn:"209242"',
    'JP': 'title:"403"+country:"JP"+ssl:"cloudflare"-asn:"13335"-asn:"209242"',
    'TW': 'title:"403"+country:"TW"+ssl:"cloudflare"-asn:"13335"-asn:"209242"',
    'HK': 'title:"403"+country:"HK"+ssl:"cloudflare"-asn:"13335"-asn:"209242"',
    'MO': 'title:"403"+country:"MO"+ssl:"cloudflare"-asn:"13335"-asn:"209242"',
    'SG': 'title:"403"+country:"SG"+ssl:"cloudflare"-asn:"13335"-asn:"209242"',
    'CN': 'title:"403"+country:"CN"+ssl:"cloudflare"-asn:"13335"-asn:"209242"',
    'US': 'title:"403"+country:"US"+ssl:"cloudflare"+asn:"906"'
}
CloudServiceRules = [
    ('amazon', 'JP', 'title:"403"+country:"JP"+ssl:"cloudflare"+asn:"16509"'),
    ('amazon', 'SG', 'title:"403"+country:"SG"+ssl:"cloudflare"+asn:"16509"'),
    ('tencent', 'SG', 'title:"403"+country:"SG"+ssl:"cloudflare"+asn:"132203"'),
    ('google', 'JP', 'title:"403"+country:"JP"+ssl:"cloudflare"+asn:"396982"'),
    ('google', 'TW', 'title:"403"+country:"TW"+ssl:"cloudflare"+asn:"396982"'),

]


def get_ip_port_from_zoom(data) -> [()]:
    """
    show host search ip and port
    :param data: dict, matches data from api
    :return:
    """
    result = []
    if data:
        for i in data:
            result.append((i.get('ip'), i.get('portinfo').get('port')))
    r_set = set()
    for i in result:
        r_set.add(f"{i[0]}:{i[1]}")
    r = []
    for j in r_set:
        ip_splits = j.split(":")
        r.append((ip_splits[0], ip_splits[1]))
    return r


def get_ip_port_from_zooms(data) -> [()]:
    """
    show host search ip and port
    :param data: dict, matches data from api
    :return:
    """
    result = []
    if data:
        datas = data[0]
        for i in datas:
            result.append((i.get('ip'), i.get('portinfo').get('port')))
    r_set = set()
    for i in result:
        r_set.add(f"{i[0]}:{i[1]}")
    r = []
    for j in r_set:
        ip_splits = j.split(":")
        r.append((ip_splits[0], ip_splits[1]))
    return r


# 每页10个
def query_proxy_ip(query_rule: str, pages: int = 7) -> [()]:
    zm = ZoomEye(api_key=api_key)
    info = zm.resources_info()
    print(f"User info: {info}")
    page_search = zm.multi_page_search(query_rule, page=pages,
                                 resource="host", facets=None)

    return get_ip_port_from_zooms(page_search)


def store_proxy_ip2redis(iptests, region: str):
    # 除了US 906 之外的us ip 都不需要
    dont_need_dc = ['North America', 'Europe']

    for server in iptests:
        ip = server["ip"]
        port = server["port"]
        loc = server["region"]

        if server["download_speed"] == '0.00 kB/s' or (loc in dont_need_dc and region != 'US'):
            continue
        server_info_json = json.dumps(server)

        r.hsetnx("snifferx-result", f"zoom-{region.lower()}:{ip}:{port}", server_info_json)


async def main():
    # zoom现在不支持普通注册用户调用api了
    return
    # 发送TG消息开始
    msg_info = f"Zoom查找: zoom: {len(ZoomeyeRules)}"
    telegram_notify = tg_notify.pretty_telegram_notify("👁️👁️Zoom-Find-Proxy运行开始",
                                                    f"zoom-find-proxy zoom",
                                                    msg_info)
    telegram_notify = tg_notify.clean_str_for_tg(telegram_notify)
    success = tg_notify.send_telegram_message(telegram_notify)

    if success:
        print("Start zoom message sent successfully!")
    else:
        print("Start zoom message failed to send.")

    # mix in cloudservice rule to zoom-query rule
    zoom_static = {}
    has_test_ip_set = set()
    # process cloud service rule
    for cloud_rule in CloudServiceRules:
        print(f"find rule: {cloud_rule}")
        rule = cloud_rule[2]
        region = cloud_rule[1]
        proxy_ips = query_proxy_ip(rule)
        proxy_ip_list = []
        for proxy_ip in proxy_ips:
            has_test_ip_set.add(proxy_ip)
            check_info = await con_checker.check_if_cf_proxy(proxy_ip[0], proxy_ip[1])
            if check_info[0]:
                print(f"ip: {proxy_ip[0]},port:{proxy_ip[1]}, cf-proxy:{check_info}")
                proxy_ip_list.append(check_info[1])
        zoom_static[region] = len(proxy_ip_list)
        store_proxy_ip2redis(proxy_ip_list, region)
        print("--------------------------------")
        await asyncio.sleep(30)

    for region, rule in ZoomeyeRules.items():
        print(f"find rule: {rule}")
        proxy_ips = query_proxy_ip(rule)
        proxy_ip_list = []
        for proxy_ip in proxy_ips:
            if proxy_ip in has_test_ip_set:
                print(f"当前IP: {proxy_ip}已经在CLoudServiceRule测试过...")
                continue
            check_info = await con_checker.check_if_cf_proxy(proxy_ip[0], proxy_ip[1])
            if check_info[0]:
                print(f"ip: {proxy_ip[0]},port:{proxy_ip[1]}, cf-proxy:{check_info}")
                proxy_ip_list.append(check_info[1])
        zoom_static[region] = len(proxy_ip_list)
        store_proxy_ip2redis(proxy_ip_list, region)
        print("--------------------------------")
        await asyncio.sleep(30)

    end_msg_info = f"统计信息: {zoom_static}"
    telegram_notify = tg_notify.pretty_telegram_notify("🎉🎉Zoom-Find-Proxy运行结束",
                                                    f"zoom-find-proxy zoom",
                                                    end_msg_info)
    telegram_notify = tg_notify.clean_str_for_tg(telegram_notify)
    success = tg_notify.send_telegram_message(telegram_notify)

    if success:
        print("Start zoom find message sent successfully!")
    else:
        print("Start zoom find message failed to send.")


if __name__ == '__main__':
    asyncio.run(main())
