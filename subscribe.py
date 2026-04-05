import json
import yaml
import urllib.parse
from redis_tool import r

import base64


# ========================
# 工具函数
# ========================
def parse_speed(speed_str):
    try:
        return int(speed_str.split()[0])
    except:
        return 0


def num_to_char(n):
    return chr(ord('A') + n)


# ========================
# 解析 vless:// 为 Clash proxy
# ========================
def parse_vless_link(link):
    # 分割 name
    base, name = link.split("#")
    name = urllib.parse.unquote(name)

    # 去掉 vless://
    base = base.replace("vless://", "")

    # uuid@host:port
    userinfo, rest = base.split("@")
    host_port, params = rest.split("?")

    host, port = host_port.split(":")
    port = int(port)

    # 解析参数
    query = urllib.parse.parse_qs(params)

    def get(key, default=None):
        return query.get(key, [default])[0]

    proxy = {
        "name": name,
        "type": "vless",
        "server": host,
        "port": port,
        "uuid": userinfo,
        "udp": True,
        "tls": get("security") == "tls",
        "servername": get("sni"),
        "client-fingerprint": get("fp"),
        "network": get("type"),
    }

    # ws / xhttp
    if proxy["network"] in ["ws", "xhttp"]:
        proxy["ws-opts"] = {
            "path": urllib.parse.unquote(get("path", "/")),
            "headers": {
                "Host": get("sni")
            }
        }

    return proxy


# ========================
# 主流程
# ========================
def main():
    node_info_temp = 'vless://5f4638b2-cf76-4f59-92a7-bdd5ad53e010@ip:port?encryption=none&security=tls&sni=rnxhttp.256800.xyz&fp=chrome&insecure=0&allowInsecure=0&type=xhttp&path=%2F5f4638b2&mode=auto#NodeName'

    node_infos = []

    # ========= 1. 从 Redis 获取 =========
    keys = r.hkeys('snifferx-cfcdn')
    ip_pool = []

    for key in keys:
        value = r.hget('snifferx-cfcdn', key)
        if not value:
            continue

        kv_value = json.loads(value.decode('utf-8'))
        ip_pool.append(kv_value)

    if not ip_pool:
        print("❌ Redis 没数据")
        return

    # ========= 2. 排序 =========
    top5 = sorted(
        ip_pool,
        key=lambda x: parse_speed(x.get("download_speed", "0 kB/s")),
        reverse=True
    )[:5]

    # ========= 3. 生成 vless + 转 Clash =========
    for index, item in enumerate(top5):
        ip = item.get("ip")
        port = item.get("port")

        if not ip or not port:
            continue

        node_name = f"🇺🇸美国-专线{num_to_char(index)}"

        # ⚠️ 注意 replace 要重新赋值
        link = node_info_temp
        link = link.replace("ip", ip)
        link = link.replace("port", str(port))
        link = link.replace("NodeName", urllib.parse.quote(node_name))

        # 解析成 Clash 格式
        proxy = parse_vless_link(link)

        node_infos.append(proxy)

    if not node_infos:
        print("❌ 没生成节点")
        return

    # ========= 4. 读取模板 =========
    with open("logs/subscribe-temp.yaml", "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # ========= 5. 写入 proxies =========
    config["proxies"] = node_infos

    # ========= 6. 更新策略组 =========
    proxy_names = [p["name"] for p in node_infos]

    for group in config.get("proxy-groups", []):
        old = group.get("proxies", [])

        # 保留基础项
        base = [x for x in old if x in ["DIRECT", "REJECT"]]

        group["proxies"] = base + proxy_names

    # ========= 7. 输出 =========
    with open("logs/subscribe-final.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    print("✅ 生成完成 subscribe-final.yaml")
    print(f"📊 节点数: {len(node_infos)}")

    # 将生成的subscribe-final.yaml 中的内容 进行base64编码，写到subscribe-final.txt里面

    # ========= 7. 输出 =========
    output_yaml_path = "logs/subscribe-final.yaml"
    output_txt_path = "logs/subscribe-final.txt"

    with open(output_yaml_path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    print("✅ 生成完成 subscribe-final.yaml")
    print(f"📊 节点数: {len(node_infos)}")

    # 只提取节点信息 提取vless节点分享链接，以一行一行的格式的字符串 格式之后 然后编码为base64 写入文件
    # ========= 8. 提取 VLESS 链接 + Base64 =========
    try:
        vless_links = []

        for item in node_infos:
            # 重新还原成 vless:// 链接（关键）
            uuid = item["uuid"]
            server = item["server"]
            port = item["port"]
            name = urllib.parse.quote(item["name"])

            query = {
                "encryption": "none",
                "security": "tls" if item.get("tls") else "none",
                "sni": item.get("servername", ""),
                "fp": item.get("client-fingerprint", "chrome"),
                "type": item.get("network", "ws"),
            }

            # ws 参数
            if item.get("network") in ["ws", "xhttp"]:
                ws_opts = item.get("ws-opts", {})
                query["path"] = urllib.parse.quote(ws_opts.get("path", "/"))

            query_str = urllib.parse.urlencode(query)

            vless_link = f"vless://{uuid}@{server}:{port}?{query_str}#{name}"
            vless_links.append(vless_link)

        # 一行一个
        raw_text = "\n".join(vless_links)

        # base64
        encoded = base64.b64encode(raw_text.encode("utf-8")).decode("utf-8")

        with open(output_txt_path, "w", encoding="utf-8") as f:
            f.write(encoded)

        print("✅ 已生成 subscribe-final.txt（VLESS Base64）")

    except Exception as e:
        print("❌ VLESS 提取失败:", str(e))


# ========================
# 启动
# ========================
if __name__ == "__main__":
    main()
