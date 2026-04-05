import json
import yaml
import base64
import urllib.parse
from typing import List, Dict, Callable
from redis_tool import r


# ========================
# 工具函数
# ========================
def parse_speed(speed_str: str) -> int:
    try:
        return int(speed_str.split()[0])
    except:
        return 0


def num_to_char(n: int) -> str:
    return chr(ord('A') + n)


def safe_get(d: dict, key: str, default=None):
    return d.get(key, default)


# ========================
# Redis 数据获取（只一次）
# ========================
def fetch_ip_pool(redis_key: str = "snifferx-cfcdn") -> List[dict]:
    keys = r.hkeys(redis_key)
    pool = []

    for key in keys:
        value = r.hget(redis_key, key)
        if not value:
            continue
        pool.append(json.loads(value.decode("utf-8")))

    return pool


# ========================
# 节点排序 + topN
# ========================
def select_top_nodes(pool: List[dict], top_n: int) -> List[dict]:
    return sorted(
        pool,
        key=lambda x: parse_speed(x.get("download_speed", "0 kB/s")),
        reverse=True
    )[:top_n]


# ========================
# Template System
# ========================
class NodeTemplate:
    def __init__(self, name_prefix: str, protocol: str, template: str):
        self.name_prefix = name_prefix
        self.protocol = protocol
        self.template = template

    def render(self, ip: str, port: str, index: int) -> str:
        node_name = f"{self.name_prefix}{num_to_char(index)}"
        return self.template.replace("ip", ip) \
                            .replace("port", str(port)) \
                            .replace("NodeName", urllib.parse.quote(node_name))


# ========================
# 支持多协议解析器注册
# ========================
class ProxyParser:
    registry: Dict[str, Callable] = {}

    @classmethod
    def register(cls, protocol: str):
        def wrapper(func):
            cls.registry[protocol] = func
            return func
        return wrapper

    @classmethod
    def parse(cls, protocol: str, link: str):
        if protocol not in cls.registry:
            raise Exception(f"Unsupported protocol: {protocol}")
        return cls.registry[protocol](link)


# ========================
# VLESS parser
# ========================
@ProxyParser.register("vless")
def parse_vless(link: str) -> dict:
    base, name = link.split("#")
    name = urllib.parse.unquote(name)

    base = base.replace("vless://", "")
    userinfo, rest = base.split("@")
    host_port, params = rest.split("?")

    host, port = host_port.split(":")
    query = urllib.parse.parse_qs(params)

    def get(k, default=None):
        return query.get(k, [default])[0]

    proxy = {
        "name": name,
        "type": "vless",
        "server": host,
        "port": int(port),
        "uuid": userinfo,
        "udp": True,
        "tls": get("security") == "tls",
        "servername": get("sni"),
        "client-fingerprint": get("fp"),
        "network": get("type"),
    }

    if proxy["network"] in ["ws", "xhttp"]:
        proxy["ws-opts"] = {
            "path": urllib.parse.unquote(get("path", "/")),
            "headers": {"Host": get("sni")}
        }

    return proxy


# ========================
# VMESS parser（示例，可扩展）
# ========================
@ProxyParser.register("vmess")
def parse_vmess(link: str) -> dict:
    raw = link.replace("vmess://", "")
    decoded = base64.b64decode(raw).decode("utf-8")
    data = json.loads(decoded)

    return {
        "name": data.get("ps"),
        "type": "vmess",
        "server": data.get("add"),
        "port": int(data.get("port")),
        "uuid": data.get("id"),
        "alterId": data.get("aid", 0),
        "network": data.get("net"),
        "tls": data.get("tls") == "tls",
    }


# ========================
# VLESS link generator
# ========================
def build_vless_link(item: dict) -> str:
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

    if item.get("network") in ["ws", "xhttp"]:
        ws = item.get("ws-opts", {})
        query["path"] = urllib.parse.quote(ws.get("path", "/"))

    return f"vless://{uuid}@{server}:{port}?{urllib.parse.urlencode(query)}#{name}"


# ========================
# 主流程
# ========================
def main():
    # ===== 可配置参数 =====
    TOP_N = 5

    templates = [
        NodeTemplate("🇺🇸美国-X专线", "vless", "vless://5f4638b2-cf76-4f59-92a7-bdd5ad53e010@ip:port?encryption=none&security=tls&sni=rnws.256800.xyz&fp=chrome&insecure=0&allowInsecure=0&type=xhttp&path=%2Feb8098&mode=auto#NodeName"),
        # 未来可以直接加：
        # NodeTemplate("🇭🇰香港-节点", "vmess", "vmess://xxxxx"),
        NodeTemplate("🇺🇸美国-W专线", "vless",
                     "vless://5f4638b2-cf76-4f59-92a7-bdd5ad53e010@ip:port?encryption=none&security=tls&sni=rnxhttp.256800.xyz&fp=chrome&insecure=0&allowInsecure=0&type=ws&path=%2F5f4638b2#NodeName"),

    ]

    # ===== 1. Redis 获取（一次）=====
    pool = fetch_ip_pool()
    if not pool:
        print("❌ Redis 没数据")
        return

    # ===== 2. 排序取 topN =====
    top_nodes = select_top_nodes(pool, TOP_N)

    all_proxies = []
    all_links = []

    # ===== 3. 多模板生成 =====
    for tpl in templates:
        for i, item in enumerate(top_nodes):
            ip = safe_get(item, "ip")
            port = safe_get(item, "port")

            if not ip or not port:
                continue

            link = tpl.render(ip, port, i)
            proxy = ProxyParser.parse(tpl.protocol, link)

            all_proxies.append(proxy)

            # 统一生成 vless/vmess link（txt用）
            if tpl.protocol == "vless":
                all_links.append(build_vless_link(proxy))

    if not all_proxies:
        print("❌ 没生成节点")
        return

    # ===== 4. 读取 YAML 模板 =====
    with open("logs/subscribe-temp.yaml", "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    config["proxies"] = all_proxies

    # ===== 5. 更新 proxy-groups =====
    proxy_names = [p["name"] for p in all_proxies]

    for group in config.get("proxy-groups", []):
        base = [x for x in group.get("proxies", []) if x in ["DIRECT", "REJECT"]]
        group["proxies"] = base + proxy_names

    # ===== 6. 写 YAML =====
    yaml_path = "logs/subscribe-final.yaml"
    with open(yaml_path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    # ===== 7. 写 Base64 TXT =====
    raw_text = "\n".join(all_links)
    encoded = base64.b64encode(raw_text.encode("utf-8")).decode("utf-8")

    txt_path = "logs/subscribe-final.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(encoded)

    print("✅ 完成生成")
    print(f"📊 节点数: {len(all_proxies)}")
    print(f"📦 YAML: {yaml_path}")
    print(f"📦 TXT: {txt_path}")


# ========================
# 启动
# ========================
if __name__ == "__main__":
    main()