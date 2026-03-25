import asyncio
import time

import checker

# 101.132.47.83 443
# 139.196.224.73 443
# server=="cloudflare" && header="Forbidden" && country=="CN" && city=="Hangzhou" && "https"
# server=="cloudflare" && header="Forbidden" && country=="CN" && city=="Shanghai" && "https"
# server=="cloudflare" && header="Forbidden" && country=="CN" && city=="Guangzhou" && "https"
# server=="cloudflare" && header="Forbidden" && country=="CN" && city=="Beijing" && "https"
async def main():
    # from fofa import query_proxy_ip
    # proxy_ip = query_proxy_ip(
    #     'server=="cloudflare" && header="Forbidden" && country=="CN" && city=="Hangzhou" && "https"', 50)
    # ips = proxy_ip
    #
    # for ip,port in ips:
    #     cloudflare_proxy = await checker.check_if_cf_proxy(ip, port)
    #     print(f"ip: {ip},port:{port}, cf-proxy:{cloudflare_proxy}")
    #     time.sleep(1)

    c2 = await checker.check_if_cf_proxy('47.99.152.144', 8888)
    print(f"cloudflare_proxy: {c2}")


if __name__ == '__main__':
    # clean_dead_ip()

    asyncio.run(main())
