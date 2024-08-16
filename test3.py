import aiohttp
import asyncio
import time
import socket

from aiohttp import ClientTimeout, TCPConnector, ClientSession


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


async def cf_speed_download(ip: str, port: int) -> float:
    url_string = f"https://speed.cloudflare.com/__down?bytes={1024 * 1024 * 1024}"
    url = url_string
    timeout = ClientTimeout(total=60)

    resolver = CustomResolver(ip, port)
    connector = TCPConnector(resolver=resolver)

    async with ClientSession(connector=connector, timeout=timeout) as session:
        try:
            async with session.get(url) as response:
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

                print("data_len: ", data_len)
                print("elapsed_time: ", elapsed_time)
                if elapsed_time - 5.0 < 0:
                    return 0.00
                return data_len / elapsed_time
        except Exception as e:
            print(f"An error occurred: {e}")
            return 0.00


async def main():
    result = await cf_speed_download('8.210.21.65', 443)
    print(f"下载速度: {result:.2f} 字节/秒")
    # 8.217.64.226
    result = await cf_speed_download('8.217.64.226', 443)
    print(f"下载速度2: {result:.2f} 字节/秒")


# Example usage:
# asyncio.run(download('93.184.216.34', 443))
if __name__ == '__main__':
    asyncio.run(main())
