import os
from zoomeyehk.sdk import ZoomEye

api_key = os.getenv("ZOOMEYE_API_KEY")

if __name__ == '__main__':
    zm = ZoomEye(api_key=api_key)
    info = zm.resources_info()
    print(info)
    page_search = zm.dork_search('title:"403"+country:"KR"+ssl:"cloudflare"-asn:"13335"-asn:"209242"', page=1,
                                 resource="host", facets=None)
    from zoomeyehk.sdk import show_ip_port, ZoomEye

    port = show_ip_port(page_search)

    print(port)
