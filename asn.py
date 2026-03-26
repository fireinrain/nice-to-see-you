import json
import os
import time
import re
import requests

from country_cidr import ASIACIDR

ASN_Map = {
    "932": "AS932 XNNET LLC,16128",
    "15169": "AS15169 Google LLC,9134336",
    "17858": "AS17858 LG POWERCOMM,10301440",
    "45102": "AS45102 Alibaba (US) Technology Co.Ltd.,3347200",
    "135377": "AS135377 UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED,158976",
    "19527": "AS19527 Google LLC,1952768",
    "2497": "AS2497 Internet Initiative Japan Inc,3928576",
    "31898": "AS31898 Oracle Corporation,3044608",
    "3462": "AS3462 Data Communication Business Group HINET,12237056",
    "396982": "AS396982 Google LLC GOOGLE-CLOUD-PLATFORM,14720256",
    "4609": "AS4609 Companhia de Telecomunicacoes de Macau SARL CTM-MO,265216",
    "4760": "AS4760 HKT Limited,1831936",
    "8075": "AS8075 Microsoft Corporation,58105088",
    "906": "AS906 DMIT Cloud Services,30208",
    "9312": "AS9312 xTom,20224",
    "9689": "AS9689 SK Broadband Co Ltd,291840",
    "4785": "AS4785 xTom,13568",
    "2914": "AS2914 NTT America Inc,7000832",
    "3258": "AS3258 xTom Japan,22016",
    "4713": "AS4713 NTT Communications Corporation Japan,28692736",
    "16625": "AS16625 Akamai Technologies,5514240",
    "21859": "AS21859 Zenlayer Inc,649728",
    "17511": "AS17511 OPTAGE Inc,3059200",
    "25820": "AS25820 IT7 Networks Inc,392448",
    "132203": "AS132203 Tencent Building Kejizhongyi Avenue,1827072",
    "4809": "AS4809 China Telecom CN2,615936",
    "7679": "AS7679 QTnet Inc,696320",
    "40065": "AS40065 CNSERVERS LLC,480512",
    "138915": "AS138915 Kaopu Cloud HK Limited,171008",
    "18450": "AS18450 WebNX Inc,99840",
    # oneman 商家
    "36002": "GoMami Networks (NHL-157),2048",
    "49304": "SAKURA LINK LIMITED,17920",
    "8143": "Neburst LLC·neburst.com,1536",
    "140096": "花卷jinx.cloud,4864",
    "400618": "primesecuritycorp.com,12032",
    "153517": "Ju Link Tech Limited rfchost,512",
    "3491": "PCCW Global Inc,1158144",
    "209554": "	isif.net ou,1536",
    "154162": "ISIF LIMITED HK,256",
    "7720": "Skywolf Technology LLC,768",
    "967": "VMISS Inc. ca,13824",
    "400464": "VMISS Inc. vmiss.com,6144",
    "41378": "Kirino LLC,15616",
    "929": "KIRINO LLC,3072",
    "60024": "HK CEDOC LIMITED,4608",
    "210110": "Kvmcloud Network CO LIMITED,768",
    "396856": "Sharon Networks LLC,3840",
    "6233": "xTom US,7168",
    # fake asn for country cidr
    "SG_CIDR": "SG_CIDR,27497572",
    "HK_CIDR": "HK_CIDR,23313807",
    "TW_CIDR": "TW_CIDR,37702651",
    "MO_CIDR": "MO_CIDR,374804",
    "JP_CIDR": "JP_CIDR,199507581",
    "KR_CIDR": "KR_CIDR,116394093",

}
# 每天运行2个，凌晨一个 中午一个
Wanted_ASN = ['906,40065,932,7679', '4760,3258,18450,SG_CIDR', '31898,9689,9312', '135377,9312,HK_CIDR', '3462',
              '4609,TW_CIDR', '25820,138915',
              '17511,2497,MO_CIDR', '4785,19527', '15169,JP_CIDR', '21859', '4809,17858,KR_CIDR', '45102',
              '132203,36002,49304,8143,140096,400618,153517,3491,209554,154162,7720,967,400464,41378,929,60024,210110,396856,6233']

CountryASN = {
    'HK': ['4515', '9269', '4760', '9304', '10103', '17444', '9381', '135377'],
    'MO': ['4609', '7582', '64061', '133613'],
    'SG': ['45102', '139070', '139190'],
    'TW': ['4609'],
    'KR': ['31898', '9689'],
    'JP': ['2497', '7679'],
    'US': ['906']
}


def fetch_cidrs(asn: str) -> list:
    url = f"https://asntool.com/{asn}"

    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        print(f"request error: {e}")
        return []

    text = resp.text

    # 匹配 CIDR（IPv4）
    cidr_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b"
    cidrs = re.findall(cidr_pattern, text)

    # 去重 + 排序
    cidrs = sorted(set(cidrs))

    return cidrs


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
        if asn.endswith("CIDR"):
            asia_cidr = ASIACIDR(cache_file='asia_ipv4_cidr.json', expire_days=30)
            region = asn.split("_")[0]
            region_ipv4_cidrs = asia_cidr.get_region_ipv4(region)
            with open(file_path, 'w') as file:
                json.dump(region_ipv4_cidrs, file)
            print(f"CIDR data for ASN {asn} fetched from API and saved to file.")
            return
        # 如果文件不存在，请求 API 数据
        # url = f'https://api.bgpview.io/asn/{asn}/prefixes'
        # headers = {
        #     "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        #     "Cookie": "_ga=GA1.2.16443840.1721715301; _ga_7YFHLCZHVM=GS1.2.1721940403.6.1.1721943528.56.0.0; cf_clearance=6qVAAvRLRnLn6Noe9h274Id6yAZYjFDn_sk9Mo4WFag-1723470618-1.0.1.1-CRGPHBAPwpMFZuVQa2QvvooVQedZAKqEyRVawhaHZF62qdcKaCAHjXtINkKM3hv5ffoJb5VYilFKEwNEtjQdmA"
        # }
        # response = requests.get(url, headers=headers)
        # response.raise_for_status()
        # data = response.json()
        # cidrs = [prefix['prefix'] for prefix in data['data']['ipv4_prefixes']]
        cidrs = fetch_cidrs(asn)
        # 将数据写入文件
        with open(file_path, 'w') as file:
            json.dump(cidrs, file)
        print(f"CIDR data for ASN {asn} fetched from API and saved to file.")

    return cidrs


if __name__ == '__main__':
    # for asn in Wanted_ASN:
    #     if ',' in asn:
    #         asns = asn.split(',')
    #         for a in asns:
    #             get_cidr_ips(a)
    #             time.sleep(2)
    get_cidr_ips("40065")
    get_cidr_ips("KR_CIDR")

