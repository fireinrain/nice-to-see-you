import json
import os
import time

import requests

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
    "7679": "AS7679 QTnet Inc,696320"
}
# 每天运行2个，凌晨一个 中午一个
Wanted_ASN = ['906', '4760', '31898', '135377', '3462', '4609', '4760',
              '17511', '4785', '7679', '21859', '4809', '45102', '132203']

CountryASN = {
    'HK': ['4515', '9269', '4760', '9304', '10103', '17444', '9381', '135377'],
    'MO': ['4609', '7582', '64061', '133613'],
    'SG': ['45102', '139070', '139190'],
    'TW': ['4609'],
    'KR': ['31898', '9689'],
    'JP': ['2497', '7679'],
    'US': ['906']
}


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
        # 如果文件不存在，请求 API 数据
        url = f'https://api.bgpview.io/asn/{asn}/prefixes'
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Cookie": "_ga=GA1.2.16443840.1721715301; _ga_7YFHLCZHVM=GS1.2.1721940403.6.1.1721943528.56.0.0; cf_clearance=6qVAAvRLRnLn6Noe9h274Id6yAZYjFDn_sk9Mo4WFag-1723470618-1.0.1.1-CRGPHBAPwpMFZuVQa2QvvooVQedZAKqEyRVawhaHZF62qdcKaCAHjXtINkKM3hv5ffoJb5VYilFKEwNEtjQdmA"
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        cidrs = [prefix['prefix'] for prefix in data['data']['ipv4_prefixes']]

        # 将数据写入文件
        with open(file_path, 'w') as file:
            json.dump(cidrs, file)
        print(f"CIDR data for ASN {asn} fetched from API and saved to file.")

    return cidrs


if __name__ == '__main__':
    # for asn in Wanted_ASN:
    #     get_cidr_ips(asn)
    #     time.sleep(2)
    get_cidr_ips("7679")
