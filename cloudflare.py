import os

import requests

# Replace with your Cloudflare API token and zone ID
api_key = os.getenv('CF_APIKEY', '')
api_email = os.getenv('CF_APIEMAIL', 'xxx@gmail.com')
zone_id = os.getenv('CF_ZONEID', 'xxx')
hostname = os.getenv('CF_HOSTNAME','xx.xx')

# DNS record details
# RecordName = 'xxx.xxxxx'
# RecordType = 'A'
# RecordContent = '192.168.1.1'

# Set headers for API requests
headers = {
    'X-Auth-Key': api_key,
    'X-Auth-Email': api_email,
    'Content-Type': 'application/json'
}


# Add a DNS record
def add_dns_record(record_type: str, record_name: str, record_content: str):
    url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records'
    data = {
        'type': record_type,
        'name': record_name,
        'content': record_content,
        'ttl': 120,  # TTL in seconds
        'proxied': False  # Whether the traffic is proxied through Cloudflare
    }
    response = requests.post(url, headers=headers, json=data)
    response.raise_for_status()  # Raises an HTTPError for bad responses
    result = response.json()['result']
    print(f"Added DNS record: {result['id']}")


# Remove a DNS record
def remove_dns_record(record_type: str, record_name: str, record_content: str):
    url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records'
    params = {'name': record_name, 'type': record_type}
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    records = response.json()['result']
    if not records:
        print(f"No record found for {record_name}")
        return
    for record in records:
        if record['content'] == record_content:
            delete_url = f"{url}/{record['id']}"
            delete_response = requests.delete(delete_url, headers=headers)
            delete_response.raise_for_status()
            print(f"Removed DNS record: {record['id']}")


if __name__ == '__main__':
    # add_dns_record('A', RecordName, RecordContent)
    # remove_dns_record('A',RecordName,RecordContent)
    pass
