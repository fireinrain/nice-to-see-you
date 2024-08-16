import json

import requests

try:
    with open('locations.json', 'r') as file:
        locations = json.load(file)
except FileNotFoundError:
    response = requests.get('https://speed.cloudflare.com/locations')
    locations = response.json()
    with open('locations.json', 'w') as file:
        file.write(locations)

CloudflareLocationJson = locations

loc_map = {}
for loc in locations:
    loc_map[loc['iata']] = loc

CloudflareLocationMap = loc_map
