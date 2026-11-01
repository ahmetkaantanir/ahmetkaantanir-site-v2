"""Opt-in IP enrichment against fixed provider endpoints, never arbitrary URLs."""
import ipaddress
import json
import os
from urllib.parse import urlencode
from urllib.request import Request, build_opener
from urllib.error import HTTPError, URLError

from integrations.client import IntegrationError, NoRedirect


def enrich_ip(provider, address):
    ip = ipaddress.ip_address(address)
    if not ip.is_global:
        raise ValueError("Only globally routable IPs may be disclosed to external providers")
    if provider == 'abuseipdb':
        key = os.getenv('LAB_ABUSEIPDB_KEY', '')
        url = 'https://api.abuseipdb.com/api/v2/check?' + urlencode({'ipAddress':str(ip),'maxAgeInDays':30})
        headers = {'Key':key, 'Accept':'application/json'}
    elif provider == 'virustotal':
        key = os.getenv('LAB_VIRUSTOTAL_KEY', '')
        url = 'https://www.virustotal.com/api/v3/ip_addresses/' + str(ip)
        headers = {'x-apikey':key, 'Accept':'application/json'}
    else:
        raise ValueError("Unknown intelligence provider")
    if not key:
        raise IntegrationError("Intelligence provider key is not configured")
    try:
        with build_opener(NoRedirect).open(Request(url,headers=headers),timeout=8) as response:
            content = response.read(512*1024+1)
            if len(content)>512*1024:
                raise ValueError()
            result = json.loads(content)
        if not isinstance(result,dict):
            raise ValueError()
    except (HTTPError,URLError,OSError,ValueError) as exc:
        raise IntegrationError("Intelligence provider unavailable") from exc
    return {'provider':provider,'ip':str(ip),'result':result,'external_disclosure':True,
        'warning':'Provider observations are time-dependent and are not proof of compromise.'}
