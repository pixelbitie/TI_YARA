import requests
import datetime
import json
import os
from collections import defaultdict

# Abuse.ch ThreatFox API endpoint
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"

# Today's date for file naming
today = datetime.date.today().strftime("%Y%m%d")

# Function to fetch IOCs (e.g., SHA256 hashes and domains)
def fetch_iocs():
    payload = {
        "query": "get_iocs",
        "limit": 50
    }
    response = requests.post(THREATFOX_API, json=payload)
    
    if response.status_code == 200:
        result = response.json()
        if "data" in result and isinstance(result["data"], list):
            return result["data"]
        else:
            print("[-] Unexpected response format:")
            print(json.dumps(result, indent=2))
            return []
    else:
        print(f"[-] Error fetching data from ThreatFox: {response.status_code}")
        return []

# Function to generate YARA rules
def generate_yara(iocs):
    yara_hashes = []
    yara_domains = []

    # Prepare to collect context
    for ioc in iocs:
        ioc_type = ioc.get("ioc_type")
        value = ioc.get("ioc")
        malware = ioc.get("malware")
        threat_type = ioc.get("threat_type")
        confidence = ioc.get("confidence_level")

        # Filter and collect IOCs
        if ioc_type == "domain":
            yara_domains.append({
                'value': value,
                'malware': malware,
                'threat_type': threat_type,
                'confidence': confidence
            })
        elif ioc_type == "sha256":
            yara_hashes.append({
                'value': value,
                'malware': malware,
                'threat_type': threat_type,
                'confidence': confidence
            })

    # Prepare YARA rule
    rule = f"""rule ThreatIntel_{today}
{{
    meta:
        description = "Auto-generated YARA rule from ThreatFox IOCs"
        author = "ThreatIntelModule"
        date = "{today}"

    strings:
"""

    # Add domains with context comments
    for i, domain in enumerate(yara_domains):
        comment = f'  // Malware: {domain["malware"]}, Threat Type: {domain["threat_type"]}, Confidence: {domain["confidence"]}'
        rule += f'        $domain{i} = "{domain["value"]}" {comment}\n'

    # Add hashes with context comments
    for i, h in enumerate(yara_hashes):
        comment = f'  // Malware: {h["malware"]}, Threat Type: {h["threat_type"]}, Confidence: {h["confidence"]}'
        rule += f'        $hash{i} = "{h["value"]}" {comment}\n'

    rule += """
    condition:
        any of them
}
"""
    return rule



def save_rule(rule_text):
    output_dir = "TI_YARA_Outputs"
    os.makedirs(output_dir, exist_ok=True)  # Create folder if it doesn't exist

    filename = f"threatintel_{today}.yara"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        f.write(rule_text)

    print(f"[+] YARA rule saved to: {filepath}")

# Called on script run
if __name__ == "__main__":
    ioc_data = fetch_iocs()
    if ioc_data:
        yara_rule = generate_yara(ioc_data)
        save_rule(yara_rule)
    else:
        print("[-] No IOC data retrieved.")
