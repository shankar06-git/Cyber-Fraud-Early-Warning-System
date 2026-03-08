import requests
import base64

API_KEY = "YOUR API KEY"

def check_virustotal(url):

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    headers = {
        "x-apikey": API_KEY
    }

    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    response = requests.get(vt_url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats["malicious"]
        suspicious = stats["suspicious"]

        print("\n--- VirusTotal Scan Results ---")
        print("Malicious:", malicious)
        print("Suspicious:", suspicious)

        if malicious > 0 or suspicious > 0:
            return True
        else:
            return False
    else:
        print("VirusTotal lookup failed")
        return False