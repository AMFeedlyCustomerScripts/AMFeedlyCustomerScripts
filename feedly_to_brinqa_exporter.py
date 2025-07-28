import requests
import logging
import yaml
import sys

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

def fetch_feedly_cves(feedly_token, dashboard_query_json):
    """
    Query the Feedly Vulnerability Dashboard and return CVEs.
    """
    url = "https://api.feedly.com/v3/vulnerability-dashboard/query"
    headers = {
        "Authorization": f"Bearer {feedly_token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(url, headers=headers, json=dashboard_query_json)
        response.raise_for_status()
        result = response.json()
        return result.get("vulnerabilities", [])
    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying Feedly: {e}")
        return []

def export_to_brinqa(cve_list, brinqa_url, brinqa_token):
    """
    Export CVE data to Brinqa using their API.
    """
    if not cve_list:
        logging.info("No CVEs to export to Brinqa.")
        return

    headers = {
        "Authorization": f"Bearer {brinqa_token}",
        "Content-Type": "application/json"
    }

    for cve in cve_list:
        try:
            payload = {
                "cveid": cve.get("cveid"),
                "description": cve.get("description"),
                "cvssV3": cve.get("cvssV3"),
                "exploitAvailable": cve.get("proofOfExploits", False),
                "exploited": cve.get("exploited", False),
                "patchAvailable": cve.get("patched", False),
                "affectedProducts": cve.get("affectedProducts", []),
                "feedSource": "Feedly"
            }

            response = requests.post(brinqa_url, headers=headers, json=payload)
            if response.status_code in [200, 201]:
                logging.info(f"Exported CVE {cve.get('cveid')} to Brinqa.")
            else:
                logging.error(f"Brinqa export failed for {cve.get('cveid')}: {response.status_code} - {response.text}")
        except Exception as e:
            logging.exception(f"Exception exporting CVE {cve.get('cveid')} to Brinqa: {e}")

def main():
    # Load config.yaml
    try:
        with open("config.yaml", "r") as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        logging.error("config.yaml not found.")
        return

    # Extract config
    feedly_token = config.get("feedly", {}).get("api_key")
    brinqa_token = config.get("brinqa", {}).get("api_token")
    brinqa_url = config.get("brinqa", {}).get("api_url")

    if not all([feedly_token, brinqa_token, brinqa_url]):
        logging.error("Missing API credentials in config.yaml.")
        return

    # Feedly dashboard query for trending CVEs from the last 7 days
    dashboard_query = {
        "layers": [
            {
                "filters": [
                    {
                        "field": "period",
                        "value": {
                            "type": "Last7Days",
                            "label": "Last 7 Days"
                        }
                    }
                ]
            },
            {
                "filters": [
                    {
                        "field": "trending",
                        "value": True
                    }
                ]
            }
        ]
    }

    logging.info("Fetching CVEs from Feedly...")
    cve_list = fetch_feedly_cves(feedly_token, dashboard_query)

    logging.info(f"Retrieved {len(cve_list)} CVEs. Exporting to Brinqa...")
    export_to_brinqa(cve_list, brinqa_url, brinqa_token)
    logging.info("Export complete.")

if __name__ == "__main__":
    main()
