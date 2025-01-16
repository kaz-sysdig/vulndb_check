import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AUTH_TOKEN = "XXXX"
BASE_URL = "https://{sysdig_backend}/secure/vulnerability/v1beta1"

HEADERS = {
    "Authorization": f"Bearer {AUTH_TOKEN}",
    "Content-Type": "application/json"
}

def get_result_ids():
    """
    get the resultId from runtime-results end point
    """
    url = f"{BASE_URL}/runtime-results"
    response = requests.get(url, headers=HEADERS, verify=False)

    if response.status_code != 200:
        print(f"Failed to fetch runtime-results: {response.status_code}")
        print(response.text)
        return []

    data = response.json()

    result_ids = [item['resultId'] for item in data.get('data', [])]
    print(f"Retrieved resultIds: {result_ids}")
    return result_ids

def get_result_details(result_id):
    """
    Retrieve details for a specified resultId and return:
    - Total number of detected vulnerabilities (the total count of `vulns` within `packages`)
    - The number of vulnerabilities where `sourceName` is `vulndb`
    """
    url = f"{BASE_URL}/results/{result_id}"
    response = requests.get(url, headers=HEADERS, verify=False)

    # Check the status code
    if response.status_code != 200:
        print(f"Failed to fetch details for resultId {result_id}: {response.status_code}")
        print(response.text)
        return 0, 0

    # Parse the JSON response
    data = response.json()

    # Count the total number of vulns in all packages
    vulnerabilities = [
        vuln for package in data.get("result", {}).get("packages", [])
        for vuln in package.get("vulns", [])
    ]
    total_vulnerabilities = len(vulnerabilities)

    # Count the number of items where sourceName is vulndb
    vulndb_vulnerabilities = [
        vuln for vuln in vulnerabilities
        if (vuln.get("severity", {}).get("sourceName", "").lower() == "vulndb") or
           (vuln.get("cvssScore", {}).get("sourceName", "").lower() == "vulndb")
    ]
    vulndb_count = len(vulndb_vulnerabilities)

    return total_vulnerabilities, vulndb_count

def calculate_vulndb_percentage(result_ids):
    """
    Calculate the total vulnerabilities detected and the total vulndb vulnerabilities
    across all resultIds, and compute the percentage of vulndb vulnerabilities.
    """
    total_vulnerabilities_detected = 0
    total_vulndb_vulnerabilities = 0

    # Loop through each resultId and aggregate values
    for result_id in result_ids:
        total_vulns, vulndb_vulns = get_result_details(result_id)
        total_vulnerabilities_detected += total_vulns
        total_vulndb_vulnerabilities += vulndb_vulns

    # Calculate the percentage
    if total_vulnerabilities_detected > 0:
        vulndb_percentage = (total_vulndb_vulnerabilities / total_vulnerabilities_detected) * 100
    else:
        vulndb_percentage = 0.0

    # Print the results
    print("\n=== Aggregated Results ===")
    print(f"Total vulnerabilities detected: {total_vulnerabilities_detected}")
    print(f"Total vulnerabilities from 'vulndb': {total_vulndb_vulnerabilities}")
    print(f"'vulndb' Percentage: {vulndb_percentage:.2f}%")

    return total_vulnerabilities_detected, total_vulndb_vulnerabilities, vulndb_percentage

if __name__ == "__main__":
    # Step 1: Retrieve all resultIds
    result_ids = get_result_ids()

    # Step 2: Calculate the vulndb percentage
    calculate_vulndb_percentage(result_ids)
