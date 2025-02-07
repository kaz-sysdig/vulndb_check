import requests
from collections import Counter
import urllib3
import time

# Suppress unnecessary SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Sysdig API endpoint and authentication token
SYSDIG_URL = "https://app.us4.sysdig.com"
API_URL = f"{SYSDIG_URL}/api/scanning/v1/results"
API_TOKEN = "YOUR_API_TOKEN"
HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}"
}

print("Fetching scanning results...")
response = requests.get(API_URL, headers=HEADERS, verify=False)

if response.status_code == 200:
    data = response.json()
    print("Successfully fetched scanning results.")
    
    # Extract the list of image IDs
    image_ids = [item["imageId"] for item in data.get("results", []) if "imageId" in item]
    print(f"Found {len(image_ids)} images to analyze.")
    
    # Retrieve vulnerability information for each image ID and store in a dictionary
    vulnerabilities = {}
    for index, image_id in enumerate(image_ids, start=1):
        print(f"Processing {index}/{len(image_ids)}: {image_id}")
        vuln_url = f"{SYSDIG_URL}/api/scanning/v1/images/by_id/{image_id}/vuln/all"
        vuln_response = requests.get(vuln_url, headers=HEADERS, verify=False)
        if vuln_response.status_code == 200:
            vulnerabilities[image_id] = vuln_response.json()
        else:
            vulnerabilities[image_id] = f"Error: {vuln_response.status_code}"
        time.sleep(0.5)  # Adding a small delay to avoid rate limits
    
    print("Finished processing all images.")
    
    # a. Count the total number of vulnerabilities
    total_vuln_count = sum(len(vuln_data.get("vulns", [])) for vuln_data in vulnerabilities.values() if isinstance(vuln_data, dict))
    
    # b. Count occurrences per feed_group
    feed_group_counts = Counter()
    for vuln_data in vulnerabilities.values():
        if isinstance(vuln_data, dict):
            for vuln in vuln_data.get("vulns", []):
                feed_group_counts[vuln.get("feed_group", "unknown")] += 1
    
    # c. Calculate the percentage of "feed_group": "vulndb:vulnerabilities"
    vulndb_vulnerabilities_count = feed_group_counts.get("vulndb:vulnerabilities", 0)
    percentage = (vulndb_vulnerabilities_count / total_vuln_count) * 100 if total_vuln_count > 0 else 0
    
    print(f"Total number of vulnerabilities: {total_vuln_count}")
    print("Occurrences per feed_group:", feed_group_counts)
    print(f"Percentage of 'vulndb:vulnerabilities' among all vulnerabilities: {percentage:.2f}%")
else:
    print(f"API request failed: {response.status_code}")

