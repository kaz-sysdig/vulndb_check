import requests
from collections import Counter
import urllib3
import concurrent.futures

# Suppress unnecessary SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SYSDIG_URL = "https://app.us4.sysdig.com"
API_URL = f"{SYSDIG_URL}/api/scanning/v1/results"
API_TOKEN = "YOUR_API_TOKEN"
HEADERS = {"Authorization": f"Bearer {API_TOKEN}"}

print("Fetching scanning results...")
response = requests.get(API_URL, headers=HEADERS, verify=False)

if response.status_code == 200:
    data = response.json()
    print("Successfully fetched scanning results.")

    image_ids = [item["imageId"] for item in data.get("results", []) if "imageId" in item]
    print(f"Found {len(image_ids)} images to analyze.")

    vulnerabilities = {}

    def fetch_vulnerabilities(index, image_id, total_images):
        """各イメージの脆弱性情報を取得"""
        print(f"Processing {index}/{total_images}: {image_id}")  # 進捗を表示
        vuln_url = f"{SYSDIG_URL}/api/scanning/v1/images/by_id/{image_id}/vuln/all"
        vuln_response = requests.get(vuln_url, headers=HEADERS, verify=False)
        return image_id, vuln_response.json() if vuln_response.status_code == 200 else f"Error: {vuln_response.status_code}"

    # 並列リクエスト実行 (最大5スレッド)
    total_images = len(image_ids)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_image = {executor.submit(fetch_vulnerabilities, index, image_id, total_images): image_id for index, image_id in enumerate(image_ids, start=1)}

        for future in concurrent.futures.as_completed(future_to_image):
            image_id, result = future.result()
            vulnerabilities[image_id] = result

    print("Finished processing all images.")

    # 集計処理
    total_vuln_count = sum(len(vuln_data.get("vulns", [])) for vuln_data in vulnerabilities.values() if isinstance(vuln_data, dict))
    feed_group_counts = Counter()
    for vuln_data in vulnerabilities.values():
        if isinstance(vuln_data, dict):
            for vuln in vuln_data.get("vulns", []):
                feed_group_counts[vuln.get("feed_group", "unknown")] += 1

    vulndb_vulnerabilities_count = feed_group_counts.get("vulndb:vulnerabilities", 0)
    percentage = (vulndb_vulnerabilities_count / total_vuln_count) * 100 if total_vuln_count > 0 else 0

    print(f"Total number of vulnerabilities: {total_vuln_count}")
    print("Occurrences per feed_group:", feed_group_counts)
    print(f"Percentage of 'vulndb:vulnerabilities' among all vulnerabilities: {percentage:.2f}%")
else:
    print(f"API request failed: {response.status_code}")

