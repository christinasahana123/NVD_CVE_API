import requests
import pymongo
from pymongo import MongoClient

# API URL
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# MongoDB Connection (Local)
client = MongoClient("mongodb://localhost:27017/")  # Connect to local MongoDB
db = client["cve_db"]
collection = db["cves"]

# Fetch Data from API
def fetch_cve_data(start_index=0, results_per_page=10):
    params = {"startIndex": start_index, "resultsPerPage": results_per_page}
    response = requests.get(API_URL, params=params)
    if response.status_code == 200:
        return response.json().get("vulnerabilities", [])
    return []

# Store Data in MongoDB
def store_data(cve_list):
    for item in cve_list:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        
        # Check if CVE ID already exists
        if collection.find_one({"id": cve_id}):
            print(f"Skipping duplicate CVE: {cve_id}")
            continue
        
        published = cve.get("published")
        modified = cve.get("lastModified")
        
        # Extract CVSS Score
        base_score = None
        metrics = cve.get("metrics", {}).get("cvssMetricV2", [])
        if metrics:
            base_score = metrics[0]["cvssData"]["baseScore"]
        
        description = cve.get("descriptions", [{}])[0].get("value", "No description available")

        # Insert into MongoDB
        cve_data = {
            "id": cve_id,
            "publishedDate": published,
            "lastModifiedDate": modified,
            "baseScore": base_score,
            "description": description
        }
        collection.insert_one(cve_data)

    print("Data successfully stored in MongoDB!")

# Run the Script
if __name__ == "__main__":
    data = fetch_cve_data(start_index=0, results_per_page=10)  # Fetch Data
    store_data(data)  # Store Data in MongoDB
