from flask import Flask, jsonify, request
from pymongo import MongoClient

app = Flask(__name__)

# Connect to Local MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["cve_db"]
collection = db["cves"]

# Home Route
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "CVE API is running!"})

# Fetch All CVEs
@app.route("/cves", methods=["GET"])
def get_all_cves():
    cves = list(collection.find({}, {"_id": 0}))  # Exclude MongoDB's "_id" field
    return jsonify(cves)

# Fetch CVE by ID
@app.route("/cve/<cve_id>", methods=["GET"])
def get_cve_by_id(cve_id):
    cve = collection.find_one({"id": cve_id}, {"_id": 0})
    if cve:
        return jsonify(cve)
    return jsonify({"error": "CVE not found"}), 404

# Fetch CVEs with optional filtering by CVSS score
@app.route("/cves", methods=["GET"])
def get_filtered_cves():
    min_score = request.args.get("min_score", type=float)
    max_score = request.args.get("max_score", type=float)

    query = {}
    if min_score is not None:
        query["baseScore"] = {"$gte": min_score}  # CVSS score should be >= min_score
    if max_score is not None:
        query["baseScore"]["$lte"] = max_score if "baseScore" in query else {"$lte": max_score}

    cves = list(collection.find(query, {"_id": 0}))  # Exclude MongoDB's "_id" field
    return jsonify(cves)


# Run Flask App
if __name__ == "__main__":
    app.run(debug=True)
