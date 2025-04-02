from flask import Flask, jsonify, request
from pymongo import MongoClient
from datetime import datetime,timedelta

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

@app.route("/cves/year/<int:year>", methods=["GET"])
def get_cves_by_year(year):
    start_date = datetime(year, 1, 1)
    end_date = datetime(year + 1, 1, 1)

    query = {
        "publishedDate": {
            "$gte": start_date.isoformat(),
            "$lt": end_date.isoformat(),
        }
    }
    
    cves = list(collection.find(query, {"_id": 0}))  # Exclude MongoDB "_id"
    return jsonify(cves)
@app.route("/cves/modified", methods=["GET"])
def get_cves_modified():
    try:
        days = int(request.args.get("days", 7))  # Default to last 7 days if not provided
        today = datetime.utcnow()
        start_date = today - timedelta(days=days)

        query = {
            "lastModifiedDate": {
                "$gte": start_date.isoformat()
            }
        }

        cves = list(collection.find(query, {"_id": 0}))  # Exclude MongoDB "_id"
        return jsonify(cves)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/cves/search", methods=["GET"])
def search_cves_by_description():
    try:
        keyword = request.args.get("keyword", "").strip()
        if not keyword:
            return jsonify({"error": "Keyword is required"}), 400

        page = int(request.args.get("page", 1))  # Default to page 1
        limit = int(request.args.get("limit", 10))  # Default to 10 results per page
        skip = (page - 1) * limit  # Calculate how many documents to skip

        sort_field = request.args.get("sort", "publishedDate")  # Default sorting field
        sort_order = request.args.get("order", "desc").lower()  # Default: descending

        query = {"description": {"$regex": keyword, "$options": "i"}}

        total_count = collection.count_documents(query)  # Count total matching CVEs

        # Validate sort field and set sorting order
        valid_sort_fields = ["baseScore", "publishedDate", "lastModifiedDate"]
        if sort_field not in valid_sort_fields:
            return jsonify({"error": f"Invalid sort field. Choose from {valid_sort_fields}"}), 400

        sort_direction = -1 if sort_order == "desc" else 1  # -1 = descending, 1 = ascending

        cves = list(collection.find(query, {"_id": 0})
                    .sort(sort_field, sort_direction)  # Apply sorting
                    .skip(skip)
                    .limit(limit))

        return jsonify({
            "page": page,
            "limit": limit,
            "total_results": total_count,
            "total_pages": (total_count // limit) + (1 if total_count % limit > 0 else 0),
            "data": cves
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500



# Run Flask App
if __name__ == "__main__":
    app.run(debug=True)
