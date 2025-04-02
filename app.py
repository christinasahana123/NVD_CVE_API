from flask import Flask, jsonify, request
from pymongo import MongoClient
from datetime import datetime,timedelta
from bson import ObjectId
from flask_cors import CORS 

app = Flask(__name__)
CORS(app)

# Connect to Local MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["cve_db"]
collection = db["cves"]

# Home Route
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "CVE API is running!"})

# @app.route('/cves/all', methods=['GET'])
# def get_all_cves():
#     # Assuming you use MongoDB
#     cves = list(db.cve_collection.find({}, {"_id": 0}))  # Exclude ObjectId
#     return jsonify(cves)

app.route("/cves/<cve_id>", methods=["GET"])
def get_cve(cve_id):
    cve = collection.find_one({"id": cve_id})  # Ensure ID matches
    if not cve:
        return jsonify({"error": "No such record found"}), 404
    cve["_id"] = str(cve["_id"])  # Convert ObjectId to string
    return jsonify(cve)

# Fetch CVE by ID
@app.route("/cves/<cve_id>", methods=["GET"])
def get_cve(cve_id):
    cve_record = collection.find_one({"cve.CVE_data_meta.ID": cve_id})

    if not cve_record:
        return jsonify({"error": "No such record found"}), 404

    # Convert ObjectId to string (fix JSON serialization error)
    cve_record["_id"] = str(cve_record["_id"])

    return jsonify(cve_record)

# Fetch CVEs with optional filtering by CVSS score
@app.route("/cves", methods=["GET"])
def get_filtered_cves():
    min_score = request.args.get("min_score", type=float)
    max_score = request.args.get("max_score", type=float)

    query = {}
    if min_score is not None:
        query["baseScore"] = {"$gte": min_score}
    if max_score is not None:
        if "baseScore" in query:
            query["baseScore"]["$lte"] = max_score
        else:
            query["baseScore"] = {"$lte": max_score}

    cves = list(collection.find(query))
    for cve in cves:
        cve["_id"] = str(cve["_id"])  # Convert ObjectId to string

    return jsonify(cves)


@app.route("/cves/year/<int:year>", methods=["GET"])
def get_cves_by_year(year):
    start_date = datetime(year, 1, 1).isoformat()
    end_date = datetime(year + 1, 1, 1).isoformat()

    query = {
        "publishedDate": {
            "$gte": start_date,
            "$lt": end_date,
        }
    }
    
    cves = list(collection.find(query))
    for cve in cves:
        cve["_id"] = str(cve["_id"])  # Convert ObjectId to string

    return jsonify(cves)

@app.route("/cves/modified", methods=["GET"])
def get_cves_modified():
    try:
        days = int(request.args.get("days", 7))  # Default to 7 days
        today = datetime.utcnow()
        start_date = today - timedelta(days=days)

        query = {"lastModifiedDate": {"$gte": start_date.isoformat()}}

        cves = list(collection.find(query))
        for cve in cves:
            cve["_id"] = str(cve["_id"])  # Convert ObjectId to string

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
    
@app.route("/cves/add", methods=["POST"])
def add_cve():
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ["id", "baseScore", "description", "publishedDate", "lastModifiedDate"]
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        # Convert date fields to ISO format
        try:
            data["publishedDate"] = datetime.strptime(data["publishedDate"], "%Y-%m-%dT%H:%M:%S.%f")
            data["lastModifiedDate"] = datetime.strptime(data["lastModifiedDate"], "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            return jsonify({"error": "Invalid date format. Use ISO 8601 format: YYYY-MM-DDTHH:MM:SS.sss"}), 400

        # Check if CVE ID already exists
        if collection.find_one({"id": data["id"]}):
            return jsonify({"error": "CVE ID already exists"}), 409  # Conflict error

        # Insert into MongoDB
        collection.insert_one(data)
        return jsonify({"message": "CVE added successfully", "data": data}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500





# Run Flask App
if __name__ == "__main__":
    app.run(debug=True)
