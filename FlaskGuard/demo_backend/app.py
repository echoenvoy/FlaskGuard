from flask import Flask, render_template, request, jsonify

app = Flask(__name__, template_folder='templates')

# Mock search results to make the page responsive if needed
@app.route("/")
def home():
    return render_template("main.html")

@app.route("/api/search")
def search():
    query = request.args.get("q", "")
    return jsonify({
        "status": "success",
        "query": query,
        "results": [
            {"id": 1, "name": f"Result for {query}", "price": 99.99}
        ]
    })

@app.route("/api/submit", methods=["POST"])
def submit():
    data = request.json or {}
    return jsonify({
        "status": "success",
        "message": "Data received",
        "data": data
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
