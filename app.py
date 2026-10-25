"""Run:  sudo python app.py   ->  open http://127.0.0.1:5000   (sudo only needed for live capture)"""
import json, os
from flask import Flask, jsonify, render_template, request
from engine import Engine
app = Flask(__name__); eng = Engine()

@app.route("/")
def index(): return render_template("index.html")

@app.route("/api/state")
def state(): return jsonify(eng.state())

@app.route("/api/metrics")
def metrics():
    return jsonify(json.load(open("metrics.json")) if os.path.exists("metrics.json") else {})

@app.route("/api/start", methods=["POST"])
def start():
    d = request.json; eng.start(d["mode"], d["source"], float(d.get("speed", 1))); return jsonify(ok=True)

@app.route("/api/stop", methods=["POST"])
def stop(): eng.stop(); return jsonify(ok=True)

if __name__ == "__main__": app.run(host="127.0.0.1", port=5000)
