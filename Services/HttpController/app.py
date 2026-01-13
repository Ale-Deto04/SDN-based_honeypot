import re
import subprocess
import ipaddress
from flask import Flask, request, jsonify, render_template, redirect, url_for, abort
from flask_socketio import SocketIO
from NETCONFIG import PATTERNS, CONFIG

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins = "*")

status = {
	"controller": {"on": False},
	"server": {"on": False,"ip": None},
	"hpot": {"on": False,"ip": None}
}

MAX_HISTORY = 50
log = []

devices = []
patterns = PATTERNS

PATTERNS_REGEX = r"\[[^\[\]]*\]"
IPV4_REGEX = r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"

PATH_TO_CONTROLLER = "/shared/controllerSDN/controller.py"

# API interface
@app.route("/api/logs", methods = ["POST"])
def collect_logs():

	# # Little security check
	# if not ipaddress.ip_address(requests.remote_addr).is_loopback:
	# 	return {"error": "Forbidden"}, 403

	payload = request.get_json()

	if payload:
		if payload.get("level") == "CONF":
			parser(payload)

		record = {
			"code": payload.get("code", 0),
			"message": formatter(payload)
		}

		log.append(record)
		if len(log) > MAX_HISTORY:
			log.pop(0)

		socketio.emit("console_message", record)

	return "", 204


# Dashboard
@app.route("/dashboard", methods = ["GET"])
def home():
	return render_template("index.html", status = status)

# Console
@app.route("/terminal", methods = ["GET"])
def terminal():
	return render_template("terminal.html", log = log)

@app.route("/devices", methods = ["GET"])
def devicesList():
	return render_template("devices.html", devices = devices, patterns = PATTERNS, net_config = CONFIG)

@app.route("/init", methods = ["GET"])
def init():
	if not status["controller"]["on"]:
		subprocess.Popen(["ryu-manager", PATH_TO_CONTROLLER], stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)
		status["controller"]["on"] = True
	return redirect(url_for("home"))


# |=========| 
# | UTILITY |
# |=========|
def parser(payload):

	ipv4 = re.search(IPV4_REGEX, payload.get("message")).group()

	# Server up
	if payload.get("code") == 200:
		status["server"]["on"] = True
		status["server"]["ip"] = ipv4
		host = {"name": "Server", "ip": ipv4, "trusted": True}
		devices.append(host)
		socketio.emit("server_status", {"ip": status["server"]["ip"]})
		socketio.emit("new_host", host)
		return

	# HPot up
	if payload.get("code") == 201:
		status["hpot"]["on"] = True
		status["hpot"]["ip"] = ipv4
		host = {"name": "HoneyPot", "ip": ipv4, "trusted": True}
		devices.append(host)
		socketio.emit("hpot_status", {"ip": status["hpot"]["ip"]})
		socketio.emit("new_host", host)
		return

	# New trusted device
	if payload.get("code") == 101:
		host = {"name": "Client", "ip": ipv4, "trusted": True}
		devices.append(host)
		socketio.emit("new_host", host)
		return

	# New untrusted device
	if payload.get("code") == 110:
		host = {"name": "Client", "ip": ipv4, "trusted": False, "monitoring": False}
		devices.append(host)
		socketio.emit("new_host", host)
		return

	# Intrusion
	if payload.get("code") == 999:
		for d in devices:
			if d["ip"] == ipv4:
				d["monitoring"] = True
				socketio.emit("monitoring", {"ip": ipv4})
				return



def formatter(payload):
	timestamp = payload.get("timestamp", "NA")
	level = payload.get("level", "NA")
	message = payload.get("message", "")
	return f"{timestamp} [{level}] {message}"

if __name__ == "__main__":
    socketio.run(app, debug = True, host = "0.0.0.0", port = 5000, allow_unsafe_werkzeug = True)
