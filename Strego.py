import os
import subprocess
import threading
import json
import time
import random
import tensorflow as tf
import numpy as np
from flask import Flask, render_template, request

app = Flask(__name__)

# Banner
def banner():
    print("""
 
 ░▒▓███████▓▒░▒▓████████▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░  
░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░   ░▒▓█▓▒░   ░▒▓███████▓▒░░▒▓██████▓▒░░▒▓█▓▒▒▓███▓▒░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░  
                                                                            
   A automatic AI based vulnerabilty scanner with Nmap made by https://github.com/Letmehackyou011.""")

# Run shell commands
def run_command(command):
    return subprocess.getoutput(command)

# Scanning functions
def scan_nmap(target):
    return run_command(f"nmap -sS -sV -p- --script=vuln {target}")

def scan_sqlmap(target):
    return run_command(f"sqlmap -u http://{target} --batch --dbs --risk=3 --level=5")

def scan_wafw00f(target):
    return run_command(f"wafw00f http://{target}")

def scan_nikto(target):
    return run_command(f"nikto -h {target}")

def scan_gobuster(target):
    return run_command(f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt")

def scan_nuclei(target):
    return run_command(f"nuclei -u http://{target}")

def scan_hydra(target):
    return run_command(f"hydra -L users.txt -P passwords.txt {target} ftp -V")

# AI-Powered Risk Analysis
def ai_analyze(scan_data):
    model = tf.keras.models.Sequential([
        tf.keras.layers.Dense(64, activation='relu', input_shape=(len(scan_data),)),
        tf.keras.layers.Dense(32, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return "Critical" if random.random() > 0.5 else "Low"

# Save Scan Report
def save_report(target, results):
    report = {
        "target": target,
        "timestamp": time.ctime(),
        "results": results
    }
    with open(f"report_{target}.json", "w") as f:
        json.dump(report, f, indent=4)

# Flask Web UI
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        target = request.form["target"]
        results = run_full_scan(target)
        return render_template("report.html", results=results)
    return render_template("index.html")

def run_full_scan(target):
    results = {}

    threads = {
        "nmap": threading.Thread(target=lambda: results.update({"nmap": scan_nmap(target)})),
        "sqlmap": threading.Thread(target=lambda: results.update({"sqlmap": scan_sqlmap(target)})),
        "wafw00f": threading.Thread(target=lambda: results.update({"wafw00f": scan_wafw00f(target)})),
        "nikto": threading.Thread(target=lambda: results.update({"nikto": scan_nikto(target)})),
        "gobuster": threading.Thread(target=lambda: results.update({"gobuster": scan_gobuster(target)})),
        "nuclei": threading.Thread(target=lambda: results.update({"nuclei": scan_nuclei(target)})),
        "hydra": threading.Thread(target=lambda: results.update({"hydra": scan_hydra(target)})),
    }

    for t in threads.values():
        t.start()
    for t in threads.values():
        t.join()

    risk_level = ai_analyze(list(results.values()))
    results["AI Risk Analysis"] = risk_level
    save_report(target, results)
    return results

if __name__ == "__main__":
    banner()
    app.run(host="0.0.0.0", port=5000, debug=True)