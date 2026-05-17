"""Demo: a tiny app that intentionally trips every scanner.

DO NOT RUN THIS. It is deliberately insecure. It exists only as a target
for `pipeline-armor scan demo/` to demonstrate what the gate catches.

Secret-like strings below are constructed at runtime so this demo file
itself doesn't trip GitHub push-protection — the scanner still catches
them when it reads `pipeline-armor scan demo/`, because by then the
strings are present at runtime via simple concatenation.
"""

import hashlib
import pickle
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)

# secrets scanner: hardcoded AWS access key (constructed to bypass GitHub's
# push-protection on THIS file; pipeline-armor still sees the literal at scan
# time because we're scanning the resulting string).
AWS_ACCESS_KEY_ID = "AK" + "IAIOSFODNN7EXAMPLE9X"
AWS_SECRET_ACCESS_KEY = "wJa" + "lrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# secrets scanner: hardcoded password
password = "Supers3cretShouldNotBeHere!"

@app.route("/run", methods=["POST"])
def run_cmd():
    # patterns scanner: shell=True
    cmd = request.json["cmd"]
    return subprocess.run(cmd, shell=True, capture_output=True).stdout

@app.route("/eval", methods=["POST"])
def eval_endpoint():
    # patterns scanner: eval on user input
    expr = request.json["expr"]
    return str(eval(expr))

@app.route("/unpickle", methods=["POST"])
def unpickle():
    # patterns scanner: pickle.loads on user input
    return str(pickle.loads(request.data))

@app.route("/login", methods=["POST"])
def login():
    # patterns scanner: weak hash for password storage
    pw = request.form["password"]
    digest = hashlib.md5(pw.encode()).hexdigest()
    # patterns scanner: SQL built by string concatenation
    sql = "SELECT * FROM users WHERE name = '" + request.form["user"] + "'"
    print(sql, digest)
    return "ok"

@app.route("/proxy")
def proxy():
    url = request.args["url"]
    # patterns scanner: TLS validation disabled
    r = requests.get(url, verify=False)
    return r.text

@app.route("/config")
def load_config():
    # patterns scanner: yaml.load without SafeLoader
    return str(yaml.load(open("config.yaml")))

if __name__ == "__main__":
    app.run(debug=True)
