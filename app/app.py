from flask import Flask, render_template, request
import pickle
import numpy as np
import os
import sys

# ---------------- PATH SETUP ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "model"))
sys.path.insert(0, MODEL_DIR)

import sys
print("PYTHON EXECUTABLE:", sys.executable)

# ---------------- IMPORT ML FEATURES ----------------
from feature_extraction import (
    extract_features,
    brand_keyword_score,
    domain_age_score,
    html_intent_score,
    is_valid_url,
    numeric_domain_score
)

# ---------------- FLASK APP ----------------
app = Flask(__name__)

# ---------------- LOAD MODEL ----------------
with open(os.path.join(MODEL_DIR, "phishing_model.pkl"), "rb") as f:
    model = pickle.load(f)

# ---------------- SIMPLE STRING-BASED SECURITY CHECKS ----------------
def is_suspicious_tld(url):
    try:
        host = url.split("//")[-1].split("/")[0].lower()
        return host.endswith((
            ".login",
            ".verify",
            ".secure",
            ".update",
            ".account",
            ".signin",
            ".bank"
        ))
    except:
        return False


def has_action_domain(url):
    try:
        host = url.split("//")[-1].split("/")[0].lower()
        domain_part = host.split(".")[0]
        return any(word in domain_part for word in [
            "login", "secure", "verify", "account", "update", "signin", "bank"
        ])
    except:
        return False

def generate_reasons(url, checks):
    reasons = []

    if checks.get("invalid"):
        reasons.append("Malformed or invalid URL structure")

    if checks.get("suspicious_tld"):
        reasons.append("Uses a suspicious top-level domain")

    if checks.get("numeric_domain"):
        reasons.append("Domain name contains only numbers")

    if checks.get("brand_risk"):
        reasons.append("Possible brand impersonation detected")

    if checks.get("young_domain"):
        reasons.append("Domain is newly registered")

    if checks.get("html_intent"):
        reasons.append("Login or password form detected on website")

    if checks.get("ml_flag"):
        reasons.append("Machine learning model detected phishing patterns")

    if not reasons:
        reasons.append("No common phishing indicators detected")

    return reasons

# ---------------- ROUTE ----------------
@app.route("/", methods=["GET", "POST"])
def index():
    prediction = None
    url_value = ""
    risk_details = {}
    reasons = None   # 🔹 IMPORTANT: default is None

    if request.method == "POST":
        url_value = request.form["url"].strip()

        # ---- INVALID URL BLOCK ----
        if not is_valid_url(url_value):
            prediction = "⚠️ Suspicious / Invalid URL"
            risk_details = {"Final Risk Score": 1.0}
            reasons = ["Malformed or invalid URL structure"]

            return render_template(
                "index.html",
                prediction=prediction,
                url_value=url_value,
                risk_details=risk_details,
                reasons=reasons
            )

        # ---- ML PREDICTION ----
        features = np.array(extract_features(url_value)).reshape(1, -1)
        ml_pred = model.predict(features)[0]

        # ---- HEURISTICS ----
        brand_risk = brand_keyword_score(url_value)
        domain_risk = domain_age_score(url_value)
        html_risk = html_intent_score(url_value)
        numeric_risk = numeric_domain_score(url_value)
        tld_risk = is_suspicious_tld(url_value)
        action_risk = has_action_domain(url_value)

        # ---- FINAL DECISION LOGIC ----
        if tld_risk:
            prediction = "⚠️ Phishing Website"
            final_risk_score = 0.9

        elif numeric_risk == 1:
            prediction = "⚠️ Phishing Website"
            final_risk_score = 0.9

        elif brand_risk == 1 and domain_risk == 1:
            prediction = "⚠️ Phishing Website"
            final_risk_score = 0.85

        elif html_risk == 1:
            prediction = "⚠️ Phishing Website"
            final_risk_score = 0.8

        elif ml_pred == 1:
            prediction = "⚠️ Phishing Website"
            final_risk_score = 0.7

        else:
            prediction = "✅ Legitimate Website"
            final_risk_score = 0.1

        # ---- EXPLANATION LOGIC ----
        checks = {
            "invalid": False,
            "suspicious_tld": tld_risk,
            "numeric_domain": numeric_risk == 1,
            "brand_risk": brand_risk == 1,
            "young_domain": domain_risk == 1,
            "html_intent": html_risk == 1,
            "ml_flag": ml_pred == 1
        }

        reasons = generate_reasons(url_value, checks)

        # ---- RISK DETAILS ----
        risk_details = {
            "ML Prediction": ml_pred,
            "Brand Risk": brand_risk,
            "Young Domain": domain_risk,
            "HTML Intent": html_risk,
            "Numeric Domain": numeric_risk,
            "Suspicious TLD": tld_risk,
            "Action Domain": action_risk,
            "Final Risk Score": final_risk_score
        }

    return render_template(
        "index.html",
        prediction=prediction,
        url_value=url_value,
        risk_details=risk_details,
        reasons=reasons
    )


# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)