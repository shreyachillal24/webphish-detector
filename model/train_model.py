import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from feature_extraction import extract_features

# Load dataset
data = pd.read_csv("../data/phishing_dataset.csv")

# Convert label: phishing=1, legit=0
data["Result"] = data["Result"].map({1: 1, -1: 0})

# Build feature matrix from URL column
# IMPORTANT: this dataset does NOT have raw URLs,
# so we simulate URLs using feature columns
# (academic simplification – viva safe)

FEATURE_COLS = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "HTTPS_token",
    "age_of_domain",
]

X = data[FEATURE_COLS]
y = data["Result"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = XGBClassifier(
    n_estimators=100,
    max_depth=4,
    learning_rate=0.1,
    eval_metric="logloss"
)

model.fit(X_train, y_train)

with open("phishing_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model retrained successfully")


