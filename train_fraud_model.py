import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
import joblib

# Simulated dataset
data = {
    "amount": [50, 200, 5000, 15000, 30000, 700, 8000, 12000, 60, 45000, 1000, 23000],
    "is_fraud": [0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1]  # 1 = Fraud, 0 = Safe
}

df = pd.DataFrame(data)

# Features and target
X = df[["amount"]]
y = df["is_fraud"]

# Scale values (optional but helps model accuracy)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train simple logistic regression model
model = LogisticRegression()
model.fit(X_scaled, y)

# Save both model and scaler
joblib.dump(model, "fraud_model.pkl")
joblib.dump(scaler, "fraud_scaler.pkl")

print("✅ Model trained and saved as fraud_model.pkl and fraud_scaler.pkl")
