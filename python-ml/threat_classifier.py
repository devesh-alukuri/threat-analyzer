"""
Threat Classifier - ML-based network traffic classification
Uses Random Forest to classify threats into categories
Author: Devesh Alukuri
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import pickle
import os

THREAT_CLASSES = [
    "NORMAL", "PORT_SCAN", "BRUTE_FORCE",
    "DDOS", "SQL_INJECTION", "XSS", "MALWARE_TRAFFIC"
]

def generate_sample_data(n_samples=5000):
    """Generate synthetic network traffic data for training."""
    np.random.seed(42)
    data = []

    for _ in range(n_samples):
        threat_type = np.random.choice(THREAT_CLASSES, p=[0.4, 0.15, 0.15, 0.1, 0.1, 0.05, 0.05])

        if threat_type == "NORMAL":
            packet_size = np.random.randint(64, 1500)
            frequency = np.random.randint(1, 50)
            dest_port = np.random.choice([80, 443, 8080, 3000])
            entropy = np.random.uniform(3.0, 5.0)
            failed_attempts = 0

        elif threat_type == "PORT_SCAN":
            packet_size = np.random.randint(40, 100)
            frequency = np.random.randint(50, 200)
            dest_port = np.random.randint(1, 65535)
            entropy = np.random.uniform(1.0, 2.5)
            failed_attempts = np.random.randint(5, 20)

        elif threat_type == "BRUTE_FORCE":
            packet_size = np.random.randint(100, 400)
            frequency = np.random.randint(80, 300)
            dest_port = np.random.choice([22, 3389, 21, 23])
            entropy = np.random.uniform(2.0, 3.5)
            failed_attempts = np.random.randint(10, 100)

        elif threat_type == "DDOS":
            packet_size = np.random.randint(40, 200)
            frequency = np.random.randint(500, 5000)
            dest_port = np.random.choice([80, 443])
            entropy = np.random.uniform(0.5, 2.0)
            failed_attempts = np.random.randint(0, 5)

        elif threat_type == "SQL_INJECTION":
            packet_size = np.random.randint(200, 2000)
            frequency = np.random.randint(1, 30)
            dest_port = np.random.choice([80, 443, 8080])
            entropy = np.random.uniform(4.0, 6.0)
            failed_attempts = np.random.randint(0, 3)

        elif threat_type == "XSS":
            packet_size = np.random.randint(150, 1500)
            frequency = np.random.randint(1, 20)
            dest_port = np.random.choice([80, 443])
            entropy = np.random.uniform(3.5, 5.5)
            failed_attempts = 0

        else:  # MALWARE_TRAFFIC
            packet_size = np.random.randint(500, 3000)
            frequency = np.random.randint(10, 100)
            dest_port = np.random.randint(1024, 65535)
            entropy = np.random.uniform(5.0, 8.0)
            failed_attempts = np.random.randint(0, 5)

        data.append({
            "packet_size": packet_size,
            "frequency": frequency,
            "dest_port": dest_port,
            "entropy": round(entropy, 2),
            "failed_attempts": failed_attempts,
            "threat_type": threat_type
        })

    return pd.DataFrame(data)


def train_model():
    """Train the Random Forest classifier."""
    print("Generating training data...")
    df = generate_sample_data(5000)

    X = df[["packet_size", "frequency", "dest_port", "entropy", "failed_attempts"]]
    y = df["threat_type"]

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nModel Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    # Save model
    os.makedirs("models", exist_ok=True)
    with open("models/threat_classifier.pkl", "wb") as f:
        pickle.dump(model, f)
    with open("models/label_encoder.pkl", "wb") as f:
        pickle.dump(le, f)

    print("\nModel saved to models/threat_classifier.pkl")
    return model, le


def load_model():
    """Load the trained model."""
    with open("models/threat_classifier.pkl", "rb") as f:
        model = pickle.load(f)
    with open("models/label_encoder.pkl", "rb") as f:
        le = pickle.load(f)
    return model, le


def predict_threat(packet_size, frequency, dest_port, entropy, failed_attempts):
    """Predict threat type for given network features."""
    try:
        model, le = load_model()
    except FileNotFoundError:
        print("Model not found. Training new model...")
        model, le = train_model()

    features = np.array([[packet_size, frequency, dest_port, entropy, failed_attempts]])
    prediction = model.predict(features)[0]
    probabilities = model.predict_proba(features)[0]
    confidence = float(max(probabilities))
    threat_type = le.inverse_transform([prediction])[0]

    return {
        "threat_type": threat_type,
        "confidence": round(confidence, 4),
        "all_probabilities": dict(zip(le.classes_, [round(p, 4) for p in probabilities]))
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", action="store_true", help="Train the model")
    parser.add_argument("--predict", action="store_true", help="Run a sample prediction")
    args = parser.parse_args()

    if args.train:
        train_model()

    if args.predict:
        # Sample prediction
        result = predict_threat(
            packet_size=150,
            frequency=200,
            dest_port=22,
            entropy=2.5,
            failed_attempts=50
        )
        print(f"\nSample Prediction: {result}")
