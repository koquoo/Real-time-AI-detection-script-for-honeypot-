import time
import os
import json
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler

# --- Config ---
COWRIE_LOG_PATH = "/path/to/cowrie.json"  

# Load pre-trained models (make sure these .pkl files are in the same folder or give full path)
iso_model = joblib.load('iso_model.pkl')
svm_model = joblib.load('svm_model.pkl')
lof_model = joblib.load('lof_model.pkl')

# Required features & default values (fill missing features)
REQUIRED_COLUMNS = [
    'Source IP', 'Time Window Start', 'Connect Count', 'Login Failed Count',
    'Command Input Count', 'File Download Count', 'Total Events Count',
    'Unique DST Ports', 'Unique Usernames', 'Failed Login',
    'Average Session Duration', 'Malicious Command',
    'File Transfer', 'Successful Login'
]

DEFAULT_VALUES = {
    'Connect Count': 0,
    'Login Failed Count': 0,
    'Command Input Count': 0,
    'File Download Count': 0,
    'Total Events Count': 0,S
    'Unique DST Ports': 0,
    'Unique Usernames': 0,
    'Failed Login': 0,
    'Average Session Duration': 0.0,
    'Malicious Command': 0,
    'File Transfer': 0,
    'Successful Login': 0
}

def fill_missing_features(df):
    for col in REQUIRED_COLUMNS:
        if col not in df.columns:
            df[col] = DEFAULT_VALUES.get(col, 0)
    return df[REQUIRED_COLUMNS]

def extract_features_from_log():
    """
    This function should implement the logic to parse the cowrie.json logs,
    aggregate events per IP and time window, and return a DataFrame with features.
    
    For now, this is a placeholder.
    """
    # TODO: Implement the actual extraction logic based on your logs format.
    # You can reuse the feature extraction code you have, adjusted here.
    
    # Example:
    # return features_df
    
    # Placeholder empty DataFrame with required columns
    return pd.DataFrame(columns=REQUIRED_COLUMNS)

def main():
    print("Starting real-time anomaly detection...")
    try:
        while True:
            # Step 1: Extract features from latest logs
            features_df = extract_features_from_log()
            
            if features_df.empty:
                print("No data in this time window. Waiting for next cycle...")
                time.sleep(CHECK_INTERVAL_SECONDS)
                continue
            
            # Step 2: Fill missing columns with defaults
            features_df = fill_missing_features(features_df)
            
            # Step 3: Prepare data for model
            # Drop non-numeric columns like 'Source IP', 'Time Window Start' for prediction
            X = features_df.drop(columns=['Source IP', 'Time Window Start'], errors='ignore')
            
            # Scale features
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            
            # Step 4: Predict anomalies with all 3 models
            iso_preds = iso_model.predict(X_scaled)
            svm_preds = svm_model.predict(X_scaled)
            lof_preds = lof_model.predict(X_scaled)
            
            # Step 5: Combine predictions (-1 means anomaly)
            alerts = []
            for idx, ip in enumerate(features_df['Source IP']):
                votes = [iso_preds[idx], svm_preds[idx], lof_preds[idx]]
                final_anomaly = 1 if votes.count(-1) >= 2 else 0
                
                if final_anomaly == 1:
                    alerts.append((ip, features_df.iloc[idx]['Time Window Start'], votes))
            
            # Step 6: Print alerts
            if alerts:
                for ip, timestamp, votes in alerts:
                    print(f"🚨 ALERT: Anomaly detected from IP {ip} at {timestamp} | Model Votes: ISO={votes[0]}, SVM={votes[1]}, LOF={votes[2]}")
            else:
                print("No anomalies detected in this cycle.")
            
            # Wait before next check
            time.sleep(CHECK_INTERVAL_SECONDS)
            
    except KeyboardInterrupt:
        print("\nDetection stopped by user. Exiting cleanly.")

if __name__ == "__main__":
    main()
