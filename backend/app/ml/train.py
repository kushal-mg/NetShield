import os
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score

def train_model(data_path="data/CICIDS2017_sample.csv", model_dir="backend/models"):
    print("Starting ML Model Training Pipeline...")
    
    # 1. Load data
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found at {data_path}. Please run generate_mock_dataset.py first.")
        
    df = pd.read_csv(data_path)
    print(f"Loaded dataset containing {df.shape[0]} rows and {df.shape[1]} columns.")
    
    # 2. Separate metadata columns, features, and target
    metadata_cols = ["Timestamp", "Source IP", "Source Port", "Destination IP"]
    target_col = "Label"
    
    X = df.drop(columns=metadata_cols + [target_col])
    y = df[target_col]
    
    # Clean any NaN or inf values just in case
    X = X.replace([float('inf'), float('-inf')], pd.NA)
    X = X.fillna(X.median())
    
    # 3. Label Encoding
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    # Save the encoder classes mapping for debug reference
    print("Label Mapping:")
    for code, label in enumerate(le.classes_):
        print(f"  {code} -> {label}")
        
    # 4. Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    
    # 5. Model Training (Random Forest)
    print("Training RandomForestClassifier...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    
    # 6. Evaluation
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nModel Accuracy on Test Split: {accuracy * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    
    # 7. Serialize and Save Artifacts
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "ids_model.pkl")
    encoder_path = os.path.join(model_dir, "label_encoder.pkl")
    
    joblib.dump(clf, model_path)
    joblib.dump(le, encoder_path)
    
    print(f"Successfully saved model to: {model_path}")
    print(f"Successfully saved label encoder to: {encoder_path}")
    print("ML training complete.")

if __name__ == "__main__":
    # Ensure working directory is correct
    train_model()
