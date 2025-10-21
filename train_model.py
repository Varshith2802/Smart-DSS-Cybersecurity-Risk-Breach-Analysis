import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from sklearn.preprocessing import LabelEncoder
import joblib
import json

# Load your training data (ensure risk_training_data.csv includes all risk levels)
df = pd.read_csv('risk_training_data.csv')

# If needed, convert columns to integer (or keep as is if numeric)
df['software_assets'] = df['software_assets'].astype(int)
df['cloud_assets'] = df['cloud_assets'].astype(int)
df['industrial_assets'] = df['industrial_assets'].astype(int)
df['ais_data'] = df['ais_data'].astype(int)

X = df[['software_assets', 'cloud_assets', 'industrial_assets', 'ais_data']]
y = df['risk_level']

# Encode risk level labels
le = LabelEncoder()
y_encoded = le.fit_transform(y)

# Split the dataset
X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

# Train the RandomForest model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, average='macro')
rec = recall_score(y_test, y_pred, average='macro')
f1 = f1_score(y_test, y_pred, average='macro')
cm = confusion_matrix(y_test, y_pred)
report = classification_report(y_test, y_pred, output_dict=True)

# Save the trained model and metrics
joblib.dump(model, 'ml/vendor_risk_model.pkl')
with open("ml/metrics.json", "w") as f:
    json.dump({"accuracy": acc, "precision": prec, "recall": rec, "f1_score": f1}, f)
with open("ml/confusion_matrix.json", "w") as f:
    json.dump(cm.tolist(), f)
with open("ml/classification_report.json", "w") as f:
    json.dump(report, f)

# Save the decoded class labels
classes = le.classes_.tolist()
with open("ml/classes.json", "w") as f:
    json.dump(classes, f)

print("Model training complete. Metrics and class labels saved.")
