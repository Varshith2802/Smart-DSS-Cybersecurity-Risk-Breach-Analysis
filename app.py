from flask import Flask, request, jsonify, redirect, render_template, make_response
from models import db, Vendor, User, AISRecord, AuditLog  # Ensure AuditLog is in models.py
import bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps
import csv
from io import StringIO
import json
import joblib
import numpy as np
from sqlalchemy.exc import IntegrityError
import requests

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'  # Replace with a strong key

db.init_app(app)
with app.app_context():
    db.create_all()

#########################################
# Helper: IP Geolocation via ipinfo.io
#########################################
def get_client_info():
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    location = "Unknown"
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.ok:
            data = response.json()
            city = data.get("city", "")
            country = data.get("country", "")
            location = f"{city}, {country}"
    except Exception as e:
        print("IP Geolocation error:", e)
    return ip, location, user_agent

#########################################
# Helper: Log Action
#########################################
def log_action(user, action, suspicious=False):
    ip, location, user_agent = get_client_info()
    log = AuditLog(user=user, action=action, ip_address=ip, location=location, user_agent=user_agent, suspicious=suspicious)
    db.session.add(log)
    db.session.commit()

#########################################
# Helper: Restricted Zone & Alert Check
#########################################
def is_in_restricted_zone(lat, lon):
    return 55.65 <= lat <= 55.70 and 12.55 <= lon <= 12.60

def check_alert(speed, lat, lon):
    return speed > 25 or is_in_restricted_zone(lat, lon)

#########################################
# Role-Based Access Decorator (used in select routes)
#########################################
def role_required(allowed_roles):
    def wrapper(f):
        @wraps(f)
        def decorated(current_user, *args, **kwargs):
            if current_user.role not in allowed_roles:
                return jsonify({'message': 'Access forbidden: insufficient permissions'}), 403
            return f(current_user, *args, **kwargs)
        return decorated
    return wrapper

#########################################
# Load ML Model and Metrics, and load class labels
#########################################
model = joblib.load('ml/vendor_risk_model.pkl')
label_decoder = ['Low', 'Medium', 'High']
try:
    with open('ml/metrics.json') as f:
        ml_metrics = json.load(f)
except Exception:
    ml_metrics = {"accuracy": 0, "precision": 0, "recall": 0, "f1_score": 0}
try:
    with open('ml/confusion_matrix.json') as f:
        confusion_matrix_data = json.load(f)
except Exception:
    confusion_matrix_data = []
try:
    with open('ml/classification_report.json') as f:
        ml_report = json.load(f)
except Exception:
    ml_report = {}
try:
    with open('ml/classes.json') as f:
        class_labels = json.load(f)
except Exception:
    class_labels = []

#########################################
# Helper: Calculate Risk Score
#########################################
def calculate_risk_score(vendor_data):
    risk = 0
    if vendor_data.get('software_assets'):
        risk += len(vendor_data['software_assets'].split(',')) * 1.5
    if vendor_data.get('cloud_assets'):
        risk += len(vendor_data['cloud_assets'].split(',')) * 2.5
    if vendor_data.get('industrial_assets'):
        risk += len(vendor_data['industrial_assets'].split(',')) * 4.5
    if vendor_data.get('ais_data'):
        risk += 6
    risk = round(risk, 2)
    if risk > 20:
        level = 'High'
    elif risk > 10:
        level = 'Medium'
    else:
        level = 'Low'
    return risk, level

#########################################
# Token Required Decorator (for selected routes)
#########################################
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
            current_user.role = data.get('role', 'Analyst')
        except Exception as e:
            print("JWT decode error:", e)
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

#########################################
# User Authentication Endpoints
#########################################
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'Analyst')
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User already exists'}), 400
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    new_user = User(username=username, password=hashed_password.decode('utf-8'), role=role)
    db.session.add(new_user)
    db.session.commit()
    log_action(username, "User registered")
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({'message': 'Invalid credentials'}), 401
    token = jwt.encode({
        'user_id': user.id,
        'role': user.role,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    log_action(username, "User login successful")
    return jsonify({'token': token})

#########################################
# Vendor CRUD Endpoints
# (Bulk upload support added later)
#########################################
@app.route('/vendors', methods=['POST'])
def add_vendor():
    # Now supports bulk upload if JSON payload is a list
    data = request.get_json()
    added = []
    errors = []
    
    # If a list is provided, process each vendor
    if isinstance(data, list):
        for vendor in data:
            required = ['name', 'software_assets', 'cloud_assets', 'industrial_assets']
            missing = [field for field in required if field not in vendor]
            if missing:
                errors.append({ "vendor": vendor.get("name", "Unknown"), "error": f"Missing fields: {missing}"})
                continue
            ais_data = vendor.get('ais_data', False)
            if vendor.get('use_ml', False):
                software_count = len(vendor['software_assets'].split(',')) if vendor['software_assets'] else 0
                cloud_count = len(vendor['cloud_assets'].split(',')) if vendor['cloud_assets'] else 0
                industrial_count = len(vendor['industrial_assets'].split(',')) if vendor['industrial_assets'] else 0
                ais_flag = 1 if ais_data else 0
                input_data = np.array([[software_count, cloud_count, industrial_count, ais_flag]])
                try:
                    prediction = model.predict(input_data)[0]
                    predicted_risk = label_decoder[prediction]
                    ml_risk_scores = {'Low': 5, 'Medium': 15, 'High': 25}
                    score = ml_risk_scores[predicted_risk]
                    level = predicted_risk
                except Exception as e:
                    errors.append({ "vendor": vendor.get("name", "Unknown"), "error": str(e)})
                    continue
            else:
                score, level = calculate_risk_score(vendor)
            try:
                new_vendor = Vendor(
                    name=vendor['name'],
                    software_assets=vendor['software_assets'],
                    cloud_assets=vendor['cloud_assets'],
                    industrial_assets=vendor['industrial_assets'],
                    ais_data=ais_data,
                    cybersecurity_score=score,
                    risk_level=level
                )
                db.session.add(new_vendor)
                added.append(vendor['name'])
            except Exception as e:
                errors.append({ "vendor": vendor.get("name", "Unknown"), "error": str(e)})
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({"message": "Error committing batch", "error": str(e)}), 500
        for name in added:
            log_action("User", f"Added vendor {name}")
        return jsonify({"message": f"{len(added)} vendors added successfully.", "added": added, "errors": errors}), 201
    else:
        # Single vendor upload
        required = ['name', 'software_assets', 'cloud_assets', 'industrial_assets']
        missing = [field for field in required if field not in data]
        if missing:
            return jsonify({'message': f'Missing fields: {missing}'}), 400
        ais_data = data.get('ais_data', False)
        if data.get('use_ml', False):
            software_count = len(data['software_assets'].split(',')) if data['software_assets'] else 0
            cloud_count = len(data['cloud_assets'].split(',')) if data['cloud_assets'] else 0
            industrial_count = len(data['industrial_assets'].split(',')) if data['industrial_assets'] else 0
            ais_flag = 1 if ais_data else 0
            input_data = np.array([[software_count, cloud_count, industrial_count, ais_flag]])
            prediction = model.predict(input_data)[0]
            predicted_risk = label_decoder[prediction]
            ml_risk_scores = {'Low': 5, 'Medium': 15, 'High': 25}
            score = ml_risk_scores[predicted_risk]
            level = predicted_risk
        else:
            score, level = calculate_risk_score(data)
        new_vendor = Vendor(
            name=data['name'],
            software_assets=data['software_assets'],
            cloud_assets=data['cloud_assets'],
            industrial_assets=data['industrial_assets'],
            ais_data=ais_data,
            cybersecurity_score=score,
            risk_level=level
        )
        db.session.add(new_vendor)
        db.session.commit()
        log_action("User", f"Added vendor {data['name']}")
        return jsonify({'message': 'New vendor added!', 'vendor_id': new_vendor.id}), 201

@app.route('/vendor/<int:vendor_id>', methods=['GET'])
def get_vendor(vendor_id):
    vendor = Vendor.query.filter_by(id=vendor_id).first()
    if not vendor:
        return jsonify({'message': 'Vendor not found'}), 404
    vendor_data = {
        'id': vendor.id,
        'name': vendor.name,
        'software_assets': vendor.software_assets,
        'cloud_assets': vendor.cloud_assets,
        'industrial_assets': vendor.industrial_assets,
        'ais_data': vendor.ais_data,
        'cybersecurity_score': vendor.cybersecurity_score,
        'risk_level': vendor.risk_level,
        'created_at': vendor.created_at
    }
    return jsonify({'vendor': vendor_data})

@app.route('/vendor/<int:vendor_id>', methods=['PUT'])
def update_vendor():
    data = request.get_json()
    vendor = Vendor.query.filter_by(id=data.get('id')).first()
    if not vendor:
        return jsonify({'message': 'Vendor not found'}), 404
    vendor.name = data.get('name', vendor.name)
    vendor.software_assets = data.get('software_assets', vendor.software_assets)
    vendor.cloud_assets = data.get('cloud_assets', vendor.cloud_assets)
    vendor.industrial_assets = data.get('industrial_assets', vendor.industrial_assets)
    vendor.ais_data = data.get('ais_data', vendor.ais_data)
    updated_data = {
        'software_assets': vendor.software_assets,
        'cloud_assets': vendor.cloud_assets,
        'industrial_assets': vendor.industrial_assets,
        'ais_data': vendor.ais_data
    }
    vendor.cybersecurity_score, new_level = calculate_risk_score(updated_data)
    vendor.risk_level = new_level
    db.session.commit()
    log_action("User", f"Updated vendor {vendor.name}")
    return jsonify({'message': 'Vendor updated successfully'})

@app.route('/vendor/<int:vendor_id>', methods=['DELETE'])
def delete_vendor(vendor_id):
    vendor = Vendor.query.filter_by(id=vendor_id).first()
    if not vendor:
        return jsonify({'message': 'Vendor not found'}), 404
    db.session.delete(vendor)
    db.session.commit()
    log_action("User", f"Deleted vendor {vendor.name}", suspicious=True)
    return jsonify({'message': 'Vendor deleted successfully'})

#########################################
# Export Endpoint (CSV)
#########################################
@app.route('/export/csv')
def export_csv():
    vendors = Vendor.query.order_by(Vendor.created_at.desc()).all()
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['ID', 'Name', 'Software', 'Cloud', 'Industrial', 'AIS', 'Score', 'Risk Level', 'Created At'])
    for v in vendors:
        writer.writerow([
            v.id, v.name, v.software_assets, v.cloud_assets, v.industrial_assets,
            'Yes' if v.ais_data else 'No',
            v.cybersecurity_score, v.risk_level, v.created_at
        ])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=vendors.csv"
    output.headers["Content-type"] = "text/csv"
    return output

#########################################
# Machine Learning Prediction Endpoint
#########################################
@app.route('/predict-risk', methods=['POST'])
def predict_risk():
    data = request.get_json()
    try:
        input_data = np.array([[ 
            int(data['software_count']),
            int(data['cloud_count']),
            int(data['industrial_count']),
            int(data['ais_data'])
        ]])
        prediction = model.predict(input_data)[0]
        risk_level = label_decoder[prediction]
        return jsonify({'predicted_risk': risk_level}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

#########################################
# AIS Data Integration & Alerts Endpoints
#########################################
@app.route('/load-ais-data')
def load_ais_data():
    try:
        with open('ais_data.json') as f:
            data = json.load(f)
    except Exception as e:
        return jsonify({'message': 'Error loading AIS data: ' + str(e)}), 500

    inserted = 0
    for entry in data:
        entry_timestamp = datetime.fromisoformat(entry['timestamp'])
        exists = AISRecord.query.filter_by(
            vessel_name=entry['vessel_name'],
            timestamp=entry_timestamp
        ).first()
        if exists:
            continue
        lat = entry['latitude']
        lon = entry['longitude']
        speed = entry['speed']
        alert_flag = check_alert(speed, lat, lon)
        entry['alert_flag'] = alert_flag
        ais = AISRecord(
            vessel_name=entry['vessel_name'],
            imo_number=entry.get('imo_number'),
            mmsi=entry.get('mmsi'),
            latitude=lat,
            longitude=lon,
            speed=speed,
            timestamp=entry_timestamp,
            alert_flag=alert_flag
        )
        db.session.add(ais)
        inserted += 1

    try:
        db.session.commit()
    except IntegrityError as e:
        db.session.rollback()
        return jsonify({'message': 'Integrity error: ' + str(e)}), 500
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error during commit: ' + str(e)}), 500

    log_action("System", f"Loaded AIS data, inserted {inserted} new record(s)")
    return jsonify({'message': f'AIS data loaded successfully! {inserted} new record(s) inserted.'})

@app.route('/ais-alerts')
def ais_alerts():
    alerts = AISRecord.query.filter_by(alert_flag=True).order_by(AISRecord.timestamp.desc()).all()
    output = []
    for a in alerts:
        output.append({
            'vessel_name': a.vessel_name,
            'latitude': a.latitude,
            'longitude': a.longitude,
            'speed': a.speed,
            'timestamp': a.timestamp.isoformat()
        })
    return jsonify({'ais_alerts': output})

#########################################
# Sample AIS Data Loader Route
#########################################
@app.route('/sample-ais-load', methods=['GET'])
def sample_ais_load():
    return redirect('/load-ais-data')

#########################################
# Audit Log Viewing (Admin Only)
#########################################
@app.route('/audit-logs')
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template("audit_logs.html", logs=logs)

#########################################
# Dashboard Route (HTML View)
#########################################
@app.route('/dashboard')
def dashboard():
    token = request.headers.get('x-access-token')
    user_role = "Guest"
    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user_role = data.get('role', "Guest")
        except Exception:
            user_role = "Guest"
    filter_risk = request.args.get('risk')
    if filter_risk:
        vendors = Vendor.query.filter_by(risk_level=filter_risk).order_by(Vendor.created_at.desc()).all()
    else:
        vendors = Vendor.query.order_by(Vendor.created_at.desc()).all()

    # For existing charts
    chart_labels = [v.name for v in vendors]
    chart_scores = [v.cybersecurity_score for v in vendors]

    # Risk Over Time: vendors sorted by creation date ascending
    vendors_over_time = Vendor.query.order_by(Vendor.created_at).all()
    risk_dates = [v.created_at.strftime('%Y-%m-%d') for v in vendors_over_time]
    risk_scores = [v.cybersecurity_score for v in vendors_over_time]

    # Risk Distribution: counts by risk level
    from sqlalchemy import func
    low_count = Vendor.query.filter_by(risk_level='Low').count()
    medium_count = Vendor.query.filter_by(risk_level='Medium').count()
    high_count = Vendor.query.filter_by(risk_level='High').count()
    risk_distribution_labels = ['Low', 'Medium', 'High']
    risk_distribution_values = [low_count, medium_count, high_count]

    # Top 5 High-Risk Vendors:
    top5 = Vendor.query.order_by(Vendor.cybersecurity_score.desc()).limit(5).all()
    top5_labels = [v.name for v in top5]
    top5_scores = [v.cybersecurity_score for v in top5]

    ais_alerts_list = AISRecord.query.filter_by(alert_flag=True).order_by(AISRecord.timestamp.desc()).all()
    ais_alerts_data = []
    for alert in ais_alerts_list:
        ais_alerts_data.append({
            'vessel_name': alert.vessel_name,
            'latitude': alert.latitude,
            'longitude': alert.longitude,
            'speed': alert.speed,
            'timestamp': alert.timestamp.isoformat()
        })

    return render_template("index.html", vendors=vendors, chart_labels=chart_labels, 
                           chart_scores=chart_scores, ml_metrics=ml_metrics,
                           ml_report=ml_report, confusion_matrix_data=confusion_matrix_data,
                           class_labels=class_labels,
                           user_role=user_role, ais_alerts=ais_alerts_data,
                           risk_dates=risk_dates, risk_scores=risk_scores,
                           risk_distribution_labels=risk_distribution_labels,
                           risk_distribution_values=risk_distribution_values,
                           top5_labels=top5_labels, top5_scores=top5_scores)

@app.route('/add-vendor', methods=['POST'])
def add_vendor_from_form():
    data = {
        'name': request.form['name'],
        'software_assets': request.form['software_assets'],
        'cloud_assets': request.form['cloud_assets'],
        'industrial_assets': request.form['industrial_assets'],
        'ais_data': 'ais_data' in request.form
    }
    use_ml = 'use_ml' in request.form
    if use_ml:
        software_count = len(data['software_assets'].split(',')) if data['software_assets'] else 0
        cloud_count = len(data['cloud_assets'].split(',')) if data['cloud_assets'] else 0
        industrial_count = len(data['industrial_assets'].split(',')) if data['industrial_assets'] else 0
        ais_flag = 1 if data['ais_data'] else 0
        input_data = np.array([[software_count, cloud_count, industrial_count, ais_flag]])
        prediction = model.predict(input_data)[0]
        predicted_risk = label_decoder[prediction]
        ml_risk_scores = {'Low': 5, 'Medium': 15, 'High': 25}
        score = ml_risk_scores[predicted_risk]
        level = predicted_risk
    else:
        score, level = calculate_risk_score(data)
    new_vendor = Vendor(
        name=data['name'],
        software_assets=data['software_assets'],
        cloud_assets=data['cloud_assets'],
        industrial_assets=data['industrial_assets'],
        ais_data=data['ais_data'],
        cybersecurity_score=score,
        risk_level=level
    )
    db.session.add(new_vendor)
    db.session.commit()
    log_action("User", f"Added vendor {data['name']}")
    return redirect('/dashboard')

#########################################
# Home Route
#########################################
@app.route('/')
def home():
    return "SDSS Port DSS - Backend API Running Successfully!"



# ---------------------------------------------------------
# ML Metrics API
# ---------------------------------------------------------
@app.route('/ml-metrics', methods=['GET'])
def ml_metrics_api():
    return jsonify({
        'metrics': ml_metrics,
        'confusion_matrix': confusion_matrix_data,
        'classification_report': ml_report,
        'class_labels': class_labels
    })

# ---------------------------------------------------------
# Risk Analytics Endpoint (for charts)
# ---------------------------------------------------------
@app.route('/risk-analytics', methods=['GET'])
def risk_analytics():
    from sqlalchemy import func
    risk_counts = db.session.query(
        Vendor.risk_level, func.count(Vendor.id)
    ).group_by(Vendor.risk_level).all()

    labels = [rc[0] for rc in risk_counts]
    values = [rc[1] for rc in risk_counts]

    return jsonify({'labels': labels, 'values': values})

# ---------------------------------------------------------
# Top Risky Vendors for Dashboard
# ---------------------------------------------------------
@app.route('/top-risky-vendors', methods=['GET'])
def top_risky_vendors():
    vendors = Vendor.query.order_by(Vendor.cybersecurity_score.desc()).limit(5).all()
    data = {
        'labels': [v.name for v in vendors],
        'scores': [v.cybersecurity_score for v in vendors]
    }
    return jsonify(data)

# ---------------------------------------------------------
# Export Audit Logs (JSON)
# ---------------------------------------------------------
@app.route('/export/logs', methods=['GET'])
def export_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    output = []
    for log in logs:
        output.append({
            'user': log.user,
            'action': log.action,
            'ip': log.ip_address,
            'location': log.location,
            'user_agent': log.user_agent,
            'timestamp': log.timestamp.isoformat(),
            'suspicious': log.suspicious
        })
    return jsonify(output)


if __name__ == '__main__':
    app.run(debug=True)
