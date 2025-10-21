from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Vendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    software_assets = db.Column(db.String(250), nullable=True)
    cloud_assets = db.Column(db.String(250), nullable=True)
    industrial_assets = db.Column(db.String(250), nullable=True)
    ais_data = db.Column(db.Boolean, default=False)
    cybersecurity_score = db.Column(db.Float, default=0)
    risk_level = db.Column(db.String(50), default="Undefined")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(50), default="Analyst")  # Default role is Analyst
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AISRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vessel_name = db.Column(db.String(100), nullable=False)
    imo_number = db.Column(db.String(50))
    mmsi = db.Column(db.String(50))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    speed = db.Column(db.Float)
    timestamp = db.Column(db.DateTime)
    alert_flag = db.Column(db.Boolean, default=False)
    __table_args__ = (db.UniqueConstraint('vessel_name', 'timestamp', name='_vessel_timestamp_uc'),)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(100))
    action = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))
    location = db.Column(db.String(100))
    user_agent = db.Column(db.String(200))
    suspicious = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
