from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

# Initialize the database instance
db = SQLAlchemy()

# Database Models

class Users(db.Model, UserMixin):
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(50), nullable=True)

    # Fix for 'AttributeError' related to datetime
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Correct usage of datetime
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    def get_id(self):
        return str(self.user_id)


# Model to log beneficiary verification events
class VerificationLog(db.Model):
    log_id = db.Column(db.Integer, primary_key=True)
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('beneficiary.beneficiary_id'), nullable=False)
    verified_by = db.Column(db.Integer, nullable=False)  # Added this column to track the verified_by field
    status = db.Column(db.String(50), nullable=False)  # Status of the verification ("Verified", "Pending", etc.)
    remarks = db.Column(db.String(255), nullable=True)  # Additional remarks/details about the verification
    verification_date = db.Column(db.DateTime, default=datetime.utcnow)  # Date of the verification

    # Relationship to Beneficiary
    beneficiary = db.relationship('Beneficiary', backref=db.backref('verification_logs', lazy=True))


class Admin(db.Model):
    admin_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), unique=True, nullable=False)
    department = db.Column(db.String(100), nullable=False)

# Fund model (with last_updated column)
class Fund(db.Model):
    fund_id = db.Column(db.Integer, primary_key=True)
    donor_name = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    allocated_to = db.Column(db.Integer, db.ForeignKey('admin.admin_id'), nullable=True)
    date_received = db.Column(db.DateTime, default=lambda: datetime.now(datetime.timezone.utc))  # Fixed datetime issue
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)  # Fixed datetime issue


class Beneficiary(db.Model):
    beneficiary_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), unique=True, nullable=False)
    impact_score = db.Column(db.Integer, nullable=True)
    nationalid = db.Column(db.String(50), unique=True, nullable=True)
    address = db.Column(db.String(100), nullable=True)
    verified = db.Column(db.Boolean, default=False)
    verification_date = db.Column(db.DateTime, nullable=True)
    disaster_id = db.Column(db.Integer, db.ForeignKey('disaster.disaster_id'), nullable=True)

    # Relationship to Users
    user = db.relationship('Users', backref=db.backref('beneficiary', uselist=False))


class Disaster(db.Model):
    disaster_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    location = db.Column(db.String(100))
    severity = db.Column(db.String(50))
    status = db.Column(db.String(50), default='active')  # Default status is 'active'

    # Use UTC for accurate timestamping
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Add created_at column
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow)  # Auto-updating timestamp on record update
    date_occurred = db.Column(db.DateTime, nullable=False)  # Required field, no default


    # Relationship to Beneficiaries
    beneficiaries = db.relationship('Beneficiary', backref='disaster', lazy=True)

    def __init__(self, name, description, location, severity, status, date_occurred):
        self.name = name
        self.description = description
        self.location = location
        self.severity = severity
        self.status = status
        self.created_at = created_at or datetime.utcnow()


# GIS Map model (using consistent column "coordinates")

class GisMap(db.Model):
    map_id = db.Column(db.Integer, primary_key=True)
    disaster_id = db.Column(db.Integer, db.ForeignKey('disaster.disaster_id'), nullable=False)
    coordinates = db.Column(db.String(100), nullable=False)  # Store as "[latitude, longitude]"
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Fixed datetime issue
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)  # Fixed datetime issue

    # Relationship to Disaster
    disaster = db.relationship('Disaster', backref=db.backref('gis_maps', lazy=True))


# Reports model (with relationship to Users for displaying the generator's name)
class Reports(db.Model):
    report_id = db.Column(db.Integer, primary_key=True)
    disaster_id = db.Column(db.Integer, db.ForeignKey('disaster.disaster_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)  # Fixed datetime issue
    format_type = db.Column(db.String(20), default="PDF")
    user = db.relationship('Users', backref=db.backref('reports', lazy=True))


# Aid Request model
class AidRequest(db.Model):
    request_id = db.Column(db.Integer, primary_key=True)
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('beneficiary.beneficiary_id'), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default='pending')
    amount = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Fixed datetime issue
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)  # Fixed datetime issue



# Chat Log Model
class ChatLog(db.Model):
    message_id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Fixed datetime issue

    # Relationships to get sender and receiver details
    sender = db.relationship('Users', foreign_keys=[sender_id], backref=db.backref('sent_messages', lazy=True))
    receiver = db.relationship('Users', foreign_keys=[receiver_id], backref=db.backref('received_messages', lazy=True))