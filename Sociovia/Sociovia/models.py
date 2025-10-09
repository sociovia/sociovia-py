from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

class User(db.Model):
    __tablename__ = "users"
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(30))
    business_name = db.Column(db.String(255))
    industry = db.Column(db.String(120))
    password_hash = db.Column(db.String(256), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(32), default="pending_verification")  # pending_verification, under_review, approved, rejected
    verification_code_hash = db.Column(db.String(256))
    verification_expires_at = db.Column(db.DateTime)
    rejection_reason = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.email}>'

class Admin(db.Model):
    __tablename__ = "admins"
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_superadmin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<Admin {self.email}>'

class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    
    id = db.Column(db.Integer, primary_key=True)
    actor = db.Column(db.String(255))  # system, admin email, admin_link
    action = db.Column(db.String(64))  # user_signup, email_verified, moved_to_review, approved, rejected
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    meta = db.Column(db.Text)  # JSON string for additional data
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<AuditLog {self.action} by {self.actor}>'
class Workspace(db.Model):
    __tablename__ = "workspaces2"
    __table_args__ = {"extend_existing": True}   # temporary: allows redefinition during debugging

    id = db.Column(db.Integer, primary_key=True)
    # important: reference 'users.id' if your User __tablename__ == 'users'
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    business_name = db.Column(db.String(255), nullable=True)
    business_type = db.Column(db.String(100), nullable=True)
    registered_address = db.Column(db.String(500), nullable=True)
    b2b_b2c = db.Column(db.String(20), nullable=True)
    industry = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)
    audience_description = db.Column(db.Text, nullable=True)
    website = db.Column(db.String(255), nullable=True)
    competitor_direct_1 = db.Column(db.String(255), nullable=True)
    competitor_direct_2 = db.Column(db.String(255), nullable=True)
    competitor_indirect_1 = db.Column(db.String(255), nullable=True)
    competitor_indirect_2 = db.Column(db.String(255), nullable=True)
    social_links = db.Column(db.Text, nullable=True)  # JSON or CSV
    usp = db.Column(db.Text, nullable=True)
    logo_path = db.Column(db.String(500), nullable=True)
    creatives_path = db.Column(db.String(500), nullable=True)
    remarks = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = db.relationship("User", backref="workspaces2")
    
    
# models.py
class SocialAccount(db.Model):
    __tablename__ = "social_accounts"
    id = db.Column(db.Integer, primary_key=True)
    account_name = db.Column(db.String(255))
    provider = db.Column(db.String(50), nullable=False)  # 'facebook'
    scopes = db.Column(db.String(255)) 
    provider_user_id = db.Column(db.String(255), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    access_token = db.Column(db.Text, nullable=True)
    token_expires_at = db.Column(db.DateTime, nullable=True)
    profile = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())
