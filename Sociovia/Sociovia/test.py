import os
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Union

from flask import Flask, request, jsonify, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv
from sqlalchemy.orm import DeclarativeBase
from flask_session import Session
from flask_cors import CORS, cross_origin

#from config import Config
"""
from config import Config

from models import db, User, Admin,SocialAccount  # make sure models.py exports User, Admin
from mailer import send_mail
from tokens import make_action_token, load_action_token
from utils import log_action, valid_password, generate_code, load_email_template
"""
from Sociovia.Sociovia.models import db, User, Admin,SocialAccount# make sure models.py exports User, Admin
from Sociovia.Sociovia.mailer import send_mail
from Sociovia.Sociovia.tokens import make_action_token, load_action_token
from Sociovia.Sociovia.utils import log_action, valid_password, generate_code, load_email_template      
#from config import Config



from datetime import timedelta
# config.py
from datetime import timedelta
import os
class Config:
    # Security
    # NOTE: For quick local testing you can hardcode, but DO NOT commit this file to any repo.
    SECRET_KEY = "change_me_super_secret_production_key"

    # Database (hardcoded sqlite file)
    SQLALCHEMY_DATABASE_URI = "postgresql://dbuser:StrongPasswordHere@34.10.193.3:5432/postgres"

    
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }

    # Email Configuration (HARDCODED - replace SMTP_PASS below)
    SMTP_HOST = "smtp.gmail.com"
    SMTP_PORT = 587
    SMTP_USER = "noreply.sociovia@gmail.com"
    SMTP_PASS = "hrgm qfdi ehky uyyz"  
    MAIL_FROM = "Sociovia <noreply.sociovia@gmail.com>"

    # Admin Configuration (hardcoded)
    ADMIN_EMAILS = ["sharan1114411@gmail.com"]

    # Application URLs
    APP_BASE_URL = "http://localhost:5000"
    FRONTEND_ORIGIN = "http://localhost:8080"

    # Timing Configuration
    VERIFY_TTL_MIN = 15
    ADMIN_LINK_TTL_HOURS = 48

    # Session lifetime (optional)
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
#==============================================================================================================================================================================================================
# ---------------- Setup ----------------

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sociovia")

class Base(DeclarativeBase):
    pass

app = Flask(__name__)
app.config.from_object(Config)

# Security key for sessions
app.secret_key = os.environ.get("SESSION_SECRET", app.config.get("SECRET_KEY", "dev-secret"))
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["ALLOW_REQUEST_USER_ID_FALLBACK"] = True  # [fix this in after session validation]

# ---------------- Session + CORS ----------------
FRONTEND_ORIGINS = [
     "https://sociovia-c9473.web.app",
    "https://sociovia.com",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:8080"
]

app.config.update(
    SESSION_TYPE="filesystem",              # use Redis in production
    SESSION_PERMANENT=False,
    SESSION_USE_SIGNER=True,
    SESSION_COOKIE_SAMESITE="None",         # allow cross-site cookies for dev; set to 'Lax' or 'Strict' in prod as appropriate
    SESSION_COOKIE_SECURE=False,              # True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7)
)
# OAuth / Facebook config — override with environment in production
FB_APP_ID = os.getenv("FB_APP_ID", "1782321995750055")
FB_APP_SECRET = os.getenv("FB_APP_SECRET", "f2e945de7d1ef2bfb2ce85699aead868")
FB_API_VERSION = os.getenv("FB_API_VERSION", "v16.0")
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://6136l5dn-5000.inc1.devtunnels.ms")
OAUTH_REDIRECT_BASE = os.getenv("OAUTH_REDIRECT_BASE", APP_BASE_URL)
# default scopes for facebook-first flow; instagram scopes will be requested later when linking IG
OAUTH_SCOPES = os.getenv("OAUTH_SCOPES", "pages_show_list,pages_read_engagement,ads_management")
Session(app)

app.config.setdefault("CORS_HEADERS", "Content-Type,Authorization,X-Requested-With,X-User-Id,X-User-Email")
""""
CORS(
    app,
    supports_credentials=True,
    resources={r"/*": {"origins": "*"}},
    allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-User-Id", "X-User-Email"],
    expose_headers=["Content-Type"],
)


CORS(
    app,
    resources={
        r"/api/*": {"origins": "*"},
        r"/outputs/*": {"origins": "*"},
    },
    supports_credentials=False,
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With", "Accept"],
)
# Update your CORS settings to include the specific endpoints
CORS(
    app,
    supports_credentials=True,
    resources={
        r"/api/*": {
            "origins": FRONTEND_ORIGINS,
            "allow_headers": ["Content-Type", "Authorization", "X-Requested-With", "X-User-Id", "X-User-Email"],
            "expose_headers": ["Content-Type"]
        }
    }
)
"""
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": FRONTEND_ORIGINS,
            "allow_headers": ["Content-Type", "Authorization", "X-Requested-With", "X-User-Id", "X-User-Email"],
            "expose_headers": ["Content-Type"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "supports_credentials": True
        },
        r"/outputs/*": {
            "origins": "*",
            "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "supports_credentials": False
        }
    }
)
# ---------------- DB Init ----------------
db.init_app(app)
with app.app_context():
    db.create_all()
    # Create default admin if none exists (override with env vars in production)
    if not Admin.query.first():
        admin_email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@sociovia.com")
        admin_pass = os.getenv("DEFAULT_ADMIN_PASS", "admin123")
        admin = Admin(
            email=admin_email,
            password_hash=generate_password_hash(admin_pass),
            is_superadmin=True
        )
        db.session.add(admin)
        db.session.commit()
        logger.info(f"Created default admin: {admin_email} / {admin_pass}")

# ---------------- Helpers ----------------
def parse_admin_emails(value: Union[str, List[str], None]) -> List[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [e.strip() for e in value if e and e.strip()]
    return [e.strip() for e in str(value).split(",") if e.strip()]


def send_mail_to(recipient: Union[str, List[str]], subject: str, body: str) -> None:
    if isinstance(recipient, (list, tuple)):
        for r in recipient:
            try:
                send_mail(r, subject, body)
            except Exception:
                logger.exception("Failed to send mail to %s", r)
    else:
        try:
            send_mail(recipient, subject, body)
        except Exception:
            logger.exception("Failed to send mail to %s", recipient)


def serialize_user(u: User) -> Dict[str, Any]:
    return {
        "id": u.id,
        "name": u.name,
        "email": u.email,
        "phone": u.phone,
        "business_name": u.business_name,
        "industry": u.industry,
        "status": u.status,
        "email_verified": bool(u.email_verified),
        "created_at": u.created_at.isoformat() if hasattr(u, "created_at") and u.created_at else None,
        "rejection_reason": getattr(u, "rejection_reason", None),
    }


def require_admin_session():
    admin_id = session.get("admin_id")
    if not admin_id:
        abort(401, description="admin_not_authenticated")
    admin = Admin.query.get(admin_id)
    if not admin:
        abort(401, description="admin_not_found")
    return admin

# Config helpers
VERIFY_TTL_MIN = int(app.config.get("VERIFY_TTL_MIN", os.getenv("VERIFY_TTL_MIN", 15)))
ADMIN_LINK_TTL_HOURS = int(app.config.get("ADMIN_LINK_TTL_HOURS", os.getenv("ADMIN_LINK_TTL_HOURS", 48)))
APP_BASE_URL = "https://sociovia-py.onrender.com"

# ---------------- Public APIs ----------------
@app.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    phone = (data.get("phone") or "").strip()
    business_name = (data.get("business_name") or "").strip()
    industry = (data.get("industry") or "").strip()
    password = data.get("password") or ""

    errors = []
    if not name:
        errors.append("Name is required")
    if not email:
        errors.append("Email is required")
    else:
        try:
            validate_email(email)
        except EmailNotValidError:
            errors.append("Invalid email format")
    if not valid_password(password):
        errors.append("Password must be at least 8 characters")
    if not business_name:
        errors.append("Business name is required")
    if email and User.query.filter_by(email=email).first():
        errors.append("Email already registered")

    if errors:
        return jsonify({"success": False, "errors": errors}), 400

    verification_code = generate_code()
    user = User(
        name=name,
        email=email,
        phone=phone,
        business_name=business_name,
        industry=industry,
        password_hash=generate_password_hash(password),
        verification_code_hash=generate_password_hash(verification_code),
        verification_expires_at=datetime.utcnow() + timedelta(minutes=VERIFY_TTL_MIN),
        status="pending_verification",
    )
    db.session.add(user)
    db.session.commit()
    log_action("system", "user_signup", user.id, {"email": email})

    try:
        email_body = load_email_template("user_verify.txt", {"name": name, "code": verification_code})
        send_mail_to(email, "Verify your Sociovia account", email_body)
    except Exception:
        logger.exception("Failed to send verification email")

    return jsonify({"success": True, "message": "Signup successful. Check your email for verification code."}), 201


@app.route("/api/verify-email", methods=["POST"])
def api_verify_email():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    code = (data.get("code") or "").strip()

    if not email or not code:
        return jsonify({"success": False, "error": "Email and code required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 404

    if user.email_verified:
        return jsonify({"success": True, "message": "Already verified", "status": user.status}), 200

    if not user.verification_code_hash or user.verification_expires_at < datetime.utcnow():
        return jsonify({"success": False, "error": "Verification expired"}), 400

    if not check_password_hash(user.verification_code_hash, code):
        return jsonify({"success": False, "error": "Invalid code"}), 400

    user.email_verified = True
    user.status = "under_review"
    user.verification_code_hash = None
    user.verification_expires_at = None
    db.session.commit()
    log_action("system", "email_verified", user.id)
    log_action("system", "moved_to_review", user.id)

    # Notify admins
    try:
        admin_list = parse_admin_emails(app.config.get("ADMIN_EMAILS", os.getenv("ADMIN_EMAILS", "")))
        if admin_list:
            approve_token = make_action_token({"user_id": user.id, "action": "approve", "issued_at": datetime.utcnow().isoformat()})
            reject_token = make_action_token({"user_id": user.id, "action": "reject", "issued_at": datetime.utcnow().isoformat()})
            email_body = load_email_template("admin_notify.txt", {
                "name": user.name,
                "email": user.email,
                "business_name": user.business_name,
                "industry": user.industry,
                "approve_url": f"{APP_BASE_URL}/admin/action?token={approve_token}",
                "reject_url": f"{APP_BASE_URL}/admin/action?token={reject_token}"
            })
            send_mail_to(admin_list, f"New account to review – {user.business_name}", email_body)
    except Exception:
        logger.exception("Failed to notify admins")

    return jsonify({"success": True, "message": "Email verified. Account under review.", "status": user.status}), 200


@app.route("/api/resend-code", methods=["POST"])
def api_resend_code():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"success": False, "error": "email_required"}), 400
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": False, "error": "user_not_found"}), 404
    if user.email_verified:
        return jsonify({"success": True, "message": "already_verified"}), 200

    verification_code = generate_code()
    user.verification_code_hash = generate_password_hash(verification_code)
    user.verification_expires_at = datetime.utcnow() + timedelta(minutes=VERIFY_TTL_MIN)
    db.session.commit()

    try:
        email_body = load_email_template("user_verify.txt", {"name": user.name, "code": verification_code})
        send_mail_to(user.email, "Verify your Sociovia account", email_body)
    except Exception:
        logger.exception("Failed to send verification email")
        return jsonify({"success": False, "error": "email_failed"}), 500

    return jsonify({"success": True, "message": "code_sent"}), 200


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"success": False, "error": "Invalid credentials"}), 401
    if user.status in ["pending_verification", "under_review", "rejected"]:
        return jsonify({"success": False, "status": user.status, "error": "not_approved"}), 403

    session['user_id'] = user.id
    return jsonify({"success": True, "message": "Login successful", "user": {"id": user.id, "name": user.name}}), 200


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.pop('user_id', None)
    return jsonify({"success": True, "message": "Logged out"}), 200


@app.route("/api/status")
def api_status():
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "email required"}), 400
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "user not found"}), 404
    return jsonify({"status": user.status}), 200

# ---------------- Admin APIs ----------------
ADMIN_EMAIL = "admin@sociovia.com"
ADMIN_PASSWORD = "admin123"


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Invalid credentials"}), 401


@app.route("/api/admin/review", methods=["POST"])
def admin_review():
    """Fetch pending users - requires admin credentials in body"""
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if email != ADMIN_EMAIL or password != ADMIN_PASSWORD:
        return jsonify({"success": False, "error": "Not authenticated"}), 401

    users = (
        User.query.filter_by(status="under_review")
        .order_by(User.created_at.desc())
        .all()
    )

    user_list = [
        {
            "id": u.id,
            "name": u.name,
            "email": u.email,
            "phone": u.phone,
            "business_name": u.business_name,
            "industry": u.industry,
            "created_at": u.created_at.isoformat(),
            "status": u.status,
        }
        for u in users
    ]

    return jsonify({"success": True, "users": user_list})



@app.route("/api/admin/logout", methods=["POST"])
def api_admin_logout():
    session.pop('admin_id', None)
    return jsonify({"success": True, "message": "admin_logged_out"}), 200
    """_summary_

    Returns:
        _type_: _description_
        
        @app.route("/api/admin/review", methods=["GET"])
def api_admin_review():
    try:
        admin = require_admin_session()
    except Exception:
        return jsonify({"success": False, "error": "admin_not_authenticated"}), 401

    users = User.query.filter_by(status="under_review").order_by(User.created_at.desc()).all()
    return jsonify({"success": True, "users": [serialize_user(u) for u in users]}), 200

    """
 
""
 

@app.route("/api/admin/approve/<int:user_id>", methods=["POST"])
def api_admin_approve(user_id: int):
    

    user = User.query.get_or_404(user_id)
    if user.status != "under_review":
        return jsonify({"success": False, "error": "user_not_in_review"}), 400

    user.status = "approved"
    db.session.commit()
    log_action("sharan1114411@gmail.com", "approved", user.id)

    try:
        email_body = load_email_template("user_approved.txt", {"name": user.name})
        send_mail_to(user.email, "Your Sociovia account is approved", email_body)
    except Exception:
        logger.exception("Failed to send approval email")

    return jsonify({"success": True, "message": f"user_{user.id}_approved"}), 200


@app.route("/api/admin/reject/<int:user_id>", methods=["POST"])
def api_admin_reject(user_id: int):
   

    data = request.get_json() or {}
    reason = (data.get("reason") or "").strip()
    if not reason:
        return jsonify({"success": False, "error": "rejection_reason_required"}), 400

    user = User.query.get_or_404(user_id)
    if user.status != "under_review":
        return jsonify({"success": False, "error": "user_not_in_review"}), 400

    user.status = "rejected"
    user.rejection_reason = reason
    db.session.commit()
    log_action(admin.email, "rejected", user.id, {"reason": reason})

    try:
        email_body = load_email_template("user_rejected.txt", {"name": user.name, "reason": reason})
        send_mail_to(user.email, "Update on your Sociovia account", email_body)
    except Exception:
        logger.exception("Failed to send rejection email")

    return jsonify({"success": True, "message": f"user_{user.id}_rejected"}), 200


from flask import redirect, render_template_string

from urllib.parse import unquote, urlencode
from flask import redirect, render_template_string

@app.route("/admin/action", methods=["GET"])
def api_admin_action():
    token = request.args.get("token")
    if not token:
        logger.warning("admin action hit with no token")
        return jsonify({"success": False, "error": "token_required"}), 400

    # Log origin + DB URI for debugging (remove in prod)
    logger.info("admin action request from=%s db=%s", request.remote_addr, app.config.get("SQLALCHEMY_DATABASE_URI"))

    try:
        # Try unquoting if email client double-encoded
        try:
            payload = load_action_token(unquote(token), ADMIN_LINK_TTL_HOURS * 3600)
        except Exception:
            payload = load_action_token(token, ADMIN_LINK_TTL_HOURS * 3600)

        logger.info("admin link payload: %s", payload)
        user_id = payload.get("user_id")
        action = payload.get("action")
        reason = payload.get("reason", "Rejected via admin link")

        # Safer lookup (no immediate abort)
        user = User.query.filter_by(id=user_id).first()
        if not user:
            # log all known user ids to help debug
            try:
                ids = [u.id for u in User.query.with_entities(User.id).all()]
            except Exception:
                ids = "<couldn't fetch ids>"
            logger.warning("admin link: user id %s not found. existing_user_ids=%s", user_id, ids)
            return render_template_string(
                "<h3>Invalid admin link</h3><p>User not found. Contact support.</p>"
            ), 400

        if user.status != "under_review":
            return render_template_string(
                "<h3>Action not allowed</h3><p>User status: {{status}}</p>",
                status=user.status
            ), 400

        if action == "approve":
            user.status = "approved"
            db.session.commit()
            log_action("admin_link", "approved", user.id)
            try:
                email_body = load_email_template("user_approved.txt", {"name": user.name})
                send_mail_to(user.email, "Your Sociovia account is approved", email_body)
            except Exception:
                logger.exception("Failed to send approval email (admin link)")
            return redirect(f"{APP_BASE_URL.rstrip('/')}/admin/complete?status=approved&uid={user.id}")

        if action == "reject":
            user.status = "rejected"
            user.rejection_reason = reason
            db.session.commit()
            log_action("admin_link", "rejected", user.id, {"reason": reason})
            try:
                email_body = load_email_template("user_rejected.txt", {"name": user.name, "reason": reason})
                send_mail_to(user.email, "Update on your Sociovia account", email_body)
            except Exception:
                logger.exception("Failed to send rejection email (admin link)")
            return redirect(f"{APP_BASE_URL.rstrip('/')}/admin/complete?status=rejected&uid={user.id}")

        return render_template_string("<h3>Invalid action</h3>"), 400

    except Exception as e:
        logger.exception("Token validation failed: %s", e)
        return render_template_string("<h3>Invalid or expired admin link</h3><p>Please contact support.</p>"), 400
# ---------------- Workspace Model + Routes ----------------
import os
from werkzeug.utils import secure_filename
from flask import send_from_directory

# Allowed file extensions for uploads
ALLOWED_IMAGE_EXTS = {"png", "jpg", "jpeg", "svg", "webp", "gif"}
UPLOAD_BASE = os.path.join(os.getcwd(), "uploads", "workspaces")  # e.g. ./uploads/workspaces/<user_id>/

# Create uploads base directory if missing
os.makedirs(UPLOAD_BASE, exist_ok=True)
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

    




def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTS


@app.route("/uploads/workspaces/<int:user_id>/<path:filename>")
def serve_workspace_upload(user_id: int, filename: str):
    """
    Serve uploaded workspace files. In production use a proper static file server.
    """
    directory = os.path.join(UPLOAD_BASE, str(user_id))
    return send_from_directory(directory, filename, as_attachment=False)
# ---------------- Helpers (add this helper) ----------------
def get_user_from_request(require: bool = True):
    """
    Resolve a User from the incoming request.
    Resolution order:
      1) session['user_id']
      2) X-User-Id header
      3) user_id query param or form field
      4) X-User-Email header
      5) email query param or form field
    Returns User instance or None.
    """
    def _get_user_by_id_safe(uid):
        try:
            if uid is None:
                return None
            # ensure int
            uid_int = int(uid)
        except Exception:
            return None
        # prefer db.session.get for SQLAlchemy 1.4+/2.0
        try:
            return db.session.get(User, uid_int)
        except Exception:
            # fallback for older SQLAlchemy versions
            try:
                return User.query.get(uid_int)
            except Exception:
                return None

    # 1) session
    user_id = session.get("user_id")
    u = _get_user_by_id_safe(user_id)
    if u:
        return u

    # 2) X-User-Id header
    uid = request.headers.get("X-User-Id")
    u = _get_user_by_id_safe(uid)
    if u:
        return u

    # 3) user_id param/form
    uid = request.args.get("user_id") or (request.form.get("user_id") if request.form else None)
    u = _get_user_by_id_safe(uid)
    if u:
        return u

    # 4) X-User-Email header
    email = request.headers.get("X-User-Email")
    if email:
        try:
            norm = str(email).strip().lower()
            u = User.query.filter_by(email=norm).first()
            if u:
                return u
        except Exception:
            pass

    # 5) email query/form
    email = request.args.get("email") or (request.form.get("email") if request.form else None)
    if email:
        try:
            norm = str(email).strip().lower()
            u = User.query.filter_by(email=norm).first()
            if u:
                return u
        except Exception:
            pass

    return None if require else None

from flask import request, jsonify
import os, json

@app.route("/api/workspace/setup", methods=["POST"])
def api_workspace_setup_create():
    """
    Create a new workspace (multipart/form-data). Always creates a NEW workspace record.
    """
    try:
        user = get_user_from_request(require=True)
        print(user)
        if not user:
            return jsonify({"success": False, "error": "not_authenticated"}), 401
        user_id = user.id

        if not request.content_type or "multipart/form-data" not in request.content_type:
            return jsonify({"success": False, "error": "content_type_must_be_multipart"}), 415

        form = request.form
        # Accept either shape for descriptions (compatibility)
        description = (form.get("describe_business") or form.get("description") or "").strip()
        audience_description = (form.get("describe_audience") or form.get("audience_description") or "").strip()

        business_name = (form.get("business_name") or "").strip()
        business_type = (form.get("business_type") or "").strip()
        registered_address = (form.get("registered_address") or "").strip()
        b2b_b2c = (form.get("b2b_b2c") or "").strip().upper()
        industry = (form.get("industry") or "").strip()
        website = (form.get("website") or "").strip()
        direct_competitors_raw = (form.get("direct_competitors") or "").strip()
        indirect_competitors_raw = (form.get("indirect_competitors") or "").strip()
        social_links_raw = (form.get("social_links") or "").strip()
        usp = (form.get("usp") or "").strip()
        additional_remarks = (form.get("additional_remarks") or "").strip()

        logo_file = request.files.get("logo")
        creatives_files = request.files.getlist("creatives")

        # --- parsing helpers (preserve name + website) ---
        def parse_competitors(raw: str):
            raw = (raw or "").strip()
            if not raw:
                return []
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    out = []
                    for item in parsed:
                        if isinstance(item, dict):
                            name = str(item.get("name") or "").strip()
                            # accept website or url keys
                            website = (item.get("website") or item.get("url") or "").strip() or None
                            if name:
                                out.append({"name": name, "website": website})
                        else:
                            s = str(item).strip()
                            if s:
                                out.append({"name": s, "website": None})
                    return out
            except Exception:
                pass
            # fallback: comma separated names (no websites)
            parts = [p.strip() for p in raw.split(",") if p.strip()]
            return [{"name": p, "website": None} for p in parts]

        def parse_social_links(raw: str):
            raw = (raw or "").strip()
            if not raw:
                return []
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    out = []
                    for item in parsed:
                        if isinstance(item, dict):
                            platform = (item.get("platform") or item.get("name") or "").strip() or None
                            url = (item.get("url") or item.get("link") or "").strip() or None
                            if platform or url:
                                out.append({"platform": platform, "url": url})
                        else:
                            s = str(item).strip()
                            if s:
                                out.append({"platform": None, "url": s})
                    return out
            except Exception:
                pass
            parts = [p.strip() for p in raw.split(",") if p.strip()]
            return [{"platform": None, "url": p} for p in parts]

        direct_competitors = parse_competitors(direct_competitors_raw)
        indirect_competitors = parse_competitors(indirect_competitors_raw)
        social_links = parse_social_links(social_links_raw)

        # --- validation ---
        errors = []
        if not business_name:
            errors.append("business_name_required")
        if business_type not in ["Pvt Ltd", "Sole Proprietorship", "Partnership", "Public"]:
            errors.append("invalid_business_type")
        if not registered_address:
            errors.append("registered_address_required")
        if b2b_b2c not in ["B2B", "B2C"]:
            errors.append("invalid_b2b_b2c")
        if not industry:
            errors.append("industry_required")
        if len(description) < 100:
            errors.append("describe_business_min_100")
        if len(audience_description) < 100:
            errors.append("describe_audience_min_100")
        if not usp:
            errors.append("usp_required")
        if not logo_file:
            errors.append("logo_required")
        elif not allowed_file(logo_file.filename):
            errors.append("logo_invalid_file_type")
        if len(direct_competitors) < 2:
            errors.append("direct_competitors_min_2")
        if len(indirect_competitors) < 2:
            errors.append("indirect_competitors_min_2")

        if errors:
            return jsonify({"success": False, "errors": errors}), 400

        # --- persist files ---
        user_upload_dir = os.path.join(UPLOAD_BASE, str(user_id))
        os.makedirs(user_upload_dir, exist_ok=True)

        logo_filename = secure_filename(logo_file.filename)
        logo_abs_name = "logo_" + logo_filename
        logo_abs_path = os.path.join(user_upload_dir, logo_abs_name)
        logo_file.save(logo_abs_path)
        logo_path_rel = os.path.join(str(user_id), logo_abs_name).replace(os.path.sep, "/")

        creatives_paths = []
        for idx, f in enumerate(creatives_files or []):
            if not f or not f.filename:
                continue
            if not allowed_file(f.filename):
                continue
            safe = secure_filename(f.filename)
            abs_name = f"creative_{idx}_{safe}"
            abs_path = os.path.join(user_upload_dir, abs_name)
            f.save(abs_path)
            creatives_paths.append(os.path.join(str(user_id), abs_name).replace(os.path.sep, "/"))

        # --- CREATE a NEW workspace (do NOT override existing) ---
        import json as _json
        workspace = Workspace(user_id=user_id)  # ALWAYS new
        workspace.business_name = business_name
        workspace.business_type = business_type
        workspace.registered_address = registered_address
        workspace.b2b_b2c = b2b_b2c
        workspace.industry = industry
        # map to DB columns used in your snapshot
        workspace.description = description
        workspace.audience_description = audience_description
        workspace.website = website or None
        workspace.direct_competitors = _json.dumps(direct_competitors)  # structured JSON with website preserved
        workspace.indirect_competitors = _json.dumps(indirect_competitors)
        workspace.social_links = _json.dumps(social_links)
        workspace.usp = usp
        workspace.logo_path = logo_path_rel
        workspace.creatives_paths = _json.dumps(creatives_paths)
        workspace.additional_remarks = additional_remarks or None

        db.session.add(workspace)
        db.session.commit()

        logo_url = f"{APP_BASE_URL.rstrip('/')}/uploads/workspaces/{workspace.user_id}/{os.path.basename(logo_abs_path)}"
        creative_urls = [
            f"{APP_BASE_URL.rstrip('/')}/uploads/workspaces/{workspace.user_id}/{os.path.basename(p)}"
            for p in creatives_paths
        ]

        log_action(user.email or "system", "workspace_create", user.id, {"workspace_id": workspace.id})

        return jsonify({
            "success": True,
            "message": "workspace_created",
            "workspace": {
                "id": workspace.id,
                "user_id": workspace.user_id,
                "business_name": workspace.business_name,
                "description": workspace.description,
                "audience_description": workspace.audience_description,
                "website": workspace.website,
                "direct_competitors": direct_competitors,
                "indirect_competitors": indirect_competitors,
                "social_links": social_links,
                "usp": workspace.usp,
                "logo_url": logo_url,
                "creative_urls": creative_urls,
            }
        }), 201

    except Exception as e:
        logger.exception("Workspace create failed")
        return jsonify({"success": False, "error": "internal_server_error", "details": str(e)}), 500

def allowed_file(filename):
    """Check if file extension is allowed."""
    allowed_extensions = {'.png', '.jpg', '.jpeg', '.gif'}
    return os.path.splitext(filename)[1].lower() in allowed_extensions
# put near top of file for consistent usage
UPLOAD_BASE = os.getenv("UPLOAD_BASE", "uploads")
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://6136l5dn-5000.inc1.devtunnels.ms").rstrip('/')

# update endpoint
class Generation(db.Model):
    __tablename__ = 'conversations'
    
    id = db.Column(db.String(32), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspaces.id'), nullable=True)
    prompt = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Generation {self.id}>'

from flask import jsonify, request
from flask_cors import cross_origin
from datetime import datetime
import os
import json
from werkzeug.utils import secure_filename
import logging

from flask import jsonify, request
from flask_cors import cross_origin
from datetime import datetime
import os
import json
from werkzeug.utils import secure_filename
import logging

logger = logging.getLogger(__name__)


@app.route('/api/workspace/<int:workspace_id>', methods=['PUT','GET','OPTIONS'])
@cross_origin(
    origins=os.getenv('FRONTEND_ORIGINS', '*').split(','),
    methods=['GET','PUT','OPTIONS'],
    allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 'X-User-Id', 'X-User-Email'],
    expose_headers=['Content-Type'],
    supports_credentials=True
)
def api_workspace(workspace_id):
    logger.info(f"Request to /api/workspace/{workspace_id} with method {request.method}")
    try:
        user = get_user_from_request(require=True)
        if not user:
            logger.warning("Authentication failed")
            return jsonify({"success": False, "error": "not_authenticated"}), 401

        # Use authenticated user.id — don't trust user_id query param
        workspace = Workspace.query.filter_by(id=workspace_id, user_id=user.id).first()
        if not workspace:
            logger.warning(f"Workspace {workspace_id} not found or forbidden for user {user.id}")
            # either not found or not owned by this user
            return jsonify({"success": False, "error": "not_found_or_forbidden"}), 404

        if request.method == 'GET':
            # Fetch generations (conversations)
            generations = Generation.query.filter_by(workspace_id=workspace_id).order_by(Generation.created_at.desc()).all()
            generations_data = [
                {
                    "id": g.id,
                    "prompt": g.prompt,
                    "response": g.response,
                    "created_at": g.created_at.isoformat() if g.created_at else None
                } for g in generations
            ]
            logger.info(f"Fetched {len(generations_data)} generations for workspace {workspace_id}")

            # Fetch creatives
            creatives = Creative.query.filter_by(workspace_id=workspace_id).order_by(Creative.created_at.desc()).all()
            creatives_data = [
                {
                    "id": c.id,
                    "filename": c.filename,
                    "url": c.url,
                    "type": c.type,
                    "created_at": c.created_at.isoformat() if c.created_at else None,
                    "user_id": c.user_id,
                    "workspace_id": c.workspace_id
                } for c in creatives
            ]
            logger.info(f"Fetched {len(creatives_data)} creatives for workspace {workspace_id}")

            logo_url = None
            if workspace.logo_path:
                logo_url = f"{APP_BASE_URL}/uploads/{workspace.logo_path}"

            return jsonify({
                "success": True,
                "workspace": {
                    "id": workspace.id,
                    "user_id": workspace.user_id,
                    "business_name": workspace.business_name,
                    "business_type": workspace.business_type,
                    "registered_address": workspace.registered_address,
                    "b2b_b2c": workspace.b2b_b2c,
                    "industry": workspace.industry,
                    "description": workspace.description,
                    "audience_description": workspace.audience_description,
                    "website": workspace.website,
                    "competitor_direct_1": workspace.competitor_direct_1,
                    "competitor_direct_2": workspace.competitor_direct_2,
                    "competitor_indirect_1": workspace.competitor_indirect_1,
                    "competitor_indirect_2": workspace.competitor_indirect_2,
                    "social_links": workspace.social_links,
                    "usp": workspace.usp,
                    "logo_path": logo_url,
                    "creatives_path": workspace.creatives_path,
                    "remarks": workspace.remarks,
                    "created_at": workspace.created_at.isoformat() if workspace.created_at else None,
                    "updated_at": workspace.updated_at.isoformat() if workspace.updated_at else None
                },
                "creatives": creatives_data,
                "conversations": generations_data
            }), 200

        # Only owner may update (we already filtered by user.id)
        # Handle multipart/form-data
        # request.mimetype is safer for checking
        if request.mimetype and "multipart/form-data" in request.mimetype:
            form = request.form.to_dict()
            logo_file = request.files.get("logo")
        else:
            logger.warning("Invalid content type for update")
            return jsonify({"success": False, "error": "invalid_content_type", "details": "Expected multipart/form-data"}), 400

        fields = [
            'business_name', 'business_type', 'registered_address', 'b2b_b2c',
            'industry', 'description', 'audience_description', 'website',
            'competitor_direct_1', 'competitor_direct_2', 'competitor_indirect_1',
            'competitor_indirect_2', 'social_links', 'usp', 'creatives_path', 'remarks'
        ]
        for field in fields:
            if field in form and form[field] is not None:
                if field == 'social_links':
                    try:
                        json.loads(form[field])
                        setattr(workspace, field, form[field])
                    except json.JSONDecodeError:
                        logger.warning("Invalid social_links format")
                        return jsonify({"success": False, "error": "invalid_social_links_format"}), 400
                else:
                    setattr(workspace, field, form[field].strip())

        # Normalize old logo path handling. store relative path WITHOUT leading "uploads/"
        old_logo_rel = workspace.logo_path  # keep as relative like "2/logo_xxx.png"

        if logo_file and logo_file.filename:
            if not allowed_file(logo_file.filename):
                logger.warning("Invalid logo file type")
                return jsonify({"success": False, "error": "invalid_logo_file_type", "details": "Allowed types: png, jpg, jpeg, gif"}), 400

            # User-specific dir under UPLOAD_BASE
            user_upload_dir = os.path.join(UPLOAD_BASE, str(user.id))
            os.makedirs(user_upload_dir, exist_ok=True)

            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            safe_name = secure_filename(logo_file.filename)
            ext = os.path.splitext(safe_name)[1]
            logo_filename = f"logo_{workspace_id}_{timestamp}{ext}"
            logo_abs_path = os.path.join(user_upload_dir, logo_filename)

            try:
                logo_file.save(logo_abs_path)
                # store relative path (no leading uploads/)
                workspace.logo_path = os.path.join(str(user.id), logo_filename).replace('\\','/')
                logger.info(f"Uploaded new logo for workspace {workspace_id}: {workspace.logo_path}")
            except Exception as e:
                logger.warning("Failed to save logo file %s: %s", logo_abs_path, e)
                return jsonify({"success": False, "error": "logo_upload_failed", "details": str(e)}), 500

            # best-effort cleanup of old logo (old_logo_rel is relative)
            if old_logo_rel:
                try:
                    old_abs = os.path.join(UPLOAD_BASE, old_logo_rel)
                    if os.path.exists(old_abs):
                        os.remove(old_abs)
                        logger.info(f"Removed old logo {old_logo_rel} for workspace {workspace_id}")
                except Exception as e:
                    logger.warning("Could not remove old logo file %s: %s", old_logo_rel, e)

        workspace.updated_at = datetime.utcnow()

        try:
            db.session.commit()
            logger.info(f"Workspace {workspace_id} updated successfully")
        except Exception as e:
            db.session.rollback()
            logger.exception("DB update failed for workspace %s", workspace_id)
            return jsonify({"success": False, "error": "db_update_failed", "details": str(e)}), 500

        log_action(user.email or "system", "workspace_update", user.id, {"workspace_id": workspace_id})

        logo_url = f"{APP_BASE_URL}/uploads/{workspace.logo_path}" if workspace.logo_path else None

        return jsonify({
            "success": True,
            "message": "workspace_updated",
            "workspace": {
                "id": workspace.id,
                "user_id": workspace.user_id,
                "business_name": workspace.business_name,
                "business_type": workspace.business_type,
                "registered_address": workspace.registered_address,
                "b2b_b2c": workspace.b2b_b2c,
                "industry": workspace.industry,
                "description": workspace.description,
                "audience_description": workspace.audience_description,
                "website": workspace.website,
                "competitor_direct_1": workspace.competitor_direct_1,
                "competitor_direct_2": workspace.competitor_direct_2,
                "competitor_indirect_1": workspace.competitor_indirect_1,
                "competitor_indirect_2": workspace.competitor_indirect_2,
                "social_links": workspace.social_links,
                "usp": workspace.usp,
                "logo_path": logo_url,
                "creatives_path": workspace.creatives_path,
                "remarks": workspace.remarks,
                "created_at": workspace.created_at.isoformat() if workspace.created_at else None,
                "updated_at": workspace.updated_at.isoformat() if workspace.updated_at else None
            }
        }), 200

    except Exception as e:
        logger.exception("Workspace update failed for workspace_id %s", workspace_id)
        return jsonify({"success": False, "error": "internal_server_error", "details": str(e)}), 500

@app.route('/api/generations', methods=['GET', 'OPTIONS'])
@cross_origin(
    origins=os.getenv('FRONTEND_ORIGINS', '*').split(','),
    methods=['GET','OPTIONS'],
    allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 'X-User-Id', 'X-User-Email'],
    expose_headers=['Content-Type'],
    supports_credentials=True
)
def api_generations():
    logger.info("Request to /api/generations")
    try:
        user = get_user_from_request(require=True)
        if not user:
            logger.warning("Authentication failed for generations")
            return jsonify({"success": False, "error": "not_authenticated"}), 401

        workspace_id = request.args.get('workspace_id', type=int)
        if not workspace_id:
            logger.warning("Missing workspace_id")
            return jsonify({"success": False, "error": "missing_workspace_id"}), 400

        # Ensure workspace belongs to user
        workspace = Workspace.query.filter_by(id=workspace_id, user_id=user.id).first()
        if not workspace:
            logger.warning(f"Workspace {workspace_id} not found or forbidden for user {user.id}")
            return jsonify({"success": False, "error": "not_found_or_forbidden"}), 404

        generations = Generation.query.filter(Generation.workspace_id == str(workspace_id)).order_by(Generation.created_at.desc()) .all()

        generations_data = [
            {
                "id": g.id,
                "prompt": g.prompt,
                "response": g.response,
                "created_at": g.created_at.isoformat() if g.created_at else None
            } for g in generations
        ]
        logger.info(f"Fetched {len(generations_data)} generations for workspace {workspace_id}")

        return jsonify({
            "success": True,
            "generations": generations_data
        }), 200

    except Exception as e:
        logger.exception("Generations fetch failed")
        return jsonify({"success": False, "error": "internal_server_error", "details": str(e)}), 500

@app.route('/api/generations/me', methods=['GET', 'OPTIONS'])
@cross_origin(
    origins=os.getenv('FRONTEND_ORIGINS', '*').split(','),
    methods=['GET','OPTIONS'],
    allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 'X-User-Id', 'X-User-Email'],
    expose_headers=['Content-Type'],
    supports_credentials=True
)
def api_generations_me():
    logger.info("Request to /api/generations/me")
    try:
        user = get_user_from_request(require=True)
        if not user:
            logger.warning("Authentication failed for generations/me")
            return jsonify({"success": False, "error": "not_authenticated"}), 401

        # For non-workspace mode, fetch generations without workspace_id
        generations = Generation.query.filter_by(user_id=user.id, workspace_id=None).order_by(Generation.created_at.desc()).all()
        generations_data = [
            {
                "id": g.id,
                "prompt": g.prompt,
                "response": g.response,
                "created_at": g.created_at.isoformat() if g.created_at else None
            } for g in generations
        ]
        logger.info(f"Fetched {len(generations_data)} generations for user {user.id} (non-workspace)")

        return jsonify({
            "success": True,
            "generations": generations_data
        }), 200

    except Exception as e:
        logger.exception("Generations me fetch failed")
        return jsonify({"success": False, "error": "internal_server_error", "details": str(e)}), 500
@app.route("/api/workspace/<int:workspace_id>", methods=["DELETE", "OPTIONS"])
@cross_origin(
    origins=os.getenv('FRONTEND_ORIGINS', '*').split(','),
    methods=['DELETE','OPTIONS'],
    allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 'X-User-Id', 'X-User-Email'],
    expose_headers=['Content-Type'],
    supports_credentials=True
)
def api_workspace_delete(workspace_id):
    """
    Delete a workspace.
    - Authenticated route (get_user_from_request(require=True))
    - Only owner can delete (or admins if your app supports that)
    - Cleans up uploaded files (logo + creatives) stored under UPLOAD_BASE
    """
    try:
        user = get_user_from_request(require=True)
        if not user:
            return jsonify({"success": False, "error": "not_authenticated"}), 401

        # Fetch workspace
        workspace = Workspace.query.filter_by(id=workspace_id).first()
        if not workspace:
            return jsonify({"success": False, "error": "not_found"}), 404

        # Authorization: only owner may delete
        if workspace.user_id != user.id:
            # Optional: allow admins to delete
            # if not getattr(user, "is_admin", False):
            return jsonify({"success": False, "error": "forbidden"}), 403

        # File cleanup (best-effort; never fail the whole operation because of missing file)
        try:
            # workspace.logo_path is expected to be something like "2/logo_xxx.png"
            if workspace.logo_path:
                logo_abs = os.path.join(UPLOAD_BASE, workspace.logo_path)
                if os.path.exists(logo_abs):
                    try:
                        os.remove(logo_abs)
                    except Exception as e:
                        logger.warning("Could not remove logo file %s: %s", logo_abs, e)

            # creatives_paths stored as JSON array of relative paths (or None)
            if workspace.creatives_paths:
                try:
                    creatives_list = json.loads(workspace.creatives_paths)
                except Exception:
                    creatives_list = workspace.creatives_paths if isinstance(workspace.creatives_paths, list) else []

                for p in creatives_list or []:
                    try:
                        abs_path = os.path.join(UPLOAD_BASE, p)
                        if os.path.exists(abs_path):
                            os.remove(abs_path)
                    except Exception as e:
                        logger.warning("Could not remove creative file %s: %s", p, e)
        except Exception as e:
            # don't abort on file cleanup failure; just log
            logger.exception("File cleanup error while deleting workspace %s: %s", workspace_id, e)

        # Delete DB row (hard delete). If you want soft-delete, set a flag instead.
        try:
            db.session.delete(workspace)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.exception("DB delete failed for workspace %s", workspace_id)
            return jsonify({"success": False, "error": "db_delete_failed", "details": str(e)}), 500

        # Optional: filesystem-level cleanup for user's directory if empty
        try:
            user_dir = os.path.join(UPLOAD_BASE, str(user.id))
            if os.path.isdir(user_dir) and not os.listdir(user_dir):
                try:
                    os.rmdir(user_dir)
                except Exception as e:
                    logger.debug("Could not remove empty user upload dir %s: %s", user_dir, e)
        except Exception:
            pass

        log_action(user.email or "system", "workspace_delete", user.id, {"workspace_id": workspace_id})

        return jsonify({"success": True, "message": "workspace_deleted", "workspace_id": workspace_id}), 200

    except Exception as e:
        logger.exception("Workspace delete failed")
        # In dev you can include details; in prod avoid leaking internal details
        return jsonify({"success": False, "error": "internal_server_error", "details": str(e)}), 500
    
from flask import request, jsonify

import json
from datetime import datetime
import logging
from flask import jsonify, request


# Define Creative model
class Creative(db.Model):
    __tablename__ = 'creatives'
    id = db.Column(db.String(32), primary_key=True)
    user_id = db.Column(db.String(128), nullable=False)
    workspace_id = db.Column(db.String(128), nullable=False)
    url = db.Column(db.String(512), nullable=False)
    filename = db.Column(db.String(256))
    type = db.Column(db.String(32))  # 'generated' or 'saved'
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

import json
from datetime import datetime
import logging
from flask import jsonify, request




@app.route("/api/workspace", methods=["GET"])
def api_workspace_get():
    """
    GET /api/workspace
    Query params:
      - user_id (optional): numeric id of user whose workspaces to fetch
      - workspace_id (optional): specific workspace id to fetch
    If user is authenticated and no user_id is provided, returns the requesting user's workspace(s).
    """
    try:
        # Try to parse explicit query params first
        q_user_id = request.args.get("user_id", None)
        q_workspace_id = request.args.get("workspace_id", None)

        # If user_id provided as string, coerce to int if possible
        if q_user_id:
            try:
                q_user_id_int = int(q_user_id)
            except ValueError:
                return jsonify({"success": False, "error": "invalid_user_id"}), 400
        else:
            q_user_id_int = None

        # workspace_id if provided
        if q_workspace_id:
            try:
                q_workspace_id_int = int(q_workspace_id)
            except ValueError:
                return jsonify({"success": False, "error": "invalid_workspace_id"}), 400
        else:
            q_workspace_id_int = None

        # Authenticated user (if any) — do NOT overwrite q_user_id_int with a User object
        user = None
        try:
            user = get_user_from_request(require=False)  # don't require auth for public fetch
        except Exception:
            user = None

        # Determine which user_id to use for DB query
        if q_user_id_int is not None:
            use_user_id = q_user_id_int
        elif user:
            # get_user_from_request probably returns a User object; use its id attribute
            # guard if user is already an int (unlikely) but handle anyway
            use_user_id = getattr(user, "id", user) if user is not None else None
            # ensure it's an int
            try:
                use_user_id = int(use_user_id)
            except Exception:
                return jsonify({"success": False, "error": "could_not_resolve_user_id"}), 500
        else:
            # no user context and no user_id param -> bad request
            return jsonify({"success": False, "error": "user_id_required"}), 400

        # Build query safely
        if q_workspace_id_int is not None:
            workspace = Workspace.query.filter_by(id=q_workspace_id_int, user_id=use_user_id).first()
            if not workspace:
                return jsonify({"success": False, "error": "not_found"}), 404

            # Fetch creatives for this workspace
            creatives = Creative.query.filter_by(workspace_id=str(q_workspace_id_int)).order_by(Creative.created_at.desc()).all()
            creatives_out = []
            for c in creatives:
                creatives_out.append({
                    "id": c.id,
                    "user_id": c.user_id,
                    "workspace_id": c.workspace_id,
                    "url": c.url,
                    "filename": c.filename,
                    "type": c.type,
                    "created_at": c.created_at.isoformat() if c.created_at else None
                })

            # serialize workspace for response (adjust keys as per your model)
            direct_competitors = [workspace.competitor_direct_1, workspace.competitor_direct_2]
            indirect_competitors = [workspace.competitor_indirect_1, workspace.competitor_indirect_2]
            return jsonify({
                "success": True,
                "workspace": {
                    "id": workspace.id,
                    "user_id": workspace.user_id,
                    "business_name": workspace.business_name,
                    "description": workspace.description,
                    "audience_description": workspace.audience_description,
                    "website": workspace.website,
                    "direct_competitors": [c for c in direct_competitors if c],
                    "indirect_competitors": [c for c in indirect_competitors if c],
                    "social_links": json.loads(workspace.social_links or "[]"),
                    "usp": workspace.usp,
                    "logo_path": workspace.logo_path,
                    "creatives_path": json.loads(workspace.creatives_path or "[]"),
                    "created_at": workspace.created_at.isoformat() if getattr(workspace, "created_at", None) else None,
                    "updated_at": workspace.updated_at.isoformat() if getattr(workspace, "updated_at", None) else None,
                },
                "creatives": creatives_out
            }), 200

        # else fetch all workspaces for the user
        workspaces = Workspace.query.filter_by(user_id=use_user_id).order_by(Workspace.id.desc()).all()
        out = []
        for w in workspaces:
            try:
                direct_competitors = [w.competitor_direct_1, w.competitor_direct_2]
            except Exception:
                direct_competitors = []
            try:
                indirect_competitors = [w.competitor_indirect_1, w.competitor_indirect_2]
            except Exception:
                indirect_competitors = []
            try:
                socials = json.loads(w.social_links or "[]")
            except Exception:
                socials = []
            try:
                creatives_path = json.loads(w.creatives_path or "[]")
            except Exception:
                creatives_path = []

            # Fetch creatives count for each workspace (to avoid loading all data)
            creatives_count = Creative.query.filter_by(workspace_id=str(w.id)).count()

            out.append({
                "id": w.id,
                "user_id": w.user_id,
                "business_name": w.business_name,
                "description": w.description,
                "audience_description": w.audience_description,
                "website": w.website,
                "direct_competitors": [c for c in direct_competitors if c],
                "indirect_competitors": [c for c in indirect_competitors if c],
                "social_links": socials,
                "usp": w.usp,
                "logo_path": w.logo_path,
                "creatives_path": creatives_path,
                "creatives_count": creatives_count,
                "created_at": w.created_at.isoformat() if getattr(w, "created_at", None) else None,
                "updated_at": w.updated_at.isoformat() if getattr(w, "updated_at", None) else None,
            })

        return jsonify({"success": True, "workspaces": out}), 200

    except Exception as e:
        logger.exception("Workspace fetch failed")
        return jsonify({"success": False, "error": "internal_server_error", "details": str(e)}), 500

@app.route("/api/me", methods=["GET"])
@app.route("/api/user/me", methods=["GET"])
def api_me():
    user_id = session.get("user_id")
   

    user = User.query.get(user_id)
    print(user)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "success": True,
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "business_name": user.business_name,
            "industry": user.industry,
            "status": user.status
        }
    }), 200
@app.after_request
def _add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin and origin in FRONTEND_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type,Authorization,X-Requested-With,X-User-Id,X-User-Email"
        )
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
    return response


@app.after_request
def after_request(response):
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:8080")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    return response
from flask import request, jsonify

 # your SQLAlchemy db instance
USER_WORKSPACES = {
    "9": {"id": 9, "name": "Shiva's Workspace", "role": "Owner"},
    "10": {"id": 10, "name": "Team Workspace", "role": "Member"}
}


import json
import os
from datetime import datetime

@app.route("/api/workspace/me", methods=["GET"])
def get_workspace_me():
    # Resolve user_id from query param first, otherwise try session/header via helper
    user_id = request.args.get("user_id")
    if not user_id:
        user = get_user_from_request(require=False)
        user_id = getattr(user, "id", None)

    try:
        user_id = int(user_id)
    except Exception:
        return jsonify({"success": False, "error": "missing_or_invalid_user_id"}), 400

    # Attempt to fetch workspace
    try:
        workspace = Workspace.query.filter_by(user_id=user_id).first()
    except Exception as e:
        logger.exception("DB error fetching workspace")
        return jsonify({"success": False, "error": "db_error", "details": str(e)}), 500

    # No workspace row
    if not workspace:
        return jsonify({"success": True, "workspace": None}), 200

    # If the route somehow returns the mock dict (old code), return normalized shape
    if isinstance(workspace, dict):
        # mock -> map to expected shape
        result = {
            "id": workspace.get("id"),
            "user_id": workspace.get("id"),
            "business_name": workspace.get("name") or "",
            "business_type": "",
            "registered_address": "",
            "b2b_b2c": "",
            "industry": "",
            "describe_business": "",
            "describe_audience": "",
            "website": "",
            "direct_competitors": [],
            "indirect_competitors": [],
            "social_links": [],
            "usp": "",
            "logo_path": None,
            "logo_url": None,
            "creative_urls": [],
            "additional_remarks": None,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        }
        return jsonify({"success": True, "workspace": result}), 200

    # At this point we expect a SQLAlchemy Workspace object — read attributes defensively
    def g(name, default=None):
        try:
            return getattr(workspace, name, default)
        except Exception:
            return default

    # Debug: log available attribute names (helpful to see what's missing)
    try:
        logger.debug("Workspace object dir(): %s", [a for a in dir(workspace) if not a.startswith("_")][:200])
    except Exception:
        pass

    # Safe JSON loads helper
    def safe_load(text_or_none):
        if not text_or_none:
            return []
        try:
            return json.loads(text_or_none)
        except Exception:
            return []

    created_at = g("created_at")
    updated_at = g("updated_at")

    def iso_or_none(dt):
        try:
            return dt.isoformat()
        except Exception:
            return None

    creatives = safe_load(g("creatives_paths") or "[]")
    direct_competitors = safe_load(g("direct_competitors") or "[]")
    indirect_competitors = safe_load(g("indirect_competitors") or "[]")
    social_links = safe_load(g("social_links") or "[]")

    logo_path = g("logo_path")
    logo_url = None
    if logo_path:
        logo_url = f"{APP_BASE_URL.rstrip('/')}/uploads/workspaces/{g('user_id')}/{os.path.basename(logo_path)}"

    result = {
        "id": g("id"),
        "user_id": g("user_id"),
        "business_name": g("business_name") or "",
        "business_type": g("business_type") or "",
        "registered_address": g("registered_address") or "",
        "b2b_b2c": g("b2b_b2c") or "",
        "industry": g("industry") or "",
        "describe_business": g("describe_business") or "",
        "describe_audience": g("describe_audience") or "",
        "website": g("website") or "",
        "direct_competitors": direct_competitors,
        "indirect_competitors": indirect_competitors,
        "social_links": social_links,
        "usp": g("usp") or "",
        "logo_path": logo_path,
        "logo_url": logo_url,
        "creative_urls": [f"{APP_BASE_URL.rstrip('/')}/uploads/workspaces/{g('user_id')}/{os.path.basename(p)}" for p in creatives],
        "additional_remarks": g("additional_remarks"),
        "created_at": iso_or_none(created_at),
        "updated_at": iso_or_none(updated_at),
    }

    return jsonify({"success": True, "workspace": result}), 200

@app.route("/api/workspace/caps", methods=["GET"])
def api_workspace_caps():
    user_id = request.args.get("user_id")
    if not user_id:
        return jsonify({"success": False, "message": "Missing user_id"}), 400

    # Example caps (replace with DB logic if needed)
    caps = [
        {"name": "Campaigns", "used": 3, "limit": 10},
        {"name": "Team Members", "used": 2, "limit": 5},
        {"name": "Storage (GB)", "used": 1, "limit": 5},
    ]

    return jsonify({"success": True, "caps": caps})


# ---------------- metaa - marketingg  ----------------

def get_facebook_token_for_user(user_id):
    sa = SocialAccount.query.filter_by(provider="facebook", user_id=user_id).first()
    if not sa or not sa.access_token:
        return None
    return sa.access_token


import requests

@app.route("/api/meta/adaccounts", methods=["GET"])
def list_ad_accounts():
    user = get_user_from_request(require=True)
    token = get_facebook_token_for_user(user.id)
    if not token:
        return jsonify({"success": False, "error": "no_facebook_token"}), 403

    url = f"https://graph.facebook.com/v16.0/me/adaccounts"
    params = {"access_token": token, "fields": "account_id,name,currency,timezone_id"}
    r = requests.get(url, params=params, timeout=10)
    if r.status_code != 200:
        return jsonify({"success": False, "error": "fb_error", "details": r.json()}), r.status_code
    return jsonify({"success": True, "ad_accounts": r.json().get("data", [])}), 200

@app.route("/api/meta/adaccounts/<account_id>/campaigns", methods=["POST"])
def create_campaign(account_id):
    user = get_user_from_request(require=True)
    token = get_facebook_token_for_user(user.id)
    if not token:
        return jsonify({"success": False, "error": "no_facebook_token"}), 403

    data = request.json or {}
    name = data.get("name", "New Campaign")
    objective = data.get("objective", "LINK_CLICKS")  # choose valid objective
    status = data.get("status", "PAUSED")

    url = f"https://graph.facebook.com/v16.0/act_{account_id}/campaigns"
    params = {"access_token": token}
    payload = {"name": name, "objective": objective, "status": status}
    r = requests.post(url, params=params, data=payload, timeout=10)
    if r.status_code not in (200,201):
        return jsonify({"success": False, "error": "fb_error", "details": r.json()}), r.status_code
    return jsonify({"success": True, "campaign": r.json()}), 201

@app.route("/api/meta/adaccounts/<account_id>/adsets", methods=["POST"])
def create_adset(account_id):
    user = get_user_from_request(require=True)
    token = get_facebook_token_for_user(user.id)
    body = request.json or {}

    payload = {
      "name": body.get("name","My AdSet"),
      "campaign_id": body["campaign_id"],
      "daily_budget": body.get("daily_budget", 1000),  # in minor units (e.g., cents)
      "billing_event": body.get("billing_event","IMPRESSIONS"),
      "optimization_goal": body.get("optimization_goal","LINK_CLICKS"),
      "bid_strategy": body.get("bid_strategy","LOWEST_COST_WITHOUT_CAP"),
      "targeting": json.dumps(body.get("targeting", {"geo_locations":{"countries":["US"]}})),
      "start_time": body.get("start_time"),  # ISO8601 or timestamp
      "end_time": body.get("end_time"),
      "status": body.get("status","PAUSED")
    }
    url = f"https://graph.facebook.com/v16.0/act_{account_id}/adsets"
    r = requests.post(url, params={"access_token": token}, data=payload, timeout=10)
    if r.status_code not in (200,201):
        return jsonify({"success": False, "error":"fb_error","details": r.json()}), r.status_code
    return jsonify({"success": True,"adset": r.json()}), 201


@app.route("/api/meta/adaccounts/<account_id>/creatives", methods=["POST"])
def create_creative(account_id):
    user = get_user_from_request(require=True)
    token = get_facebook_token_for_user(user.id)
    body = request.json or {}

    # Example: link ad creative
    object_story_spec = {
        "page_id": body["page_id"],
        "link_data": {
            "message": body.get("message", "Try it!"),
            "link": body["link"],
            "caption": body.get("caption",""),
        }
    }

    payload = {
        "name": body.get("name","Creative"),
        "object_story_spec": json.dumps(object_story_spec)
    }
    url = f"https://graph.facebook.com/v16.0/act_{account_id}/adcreatives"
    r = requests.post(url, params={"access_token": token}, data=payload, timeout=10)
    if r.status_code not in (200,201):
        return jsonify({"success": False, "error":"fb_error", "details": r.json()}), r.status_code
    return jsonify({"success": True, "creative": r.json()}), 201

@app.route("/api/meta/adaccounts/<account_id>/ads", methods=["POST"])
def create_ad(account_id):
    user = get_user_from_request(require=True)
    token = get_facebook_token_for_user(user.id)
    body = request.json or {}
    payload = {
        "name": body.get("name","My Ad"),
        "adset_id": body["adset_id"],
        "creative": json.dumps({"creative_id": body["creative_id"]}),
        "status": body.get("status","PAUSED")
    }
    url = f"https://graph.facebook.com/v16.0/act_{account_id}/ads"
    r = requests.post(url, params={"access_token": token}, data=payload, timeout=10)
    if r.status_code not in (200,201):
        return jsonify({"success": False, "error":"fb_error", "details": r.json()}), r.status_code
    return jsonify({"success": True, "ad": r.json()}), 201


@app.route("/api/meta/adaccounts/<account_id>/insights", methods=["GET"])
def ad_account_insights(account_id):
    user = get_user_from_request(require=True)
    token = get_facebook_token_for_user(user.id)
    params = {
        "access_token": token,
        "level": request.args.get("level","ad"),
        "time_range": json.dumps({"since": request.args.get("since"), "until": request.args.get("until")}),
        "fields": request.args.get("fields","impressions,clicks,spend,ctr")
    }
    url = f"https://graph.facebook.com/v16.0/act_{account_id}/insights"
    r = requests.get(url, params=params, timeout=20)
    return jsonify({"success": r.status_code == 200, "data": r.json()}), r.status_code


@app.route("/api/social/accounts", methods=["GET", "OPTIONS"])
def api_social_accounts():
    if request.method == "OPTIONS":
        # Preflight
        return jsonify({}), 200
    # Normal GET
    accounts = SocialAccount.query.all()
    return jsonify({"accounts": [a.serialize() for a in accounts]})


@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        resp = app.make_default_options_response()
        headers = resp.headers

        headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "")
        headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, X-User-Id, X-User-Email"
        headers["Access-Control-Allow-Credentials"] = "true"

        return resp

@app.route('/')
def index():
    return "SOCIOVIA running. POST credentials to endpoints to fetch data."


# Add to your Flask app.py

@app.route("/api/workspaces", methods=["GET"])
def api_workspaces():
    """Return all workspaces for the current user"""
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    
    # Get all workspaces for this user
    workspaces = Workspace.query.filter_by(user_id=user.id).all()
    
    result = []
    for workspace in workspaces:
        # Format each workspace to match the expected frontend structure
        result.append({
            "id": workspace.id,
            "name": workspace.business_name,
            "sector": workspace.industry,
            "role": "Owner",  # Default role
            "created_at": workspace.created_at.isoformat() if workspace.created_at else None,
            "logo": workspace.logo_url if hasattr(workspace, 'logo_url') else None
        })
    
    return jsonify({"success": True, "workspaces": result}), 200

@app.route("/api/workspace/list", methods=["GET"])
def api_workspace_list():
    """Alternative endpoint for workspace list"""
    return api_workspaces()  # Reuse the same implementation

@app.route("/api/workspace/metrics", methods=["GET"])
def api_workspace_metrics():
    """Return metrics for workspaces"""
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    
    workspaces = Workspace.query.filter_by(user_id=user.id).all()
    metrics = {}
    
    for workspace in workspaces:
        # Create mock metrics for each workspace (replace with real data)
        metrics[workspace.id] = {
            "workspace_id": workspace.id,
            "total_spend": 10000 + workspace.id * 100,
            "leads": 500 + workspace.id * 50,
            "active_campaigns": (workspace.id % 5) + 1,
            "reach": 10000 + workspace.id * 1000,
            "impressions": 50000 + workspace.id * 5000,
            "clicks": 3000 + workspace.id * 300,
            "ctr": 6.0 - (workspace.id % 5) * 0.2,
            "cpm": 15.0 + (workspace.id % 5) * 0.5,
            "last_updated": datetime.utcnow().isoformat()
        }
    
    return jsonify({"success": True, "metrics": metrics}), 200

# ---------------- Password reset endpoints ----------------
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer

# TTL for password reset tokens (hours)
RESET_TTL_HOURS = int(app.config.get("RESET_TTL_HOURS", os.getenv("RESET_TTL_HOURS", 2)))
# Constants (near other config constants)
RESET_TTL_SECONDS = int(os.getenv("RESET_TTL_SECONDS", 3600))  # 1 hour by default

# ---------------- Password reset endpoints (consolidated) ----------------
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer

# TTL for password reset tokens (seconds). Can be overridden via env/config.
RESET_TTL_SECONDS = int(app.config.get("RESET_TTL_SECONDS", os.getenv("RESET_TTL_SECONDS", 3600)))
# Also provide hours for human messaging if needed
RESET_TTL_HOURS = max(1, int(RESET_TTL_SECONDS // 3600))

# FRONTEND base used for reset link (point to your frontend site)
FRONTEND_BASE_URL = app.config.get("FRONTEND_BASE_URL", os.getenv("FRONTEND_BASE_URL", "https://sociovia.com"))

def _build_reset_url(token: str) -> str:
    return f"{FRONTEND_BASE_URL.rstrip('/')}/reset-password?token={token}"

@app.route("/api/password/forgot", methods=["POST"])
def api_password_forgot():
    """
    Request a password reset. Body: { "email": "<email>" }.
    Sends a single-use token link to the user's email (token TTL controlled by RESET_TTL_SECONDS).
    """
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"success": False, "error": "email_required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        # Do NOT reveal that the email is missing: return generic success
        logger.info("Password reset requested for unknown email: %s", email)
        return jsonify({"success": True, "message": "If the email exists, a reset link has been sent."}), 200

    try:
        # Create signed reset token (stateless). Uses your existing make_action_token function.
        token = make_action_token({
            "user_id": user.id,
            "action": "reset_password",
            "issued_at": datetime.utcnow().isoformat()
        })

        reset_url = _build_reset_url(token)

        # Try to render your template; pass both reset_url and reset_link names
        try:
            email_body = load_email_template(
                "password_reset.txt",
                {"name": user.name or user.email, "reset_url": reset_url, "reset_link": reset_url, "ttl_hours": RESET_TTL_HOURS}
            )
        except Exception:
            # Fallback to simple text if template missing or rendering fails
            email_body = (
                f"Hi {user.name or user.email},\n\n"
                f"We received a request to reset your password.\n\n"
                f"Click the link below to reset your password (valid for {RESET_TTL_HOURS} hour(s)):\n\n"
                f"{reset_url}\n\n"
                "If you didn't request this, please ignore this email.\n\n"
                "Thanks,\nSociovia Team\nhttps://sociovia.com"
            )

        send_mail_to(user.email, "Sociovia — Password reset instructions", email_body)
        log_action("system", "password_reset_requested", user.id)
    except Exception as e:
        logger.exception("Failed to process forgot-password for %s", email)
        # Keep response generic for security
        return jsonify({"success": False, "error": "internal_error"}), 500

    return jsonify({"success": True, "message": "If the email exists, a reset link has been sent."}), 200


# Compatibility alias (optional) - forwards to canonical endpoint
@app.route("/api/forgot-password", methods=["POST"])
def api_forgot_password_alias():
    return api_password_forgot()


@app.route("/api/password/forgot/validate", methods=["GET"])
def api_password_reset_validate():
    """
    Validate a reset token -> returns {"valid": True, "user_id": ...} or {"valid": False, "error": "..."}.
    Accepts token as query param: ?token=...
    """
    token = request.args.get("token") or ""
    if not token:
        return jsonify({"valid": False, "error": "token_required"}), 400
    try:
        payload = load_action_token(token, RESET_TTL_SECONDS)
        if payload.get("action") != "reset_password":
            return jsonify({"valid": False, "error": "invalid_action"}), 400
        user_id = payload.get("user_id")
        user = User.query.get(user_id)
        if not user:
            return jsonify({"valid": False, "error": "user_not_found"}), 404
        return jsonify({"valid": True, "user_id": user_id, "email": user.email}), 200
    except Exception as e:
        logger.exception("Reset token validate failed: %s", e)
        return jsonify({"valid": False, "error": "invalid_or_expired_token"}), 400


@app.route("/api/password/reset", methods=["POST"])
def api_password_reset():
    """
    Reset the password. Body: { token: string, password: string }
    """
    data = request.get_json() or {}
    token = (data.get("token") or "").strip()
    new_password = data.get("password") or ""

    if not token or not new_password:
        return jsonify({"success": False, "error": "token_and_password_required"}), 400

    # Basic password policy check (reuse valid_password from utils)
    if not valid_password(new_password):
        return jsonify({"success": False, "error": "password_policy_failed"}), 400

    try:
        payload = load_action_token(token, RESET_TTL_SECONDS)
    except Exception as e:
        logger.warning("Invalid/expired reset token: %s", e)
        return jsonify({"success": False, "error": "invalid_or_expired_token"}), 400

    if payload.get("action") != "reset_password":
        return jsonify({"success": False, "error": "invalid_action"}), 400

    user_id = payload.get("user_id")
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "error": "user_not_found"}), 404

    # All good: update password
    try:
        user.password_hash = generate_password_hash(new_password)
        db.session.add(user)
        db.session.commit()
        log_action("system", "password_reset_completed", user.id)

        # Try to send confirmation email (non-fatal if it fails)
        try:
            email_body = load_email_template("password_reset_confirm.txt", {"name": user.name or user.email})
        except Exception:
            email_body = f"Hi {user.name or user.email},\n\nYour password was successfully changed.\n\nIf you did not request this, please contact support.\n\nSociovia Team"
        send_mail_to(user.email, "Your Sociovia password has been changed", email_body)

        return jsonify({"success": True, "message": "password_reset_success"}), 200
    except Exception as e:
        logger.exception("Failed to update password for user %s: %s", user_id, e)
        return jsonify({"success": False, "error": "internal_server_error"}), 500

# ---------------- FastAPI microservice for Facebook Graph API proxy ----------------

# ---------------- CORS preflight handler ----------------
@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        resp = app.make_default_options_response()
        headers = resp.headers
        headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "")
        headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, X-User-Id, X-User-Email"
        headers["Access-Control-Allow-Credentials"] = "true"
        return resp

@app.after_request
def after_request(response):
    origin = request.headers.get("Origin")
    if origin in ["http://localhost:5173", "https://sociovia.com", "https://6136l5dn-5000.inc1.devtunnels.ms","http://localhost:8080","https://localhost:3000","https://localhost:8080","http://localhost:8080","http://localhost:8080","https://sociovia-c9473.web.app","https://sociovia.com","https://127.0.0.1","http://127.0.0.1:8080"]:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
    return response

# ---------------- Facebook-first OAuth routes (compatibility) ----------------
def _build_fb_oauth_url(state: str, scopes: str = None):
    client_id = FB_APP_ID
    redirect_uri = f"{OAUTH_REDIRECT_BASE.rstrip('/')}/api/oauth/facebook/callback"
    use_scopes = scopes or OAUTH_SCOPES
    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'scope': use_scopes,
        'response_type': 'code',
        'state': state,
    }
    return f"https://www.facebook.com/{FB_API_VERSION}/dialog/oauth?{urlencode(params)}"

# Support legacy /api/oauth/instagram/connect by routing to FB connect for now (compat)
@app.route('/api/oauth/facebook/connect', methods=['GET'])
@app.route('/api/oauth/instagram/connect', methods=['GET'])
def oauth_facebook_connect():
    # Read incoming state (may already be JSON or a plain string)
    incoming_state = request.args.get('state') or ''
    raw_user_id = request.args.get('user_id')

    # Build a JSON state object so we can carry user_id through the FB OAuth dance.
    # If incoming_state is JSON, merge; otherwise keep it under "s".
    state_payload = {}
    if incoming_state:
        try:
            parsed = json.loads(incoming_state)
            if isinstance(parsed, dict):
                state_payload.update(parsed)
            else:
                state_payload['s'] = incoming_state
        except Exception:
            state_payload['s'] = incoming_state

    # Add user_id if provided on the connect request
    if raw_user_id:
        try:
            state_payload['user_id'] = int(raw_user_id)
        except Exception:
            state_payload['user_id'] = raw_user_id

    # Final state string passed to FB (empty string if nothing)
    state_to_send = json.dumps(state_payload) if state_payload else ''

    current_app.logger.info('Starting Facebook connect (state=%s)', state_to_send)
    auth_url = _build_fb_oauth_url(state=state_to_send)
    return redirect(auth_url)

# Add this at the top of your Flask config or constants
OAUTH_SCOPES = [
    # Pages
    "pages_show_list",            # List all Pages the user manages
    "pages_read_engagement",      # Read Page insights and engagement
    "pages_manage_posts",         # Create, edit, delete Page posts
    "pages_manage_engagement",    # Moderate comments, respond to messages
    "pages_read_user_content",    # Read user-generated content on the Page
    "pages_manage_metadata",      # Read Page settings, roles, metadata
    "pages_manage_ads",           # Manage ads linked to Pages

    # Ads & Business
    "ads_management",             # Create/update/delete ad campaigns, sets, and ads
    "ads_read",                   # Read ads and insights
    "business_management",        # Access Business Manager assets and roles

    # Instagram
    "instagram_basic",            # Read Instagram account profile info
    "instagram_content_publish"   # Publish content to Instagram business accounts
]


OAUTH_SCOPES_STR = ",".join(OAUTH_SCOPES)
@app.route('/api/oauth/facebook/callback', methods=['GET'])
@app.route('/api/oauth/instagram/callback', methods=['GET'])
def oauth_facebook_callback():
    code = request.args.get('code')
    state = request.args.get('state') or ''
    error = request.args.get('error')
    frontend = FRONTEND_BASE_URL.rstrip('/')

    def render_response(payload):
        payload_json = json.dumps(payload)
        return render_template_string("""
<!doctype html><html><head><meta charset="utf-8"/></head><body>
<script>
(function(){
  var payload = {{payload|safe}};
  var targetOrigin = "{{frontend}}";
  try {
    if (window.opener && !window.opener.closed) {
      window.opener.postMessage(payload, targetOrigin);
      window.close();
    } else {
      var frag = "data=" + encodeURIComponent(JSON.stringify(payload));
      window.location.href = "{{frontend}}/oauth-complete#" + frag;
    }
  } catch(e) {
    var frag = "data=" + encodeURIComponent(JSON.stringify(payload));
    window.location.href = "{{frontend}}/oauth-complete#" + frag;
  }
})();
</script>
</body></html>
        """, payload=payload_json, frontend=frontend)

    # 1) validate
    if error or not code:
        payload = {"type": "sociovia_oauth_complete", "success": False, "state": state,
                   "fb_error": {"message": error or "no_code"}}
        return render_response(payload)

    # 2) exchange code -> short token
    token_url = f"https://graph.facebook.com/{FB_API_VERSION}/oauth/access_token"
    params = {
        'client_id': FB_APP_ID,
        'client_secret': FB_APP_SECRET,
        'redirect_uri': f"{OAUTH_REDIRECT_BASE.rstrip('/')}/api/oauth/facebook/callback",
        'code': code
    }
    try:
        r = requests.get(token_url, params=params, timeout=10)
        data = r.json()
        if 'error' in data:
            raise ValueError(data['error'])
        short_token = data.get('access_token')
    except Exception as exc:
        payload = {"type": "sociovia_oauth_complete", "success": False, "state": state,
                   "fb_error": {"message": "token_exchange_failed", "details": str(exc)}}
        return render_response(payload)

    # 3) exchange short -> long (best-effort)
    exch_url = f"https://graph.facebook.com/{FB_API_VERSION}/oauth/access_token"
    exch_params = {
        'grant_type': 'fb_exchange_token',
        'client_id': FB_APP_ID,
        'client_secret': FB_APP_SECRET,
        'fb_exchange_token': short_token
    }
    try:
        r2 = requests.get(exch_url, params=exch_params, timeout=10)
        long_token = r2.json().get('access_token', short_token)
    except Exception:
        long_token = short_token

    # 4) fetch pages
    try:
        pages_url = f"https://graph.facebook.com/{FB_API_VERSION}/me/accounts"
        pages_r = requests.get(pages_url, params={
            'access_token': long_token,
            'fields': 'id,name,access_token,instagram_business_account'
        }, timeout=10)
        pages = pages_r.json().get('data', [])
    except Exception as exc:
        payload = {"type": "sociovia_oauth_complete", "success": False, "state": state,
                   "fb_error": {"message": "fetch_pages_failed", "details": str(exc)}}
        return render_response(payload)

    # 5) resolve user - PRIORITIZE explicit request user_id (from query param), then session, then state fallback
    user = None
    user_id = None

    # 5.a check query param first (you asked user_id will be in request)
    raw_q_uid = request.args.get("user_id")
    print("DEBUG: callback raw user_id (query param):", raw_q_uid, flush=True)
    if raw_q_uid:
        try:
            parsed_uid = int(raw_q_uid)
            maybe_user = User.query.get(parsed_uid)
            if maybe_user:
                user = maybe_user
                user_id = maybe_user.id
                current_app.logger.info(f"oauth callback: using user_id from query param: {user_id}")
            else:
                current_app.logger.warning(f"oauth callback: user_id {parsed_uid} provided but user not found")
        except Exception as e:
            current_app.logger.warning(f"oauth callback: invalid user_id query param: {raw_q_uid} ({e})")

    # 5.b fallback to session if query param not present / invalid
    if not user:
        session_user = get_user_from_request(require=False)
        if session_user:
            user = session_user
            user_id = getattr(session_user, "id", None)
            current_app.logger.info(f"oauth callback: resolved session user_id={user_id}")

    # 5.c final fallback: parse state JSON or simple substring (kept but lower priority)
    if not user and state:
        try:
            parsed_state = json.loads(state)
            if isinstance(parsed_state, dict) and parsed_state.get("user_id"):
                try:
                    parsed_uid = int(parsed_state.get("user_id"))
                    maybe_user = User.query.get(parsed_uid)
                    if maybe_user:
                        user = maybe_user
                        user_id = maybe_user.id
                        current_app.logger.info(f"oauth callback: resolved user_id from state JSON: {user_id}")
                except Exception:
                    current_app.logger.warning("oauth callback: invalid user_id in state JSON")
        except Exception:
            # not JSON — attempt simple "user_id=NN" substring extraction
            if "user_id=" in state:
                try:
                    tail = state.split("user_id=")[1].split("&")[0]
                    parsed_uid = int(tail)
                    maybe_user = User.query.get(parsed_uid)
                    if maybe_user:
                        user = maybe_user
                        user_id = maybe_user.id
                        current_app.logger.info(f"oauth callback: resolved user_id from state substring: {user_id}")
                except Exception:
                    current_app.logger.warning("oauth callback: failed to parse user_id from state substring")

    # 6) save/update social accounts
    saved = []
    db_error = None
    try:
        for p in pages:
            page_id = str(p.get('id'))
            page_name = p.get('name') or ""
            page_token = p.get('access_token') or long_token
            ig = p.get('instagram_business_account')
            ig_id = str(ig.get('id')) if ig else None

            # DEBUG log
            current_app.logger.info(f"Saving page id={page_id}, name={page_name}, attaching user_id={user_id}")
            print("DEBUG: saving page, attaching user_id=", user_id, " page_id=", page_id, flush=True)

            try:
                existing = SocialAccount.query.filter_by(provider='facebook', provider_user_id=page_id).first()

                if existing:
                    # normalize existing.user_id if stored as empty string (or string "None")
                    try:
                        if existing.user_id == "" or existing.user_id is None:
                            existing.user_id = None
                    except Exception:
                        existing.user_id = None

                    existing.access_token = page_token
                    existing.scopes = ",".join(OAUTH_SCOPES) if isinstance(OAUTH_SCOPES, (list, tuple)) else str(OAUTH_SCOPES)
                    existing.instagram_business_id = ig_id

                    # only overwrite/attach owner if we have a resolved user_id
                    if user_id:
                        try:
                            existing.user_id = int(user_id)
                        except Exception:
                            existing.user_id = user_id
                        current_app.logger.info(f"Updated existing SocialAccount {page_id} owner -> {existing.user_id}")
                    db.session.add(existing)
                    db.session.flush()
                    saved.append(existing.serialize())
                else:
                    sa = SocialAccount(
                        provider='facebook',
                        provider_user_id=page_id,
                        account_name=page_name,
                        access_token=page_token,
                        user_id=(int(user_id) if user_id else None),
                        scopes=",".join(OAUTH_SCOPES) if isinstance(OAUTH_SCOPES, (list, tuple)) else str(OAUTH_SCOPES),
                        instagram_business_id=ig_id
                    )
                    db.session.add(sa)
                    db.session.flush()
                    current_app.logger.info(f"Created SocialAccount {page_id} owner -> {sa.user_id}")
                    print("DEBUG: created SocialAccount", sa.serialize(), flush=True)
                    saved.append(sa.serialize())
            except Exception as e:
                db.session.rollback()
                current_app.logger.exception("Failed to save social account")
                db_error = str(e)
                # break early on per-account DB error to avoid partial inconsistent state
                break
    except Exception as e:
        db_error = str(e)

    # final commit (if no earlier DB error)
    try:
        if db_error is None:
            db.session.commit()
    except Exception as e:
        current_app.logger.exception("Final commit failed in oauth callback")
        db.session.rollback()
        db_error = str(e)

    resp_payload = {
        "type": "sociovia_oauth_complete",
        "success": (len(saved) > 0 and db_error is None),
        "state": state,
        "saved": saved,
        "fb_pages_count": len(pages),
        "user_attached": bool(user_id)
    }
    if db_error:
        resp_payload["db_error"] = db_error

    return render_response(resp_payload)


@app.route('/api/oauth/facebook/save-selection', methods=['POST'])
@cross_origin(origins=["https://sociovia.com","https://6136l5dn-5000.inc1.devtunnels.ms"], supports_credentials=True)
def oauth_save_selection():
    """
    Request body:
    {
      "user_id": 2,
      "accounts": [
         { "provider":"facebook", "provider_user_id":"123", "name":"My Page", "access_token":"...", "instagram_business_id":"..." },
         ...
      ],
      "features": { "pages_manage_posts": true, "ads_management": false }  # optional
    }
    """
    try:
        data = request.get_json(force=True, silent=True)
    except Exception as e:
        current_app.logger.warning("oauth_save_selection invalid json: %s", e)
        return jsonify({'success': False, 'error': 'invalid_json'}), 400

    if not data:
        return jsonify({'success': False, 'error': 'invalid_json'}), 400

    raw_user_id = data.get('user_id')
    print("DEBUG: oauth_save_selection raw_user_id:", raw_user_id, flush=True)
    if raw_user_id is None or raw_user_id == "":
        return jsonify({'success': False, 'error': 'missing_user_id'}), 400

    try:
        user_id = int(raw_user_id)
    except Exception:
        return jsonify({'success': False, 'error': 'invalid_user_id'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'error': 'user_not_found'}), 404

    accounts = data.get('accounts', [])
    features = data.get('features', {}) or {}
    saved = []

    try:
        for a in accounts:
            provider = a.get('provider') or 'facebook'
            pid = str(a.get('provider_user_id') or "").strip()
            if not pid:
                current_app.logger.warning("Skipping account with empty provider_user_id: %s", a)
                continue

            name = a.get('name') or a.get('account_name') or ""
            access_token = a.get('access_token') or None
            instagram_business_id = a.get('instagram_business_id') or a.get('instagram_business_account') or None

            # compute scopes_list
            if isinstance(a.get('scopes'), (list, tuple)):
                scopes_list = [s for s in a.get('scopes') if s]
            elif isinstance(a.get('scopes'), str) and a.get('scopes').strip():
                scopes_list = [s.strip() for s in a.get('scopes').replace("{","").replace("}","").split(",") if s.strip()]
            else:
                scopes_list = [k for k, v in (features or {}).items() if v]

            existing = SocialAccount.query.filter_by(provider=provider, provider_user_id=pid).first()
            if existing:
                # normalize user_id empty-string -> None
                if existing.user_id == "" or existing.user_id is None:
                    existing.user_id = None

                if name:
                    existing.account_name = name
                if access_token:
                    existing.access_token = access_token
                if instagram_business_id:
                    existing.instagram_business_id = instagram_business_id

                # Only set user_id if existing has no owner or owner == same user
                try:
                    if not existing.user_id:
                        existing.user_id = user.id
                    elif int(existing.user_id) == user.id:
                        existing.user_id = user.id
                    # else leave as-is (do not override another user's ownership)
                except Exception:
                    existing.user_id = user.id

                # merge scopes if provided
                if scopes_list:
                    existing_scopes = []
                    if existing.scopes:
                        if isinstance(existing.scopes, str):
                            existing_scopes = [s.strip() for s in existing.scopes.replace("{","").replace("}","").split(",") if s.strip()]
                        elif isinstance(existing.scopes, (list, tuple)):
                            existing_scopes = list(existing.scopes)
                    merged = list(dict.fromkeys(existing_scopes + scopes_list))
                    existing.scopes = ",".join(merged)

                db.session.add(existing)
                db.session.flush()
                saved.append(existing.serialize())
            else:
                new_scopes = ",".join(scopes_list) if scopes_list else ""
                sa = SocialAccount(
                    user_id=user.id,
                    provider=provider,
                    provider_user_id=pid,
                    account_name=name,
                    access_token=access_token,
                    instagram_business_id=instagram_business_id,
                    scopes=new_scopes
                )
                db.session.add(sa)
                db.session.flush()
                saved.append(sa.serialize())

        db.session.commit()
        return jsonify({'success': True, 'connected': saved}), 200

    except Exception as e:
        current_app.logger.exception("oauth_save_selection failed")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'db_error', 'message': str(e)}), 500



@app.route('/api/oauth/facebook/revoke', methods=['POST'])
@app.route('/api/oauth/instagram/revoke', methods=['POST'])
def oauth_revoke():
    data = request.get_json(force=True, silent=True) or {}
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'error': 'missing_user_id'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'error': 'user_not_found'}), 404

    provider = data.get('provider')
    provider_user_id = str(data.get('provider_user_id'))
    sa = SocialAccount.query.filter_by(
        provider=provider,
        provider_user_id=provider_user_id,
        user_id=user.id
    ).first()

    if not sa:
        return jsonify({'success': False, 'error': 'not_found'}), 404

    try:
        if sa.access_token:
            revoke_url = f"https://graph.facebook.com/{FB_API_VERSION}/me/permissions"
            requests.delete(revoke_url, params={'access_token': sa.access_token}, timeout=5)
    except Exception:
        logger.exception('Failed to call fb revoke')

    db.session.delete(sa)
    db.session.commit()
    return jsonify({'success': True}), 200

# Deauthorize & Data Deletion endpoints (hook into FB App settings)
@app.route('/api/oauth/deauthorize', methods=['POST'])
def fb_deauthorize():
    # FB sends a signed_request form param on deauth — you must verify it with your app secret.
    # For now accept and mark accounts disconnected (dev skeleton).
    payload = request.form or request.json or {}
    logger.info("FB deauthorize payload: %s", payload)
    # TODO: validate signed_request here
    # Example behavior: find user by facebook id in payload and remove tokens
    return jsonify({'success': True}), 200

@app.route('/api/data-deletion', methods=['POST'])
def fb_data_deletion():
    # Data deletion flow: FB will POST a request. You should start deletion and return a JSON with a status URL.
    body = request.get_json() or {}
    logger.info("FB data deletion request: %s", body)
    # TODO: implement actual deletion and return a reachable status/url per FB spec
    status_url = f"{APP_BASE_URL.rstrip('/')}/data-deletion-status?request_id={int(datetime.utcnow().timestamp())}"
    return jsonify({"url": status_url}), 200

# ---------------- Facebook Meta endpoints (ads, campaigns, insights) ----------------
def get_facebook_token_for_user(user_id):
    if not user_id:
        return None
    sa = SocialAccount.query.filter_by(provider="facebook", user_id=user_id).first()
    if not sa:
        return None
    # prefer the stored access_token
    token = getattr(sa, "access_token", None)
    return token

import os
import json
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
from dotenv import load_dotenv  

BASE_DIR = Path(__file__).resolve().parent
STORAGE_FILE =BASE_DIR = Path(__file__).resolve().parent/ "tokens.json" 
    # ----- Storage helpers (file-backed demo) -----
async def read_storage() -> Dict[str, Any]:
    if not STORAGE_FILE.exists():
        await asyncio.to_thread(STORAGE_FILE.write_text, json.dumps({"pages": {}, "workspace_map": {}}))
    raw = await asyncio.to_thread(STORAGE_FILE.read_text)
    try:
        return json.loads(raw)
    except Exception:
        return {"pages": {}, "workspace_map": {}}

async def write_storage(payload: Dict[str, Any]):
    await asyncio.to_thread(STORAGE_FILE.write_text, json.dumps(payload, indent=2))

# ----- WebSocket connection manager (simple broadcast) -----
class ConnectionManager:
    def __init__(self):
        self.connections: List[WebSocket] = []
        self.lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self.lock:
            self.connections.append(ws)

    async def disconnect(self, ws: WebSocket):
        async with self.lock:
            if ws in self.connections:
                self.connections.remove(ws)

    async def broadcast(self, message: Dict[str, Any]):
        text = json.dumps(message)
        async with self.lock:
            to_remove: List[WebSocket] = []
            for ws in list(self.connections):
                try:
                    await ws.send_text(text)
                except Exception:
                    to_remove.append(ws)
            for ws in to_remove:
                if ws in self.connections:
                    self.connections.remove(ws)

manager = ConnectionManager()

# ----- HTTP helper for Facebook Graph calls -----
async def fb_get(path: str, params: Dict[str, Any]) -> Dict[str, Any]:
    url = f"https://graph.facebook.com/v17.0/{path}"
    async with httpx.AsyncClient(timeout=20.0) as client:
        r = await client.get(url, params=params)
        try:
            return r.json()
        except Exception:
            raise HTTPException(status_code=502, detail="Invalid response from Facebook")

async def fb_post(path: str, params: Dict[str, Any]) -> Dict[str, Any]:
    url = f"https://graph.facebook.com/v17.0/{path}"
    async with httpx.AsyncClient(timeout=20.0) as client:
        r = await client.post(url, data=params)
        try:
            return r.json()
        except Exception:
            raise HTTPException(status_code=502, detail="Invalid response from Facebook")

# ----- Parse Insights -> WorkspaceMetrics (best-effort) -----
def parse_facebook_insights_to_metrics(page_id: str, insights_response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert Graph API insights response into a metrics dict frontend expects.
    The Graph API returns `data` array where each item has `name`, `period`, `values`.
    We try to extract: impressions, clicks (if available), reach, ctr, cpm estimate, leads (not usually on page insights).
    This function returns a dict containing keys: workspace_id (placeholder), page_id, impressions, clicks, reach, ctr, cpm, total_spend (unknown), leads (unknown), last_updated
    Adjust mapping per your Graph API calls (ads insights vs page insights differ).
    """
    metrics: Dict[str, Any] = {
        "workspace_id": None,
        "page_id": page_id,
        "impressions": 0,
        "clicks": 0,
        "reach": 0,
        "ctr": 0.0,
        "cpm": 0.0,
        "total_spend": 0.0,
        "leads": 0,
        "active_campaigns": 0,
        "last_updated": int(asyncio.get_event_loop().time()) if asyncio.get_event_loop().is_running() else 0,
        "insights_raw": insights_response,
    }

    data = insights_response.get("data") or []
    # Common names: page_impressions, page_impressions_unique, page_engaged_users, page_fans, etc.
    for item in data:
        name = item.get("name")
        values = item.get("values") or []
        # try last value numeric
        last_value = None
        if values:
            last = values[-1]
            # `value` could be number or dict
            last_value = last.get("value") if isinstance(last, dict) else last

        if name in ("page_impressions", "page_impressions_unique"):
            try:
                metrics["impressions"] = int(last_value or 0)
            except Exception:
                pass
        elif name in ("page_engaged_users",):
            try:
                metrics["reach"] = int(last_value or 0)
            except Exception:
                pass
        elif name in ("page_fan_adds", "page_fan_removes"):
            # ignore for now
            pass
        # Add other mapping rules as needed

    # Ads-level metrics (if you call /act_{ad_account}/insights) would include 'impressions', 'clicks', 'spend', 'ctr', 'cpm'
    # Check if insights_response already has totals in a different shape (some endpoints return a single object with fields)
    # Try to extract ads-like fields if present:
    if isinstance(insights_response, dict):
        # sometimes metrics are top-level keys
        for k in ("impressions", "clicks", "spend", "ctr", "cpm"):
            if k in insights_response:
                try:
                    if k == "spend":
                        metrics["total_spend"] = float(insights_response[k])
                    elif k == "impressions":
                        metrics["impressions"] = int(insights_response[k])
                    elif k == "clicks":
                        metrics["clicks"] = int(insights_response[k])
                    elif k == "ctr":
                        metrics["ctr"] = float(insights_response[k])
                    elif k == "cpm":
                        metrics["cpm"] = float(insights_response[k])
                except Exception:
                    pass

    # heuristics: compute ctr if impressions and clicks available
    try:
        imps = metrics.get("impressions", 0)
        clicks = metrics.get("clicks", 0)
        if imps and clicks:
            metrics["ctr"] = round((clicks / imps) * 100, 2)
    except Exception:
        metrics["ctr"] = 0.0

    # attempt approximate CPM if we have spend and impressions
    try:
        if metrics.get("impressions") and metrics.get("total_spend"):
            metrics["cpm"] = round((metrics["total_spend"] / (metrics["impressions"] / 1000 or 1)), 2)
    except Exception:
        metrics["cpm"] = 0.0

    # active_campaigns & leads require Ads API / conversion tracking; leave defaults
    return metrics

# ----- ROUTES -----

    @app.get("/api/health")
    async def health():
        return {"status": "ok"}

    @app.get("/api/facebook/pages")
    async def list_pages():
        """
        Return pages we have stored (linked) with their metadata.
        """
        store = await read_storage()
        pages = list(store.get("pages", {}).values())
        return JSONResponse({"success": True, "pages": pages})

    @app.post("/api/facebook/unlink")
    async def unlink_page(req: Request):
        """
        Body: { pageId: '12345' }
        Removes stored page token and associated workspace mapping.
        """
        body = await req.json()
        page_id = str(body.get("pageId") or "")
        if not page_id:
            raise HTTPException(400, "pageId required")

        store = await read_storage()
        pages = store.get("pages", {})
        if page_id in pages:
            pages.pop(page_id, None)
            # remove mappings to workspace
            wsmap = store.get("workspace_map", {})
            to_delete = [k for k, v in wsmap.items() if str(v) == page_id]
            for k in to_delete:
                wsmap.pop(k, None)
            store["workspace_map"] = wsmap
            store["pages"] = pages
            await write_storage(store)
            # broadcast unlink event
            await manager.broadcast({"type": "page_unlinked", "payload": {"pageId": page_id}})
            return {"success": True, "message": "Page unlinked"}
        return {"success": False, "message": "Page not found"}

    @app.post("/api/facebook/switch")
    async def switch_account(req: Request):
        """
        Body: { workspaceId: 123, pageId: '67890' }
        Map workspace -> pageId so future refreshes attribute metrics to workspace.
        """
        body = await req.json()
        workspace_id = body.get("workspaceId")
        page_id = str(body.get("pageId") or "")
        if not workspace_id or not page_id:
            raise HTTPException(400, "workspaceId and pageId required")

        store = await read_storage()
        store.setdefault("workspace_map", {})[str(workspace_id)] = page_id
        await write_storage(store)
        await manager.broadcast({"type": "page_switched", "payload": {"workspaceId": workspace_id, "pageId": page_id}})
        return {"success": True}

    @app.post("/api/facebook/refresh")
    async def refresh_insights(req: Request):
        """
        Trigger server to fetch latest insights for a given page or all pages.
        Body: { pageId?: '123' }
        The server will fetch Graph API insights and broadcast messages to WS clients:
        - message type: 'metrics_update' with payload equal to parsed metrics (see parse_facebook_insights_to_metrics).
        """
        body = await req.json()
        page_id = body.get("pageId")

        store = await read_storage()
        pages = store.get("pages", {})
        targets: List[str] = [page_id] if page_id else list(pages.keys())
        if not targets:
            return {"success": False, "message": "No pages linked to refresh"}

        async def fetch_and_broadcast(pid: str):
            page = pages.get(pid)
            token = page.get("access_token") if page else None
            if not token:
                return False
            # Choose which insights to request. Adjust metrics list to your needs.
            metric = "page_impressions,page_engaged_users"
            params = {"access_token": token, "metric": metric, "period": "days_7"}
            try:
                data = await fb_get(f"{pid}/insights", params)
                metrics = parse_facebook_insights_to_metrics(pid, data)
                # attach workspace_id if mapped
                workspace_map = store.get("workspace_map", {})
                mapped_ws = None
                for wsid, p in (workspace_map.items() if isinstance(workspace_map, dict) else []):
                    if str(p) == str(pid):
                        mapped_ws = int(wsid) if str(wsid).isdigit() else wsid
                        break
                metrics["workspace_id"] = mapped_ws or metrics.get("workspace_id")
                # broadcast
                await manager.broadcast({"type": "metrics_update", "payload": metrics})
                return True
            except Exception as e:
                print("refresh error for", pid, e)
                return False

        results = await asyncio.gather(*(fetch_and_broadcast(pid) for pid in targets))
        ok = all(results)
        return {"success": ok}

    @app.post("/api/facebook/exchange_code")
    async def exchange_code(req: Request):
        """
        Exchanges an OAuth code for a user access token and fetches pages & page access tokens.
        Body: { code: string, redirect_uri: string }
        Returns: pages list with page access tokens (and stores them).
        IMPORTANT: In production you must validate state and associate tokens with the authenticated user (not shown here).
        """
        body = await req.json()
        code = body.get("code")
        redirect_uri = body.get("redirect_uri")
        if not code or not redirect_uri:
            raise HTTPException(400, "code and redirect_uri required")

        # Step 1: exchange code -> user access token
        exchange_params = {
            "client_id": FB_APP_ID,
            "redirect_uri": redirect_uri,
            "client_secret": FB_APP_SECRET,
            "code": code,
        }
        token_resp = await fb_get("oauth/access_token", exchange_params)
        user_token = token_resp.get("access_token")
        if not user_token:
            raise HTTPException(status_code=400, detail={"message": "Failed to exchange code", "details": token_resp})

        # Step 2: get pages (with page access tokens)
        # Request /me/accounts with user access token
        pages_resp = await fb_get("me/accounts", {"access_token": user_token})
        pages_data = pages_resp.get("data", [])
        stored = await read_storage()
        pages_store = stored.get("pages", {})
        for p in pages_data:
            pid = str(p.get("id"))
            # Graph returns `access_token` for page if user has sufficient permissions
            page_token = p.get("access_token")
            pages_store[pid] = {
                "id": pid,
                "name": p.get("name"),
                "category": p.get("category"),
                "access_token": page_token,
                # extra fields
            }
        stored["pages"] = pages_store
        await write_storage(stored)

        # return the pages list
        return {"success": True, "pages": list(pages_store.values()), "user_token": bool(user_token)}

    # ----- WebSocket endpoint -----
    @app.websocket("/ws/metrics")
    async def websocket_metrics(ws: WebSocket):
        """
        WebSocket for broadcasting metric updates.
        Message format:
        { type: 'metrics_update', payload: { workspace_id, page_id, impressions, clicks, ctr, cpm, total_spend, last_updated, insights_raw } }
        Clients can simply listen and merge payload into their metricsMap.
        """
        await manager.connect(ws)
        try:
            while True:
                # optionally, the client may send messages to subscribe; we currently ignore client messages
                try:
                    msg = await ws.receive_text()
                    # ignore; optionally parse subscription messages here
                except Exception:
                    # idle loop to keep alive; allow server to send broadcasts
                    await asyncio.sleep(0.1)
        except WebSocketDisconnect:
            await manager.disconnect(ws)
        except Exception:
            await manager.disconnect(ws)
            

from flask import jsonify, request
import requests
import json
from typing import Optional

# --- Helper: call Graph API with a token (safe wrapper) ---
def _graph_get(path: str, token: str, params: dict = None, timeout: int = 10):
    """
    GET to Graph API path (path may be like 'me' or '12345' or '12345/insights').
    Returns tuple (ok: bool, status_code: int, json_or_text)
    """
    params = params.copy() if params else {}
    params["access_token"] = token
    url = f"https://graph.facebook.com/{FB_API_VERSION}/{path}"
    try:
        resp = requests.get(url, params=params, timeout=timeout)
        # try parse json but return raw text if parse fails
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        return (resp.status_code == 200, resp.status_code, body)
    except Exception as exc:
        logger.exception("Graph GET failed for %s: %s", path, exc)
        return (False, 500, {"error": "exception", "details": str(exc)})

# --- 1) /api/social/accounts/db  (list DB accounts; alias for your existing route) ---
@app.route("/api/social/accounts/db", methods=["GET", "OPTIONS"])
def api_social_accounts_db():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    user = get_user_from_request(require=False)
    if user:
        accounts = SocialAccount.query.filter((SocialAccount.user_id == None) | (SocialAccount.user_id == user.id)).all()
    else:
        accounts = SocialAccount.query.filter_by(user_id=None).all()
    return jsonify({"success": True, "accounts": [a.serialize() for a in accounts]}), 200

# --- 2) /api/social/accounts/raw  (fetch current DB accounts + try to refresh Graph data for each) ---
@app.route("/api/social/accounts/raw", methods=["GET"])
def api_social_accounts_raw():
    """
    Returns an array of objects: { db: <serialized DB row>, fb_raw: <graph response or null>, error: <optional> }
    This helps the frontend show both DB state and the latest data from FB for each connected page.
    """
    user = get_user_from_request(require=False)
    accounts = SocialAccount.query.all()
    result = []
    for a in accounts:
        entry = {"db": a.serialize(), "fb_raw": None, "error": None}
        token = a.access_token or (get_facebook_token_for_user(user.id) if user else None)
        if token:
            ok, status, body = _graph_get(f"{a.provider_user_id}", token, params={"fields":"id,name,link,fan_count,category,instagram_business_account"})
            if ok:
                entry["fb_raw"] = body
            else:
                entry["error"] = {"status": status, "body": body}
        else:
            entry["error"] = {"message":"no_token_available"}
        result.append(entry)
    return jsonify({"success": True, "rows": result}), 200

# --- 3) /api/facebook/page-details?page_id=...&fields=...  (fetch FB page details/insights for a page) ---
@app.route("/api/facebook/page-details", methods=["GET"])
def api_facebook_page_details():
    """
    Query params:
      - page_id (required)
      - fields (optional, comma separated) default: id,name,link,fan_count,category,insights.metric(page_impressions,page_engaged_users).period(days_7)
      - since / until (optional) for insights time_range
    """
    page_id = request.args.get("page_id")
    if not page_id:
        return jsonify({"success": False, "error": "missing_page_id"}), 400

    # Try to find a DB SocialAccount for this page
    sa = SocialAccount.query.filter_by(provider="facebook", provider_user_id=str(page_id)).first()
    token = None
    if sa and sa.access_token:
        token = sa.access_token
    else:
        # fallback: current user's token
        user = get_user_from_request(require=False)
        if user:
            token = get_facebook_token_for_user(user.id)

    if not token:
        return jsonify({"success": False, "error": "no_token_available"}), 403

    # fields default
    fields = request.args.get("fields") or "id,name,link,fan_count,category,instagram_business_account"
    extra_params = {}
    # support insights query if user requested insights via fields param using Graph shorthand (frontend can pass)
    # but to make it easier: accept `insights=true` and since/until for insights
    if request.args.get("insights") == "true":
        since = request.args.get("since")
        until = request.args.get("until")
        if since and until:
            extra_params["time_range"] = json.dumps({"since": since, "until": until})
        # get some common metrics if not explicitly provided
        fields = fields + ",insights.metric(page_impressions,page_engaged_users,page_fans).period(days_7)"

    ok, status, body = _graph_get(f"{page_id}", token, params={"fields": fields, **extra_params}, timeout=20)
    if not ok:
        return jsonify({"success": False, "error": "fb_error", "details": body}), status
    return jsonify({"success": True, "page": body}), 200
 
# Add / paste into your Flask app file (below other imports & existing helpers)
from flask import request, jsonify
import json
import requests
from datetime import datetime

# ensure _graph_get exists (if not, add this helper)
def _graph_get(path: str, token: str, params: dict = None, timeout: int = 10):
    params = params.copy() if params else {}
    params["access_token"] = token
    url = f"https://graph.facebook.com/{FB_API_VERSION}/{path}"
    try:
        resp = requests.get(url, params=params, timeout=timeout)
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        return (resp.status_code == 200, resp.status_code, body)
    except Exception as exc:
        logger.exception("Graph GET failed for %s: %s", path, exc)
        return (False, 500, {"error": "exception", "details": str(exc)})

# --- 1) Full social management endpoint (list accounts + optionally live fb data) ---
@app.route("/api/social/management", methods=["GET", "OPTIONS"])
def api_social_management():
    """
    Return linked social accounts for the resolved user.

    Resolution order:
      1) get_user_from_request(require=False)   (session or bearer token)
      2) optional fallback: request.args['user_id'] or JSON['user_id'] when
         current_app.config['ALLOW_REQUEST_USER_ID_FALLBACK'] is True (dev-only)

    Returns 401 when no user could be resolved.
    """
    DEFAULT_USER_ID = None  # legacy default removed; require explicit user or explicit fallback

    # read JSON if present (silent to avoid parse errors)
    data = request.get_json(silent=True) or {}

    # 1) try normal resolution (session / token)
    user = get_user_from_request(require=False)

    # 2) optional dev fallback: explicit user_id in query or body
    if not user:
        fallback_uid = request.args.get("user_id") or data.get("user_id")
        if fallback_uid and current_app.config.get("ALLOW_REQUEST_USER_ID_FALLBACK"):
            try:
                fallback_uid = int(fallback_uid)
                user = User.query.get(fallback_uid)
                if user:
                    current_app.logger.warning(
                        f"api_social_management used fallback user_id={fallback_uid} from request. "
                        "Enable fallback only for development."
                    )
            except Exception as e:
                current_app.logger.warning(f"Invalid fallback user_id provided to api_social_management: {fallback_uid} ({e})")
                user = None

    # If still no user, return 401
    if not user:
        return jsonify({"success": False, "error": "unauthorized", "message": "user not authenticated"}), 401

    # Only return accounts for this user
    accounts = SocialAccount.query.filter_by(user_id=user.id).order_by(SocialAccount.id.desc()).all()

    rows = []
    active = None

    for a in accounts:
        item = {"db": a.serialize(), "fb_raw": None, "error": None}

        # Prefer account access_token; otherwise try to fetch a token for this user
        token = a.access_token or get_facebook_token_for_user(user.id)

        if token:
            ok, status, body = _graph_get(
                f"{a.provider_user_id}",
                token,
                params={"fields": "id,name,link,fan_count,category,picture.width(200).height(200),instagram_business_account"},
            )
            if ok:
                item["fb_raw"] = body
            else:
                item["error"] = {"status": status, "body": body}
        else:
            item["error"] = {"message": "no_token_available"}

        rows.append(item)

        try:
            if getattr(user, "active_social_account_id", None) == a.id:
                active = a.serialize()
        except Exception:
            pass

    # If no active and rows exist, optionally set first as active (keeping previous behavior)
    if active is None and rows:
        active = rows[0]["db"]

    return jsonify({"success": True, "accounts": rows, "active_account": active}), 200


from flask import g, session, request, jsonify

@app.before_request
def load_user():
    user_id = session.get("user_id")
    if user_id:
        g.user = User.query.get(user_id)
    else:
        g.user = None

# --- 2) Update permissions / scopes for a social account ---

# Fix permissions endpoint to always save under user 1
@app.route("/api/social/permissions", methods=["POST"])
def api_social_permissions():
    """
    Update social account permissions.

    Behavior:
      1. Resolve user via get_user_from_request(require=False).
      2. If not found and app.config["ALLOW_REQUEST_USER_ID_FALLBACK"] is True,
         attempt to use `user_id` from request JSON or query as a fallback (dev-only).
      3. Validate provider/provider_user_id and update `scopes`.
      4. Assign the account to the resolved user (account.user_id = user.id).
    Notes:
      - Accepting user_id from requests is insecure for production; enable only for dev/debug.
      - If you prefer not to reassign account ownership, add a check preventing reassignment.
    """
    data = request.get_json(silent=True) or {}

    # Resolve user (session / token)
    user = get_user_from_request(require=False)

    # Optional fallback: accept explicit user_id in request (dev-only)
    if not user:
        fallback_uid = data.get("user_id") or request.args.get("user_id")
        if fallback_uid and current_app.config.get("ALLOW_REQUEST_USER_ID_FALLBACK"):
            try:
                fallback_uid = int(fallback_uid)
                user = User.query.get(fallback_uid)
                if user:
                    current_app.logger.warning(
                        f"api_social_permissions used fallback user_id={fallback_uid} from request. "
                        "Enable fallback only for development."
                    )
            except Exception as e:
                current_app.logger.warning(f"Invalid fallback user_id provided: {fallback_uid} ({e})")
                user = None

    if not user:
        return jsonify({"success": False, "error": "unauthorized"}), 401

    provider = data.get("provider")
    provider_user_id = str(data.get("provider_user_id") or "")

    if not provider or not provider_user_id:
        return jsonify({"success": False, "error": "missing_required_fields"}), 400

    # Normalize scopes input: accept list or comma-separated string
    scopes = data.get("scopes", [])
    if isinstance(scopes, str):
        # allow either "a,b,c" or "a, b, c"
        scopes = [s.strip() for s in scopes.split(",") if s.strip()]
    elif isinstance(scopes, (list, tuple)):
        scopes = [str(s).strip() for s in scopes if str(s).strip()]
    else:
        scopes = []

    account = SocialAccount.query.filter_by(
        provider=provider,
        provider_user_id=provider_user_id
    ).first()

    if not account:
        return jsonify({"success": False, "error": "account_not_found"}), 404

    try:
        account.scopes = ",".join(scopes)
        # assign/ensure this account is associated with the resolved user
        account.user_id = user.id

        db.session.add(account)
        db.session.commit()

        return jsonify({
            "success": True,
            "account": account.serialize() if hasattr(account, "serialize") else {
                "id": account.id,
                "provider": account.provider,
                "provider_user_id": account.provider_user_id,
                "scopes": account.scopes,
                "user_id": account.user_id
            }
        })

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Failed to update social permissions")
        return jsonify({
            "success": False,
            "error": "db_error",
            "message": str(e)
        }), 500

@app.route("/api/social/unlink", methods=["POST"])
def api_social_unlink():
    """Unlink social account.

    Behavior:
      1. Try to resolve user via get_user_from_request(require=False).
      2. If not found, look for user_id in request JSON or query parameters
         and try to load that user (fallback).
      3. If still not found -> 401.
    NOTE: Accepting user_id from requests is a fallback for testing/dev only;
    don't rely on it in production unless you have additional safeguards.
    """
    # read JSON early (silent=True to avoid exceptions on non-json bodies)
    data = request.get_json(silent=True) or {}

    # 1) try normal resolution (session / token helpers)
    user = get_user_from_request(require=False)

    # 2) fallback: if no user, check for explicit user_id in payload or query
    if not user:
        fallback_uid = data.get("user_id") or request.args.get("user_id")
        if fallback_uid:
            try:
                fallback_uid = int(fallback_uid)
                # attempt to fetch the User by id
                user = User.query.get(fallback_uid)
                if user:
                    # warn in logs so you can detect fallback usage
                    current_app.logger.warning(
                        f"api_social_unlink used fallback user_id={fallback_uid} from request. "
                        "Ensure this is intended (dev-only)."
                    )
            except Exception as e:
                current_app.logger.warning(f"Invalid fallback user_id provided: {fallback_uid} ({e})")
                user = None

    if not user:
        return jsonify({"success": False, "error": "unauthorized"}), 401

    # validate request body after user resolution
    provider = data.get("provider")
    provider_user_id = str(data.get("provider_user_id") or "")

    if not provider or not provider_user_id:
        return jsonify({"success": False, "error": "missing_required_fields"}), 400

    account = SocialAccount.query.filter_by(
        provider=provider,
        provider_user_id=provider_user_id,
        user_id=user.id
    ).first()

    if not account:
        return jsonify({"success": False, "error": "account_not_found"}), 404

    try:
        # Try to revoke at Facebook if we have token
        if account.access_token:
            try:
                revoke_url = f"https://graph.facebook.com/{FB_API_VERSION}/me/permissions"
                requests.delete(
                    revoke_url,
                    params={"access_token": account.access_token},
                    timeout=10
                )
            except Exception as e:
                current_app.logger.warning(f"Failed to revoke FB token: {e}")

        db.session.delete(account)
        db.session.commit()

        return jsonify({"success": True})

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Failed to unlink social account")
        return jsonify({
            "success": False,
            "error": "db_error",
            "message": str(e)
        }), 500

       
        # --- 5) Current active profile summary for UI (picture/name/fan_count etc) ---
@app.route("/api/social/active-profile", methods=["GET"])
def api_social_active_profile():
    user = get_user_from_request(require=True)
    active_id = getattr(user, "active_social_account_id", None)
    if not active_id:
        return jsonify({"success": False, "error": "no_active_account"}), 404
    sa = SocialAccount.query.get(active_id)
    if not sa:
        return jsonify({"success": False, "error": "active_account_not_found"}), 404
    token = sa.access_token or get_facebook_token_for_user(user.id)
    if not token:
        return jsonify({"success": False, "error": "no_token_available"}), 403
    ok, status, body = _graph_get(f"{sa.provider_user_id}", token, params={"fields":"id,name,link,fan_count,picture.width(200).height(200),category,instagram_business_account"})
    if not ok:
        return jsonify({"success": False, "error": "fb_error", "details": body}), status
    return jsonify({"success": True, "profile": body, "db": sa.serialize()}), 200


# --- facebook_insights_routes.py ---
import requests
import json
from datetime import datetime, timedelta
from flask import request, jsonify

# Helpers: _graph_get
def _graph_get(path_or_node: str, access_token: str, params: dict = None, timeout: int = 10):
    """
    Simple helper to call the Facebook Graph API GET endpoint.
    path_or_node: "12345" or "12345/posts" etc.
    access_token: token string
    returns: (ok: bool, status_code: int, body: dict or text)
    """
    params = params or {}
    params["access_token"] = access_token
    url = f"https://graph.facebook.com/{FB_API_VERSION}/{path_or_node.lstrip('/')}"
    try:
        r = requests.get(url, params=params, timeout=timeout)
        try:
            body = r.json()
        except Exception:
            body = r.text
        ok = (r.status_code == 200)
        return ok, r.status_code, body
    except Exception as exc:
        logger.exception("_graph_get exception for %s: %s", path_or_node, exc)
        return False, 0, {"error": "request_exception", "details": str(exc)}

# Helper: attempt to find a SocialAccount for user 1 (or find first)
def _choose_account_for_default_user(default_uid=1, provider="facebook", provider_user_id: str = None):
    """
    If provider_user_id provided, look that up first.
    Otherwise prefer accounts for user_id == default_uid, else first account.
    Returns (SocialAccount instance or None)
    """
    if provider_user_id:
        sa = SocialAccount.query.filter_by(provider=provider, provider_user_id=str(provider_user_id)).first()
        if sa:
            return sa
    # try user default
    sa = SocialAccount.query.filter_by(provider=provider, user_id=default_uid).order_by(SocialAccount.id.desc()).first()
    if sa:
        return sa
    # fallback: any account
    sa = SocialAccount.query.filter_by(provider=provider).order_by(SocialAccount.id.desc()).first()
    return sa

# Route: page details (used by FacebookManager.refreshRow)
@app.route("/api/facebook/page-details2", methods=["GET"])
def api_facebook_page_details2():
    """
    GET params:
      page_id (provider_user_id) - optional; if not provided we try to pick user 1's account
      insights (bool) - if true, also include basic insights (not used heavily)
    Returns:
      { success: true, page: {...} } or error
    """
    page_id = request.args.get("page_id") or request.args.get("provider_user_id")
    include_insights = request.args.get("insights", "false").lower() in ("1", "true", "yes")

    # Choose SocialAccount (prefer provided id > user 1 > first)
    sa = _choose_account_for_default_user(default_uid=1, provider="facebook", provider_user_id=page_id)
    if not sa:
        return jsonify({"success": False, "error": "no_social_account_found"}), 404

    token = sa.access_token or None
    if not token:
        # if you have a function to fetch app token, use it as a last resort
        token = f"{FB_APP_ID}|{FB_APP_SECRET}"

    # get page basic fields
    ok, status, body = _graph_get(f"{sa.provider_user_id}", token, params={"fields": "id,name,link,fan_count,category,picture.width(200).height(200)"})
    if not ok:
        return jsonify({"success": False, "error": "graph_error", "status": status, "body": body}), status if status else 500

    page_obj = body if isinstance(body, dict) else {"raw": body}

    # optional: add a few lightweight insights (page impressions last 7 days)
    if include_insights:
        since = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
        until = datetime.utcnow().strftime("%Y-%m-%d")
        metrics = "page_impressions,page_engaged_users"
        ok_i, s_i, b_i = _graph_get(f"{sa.provider_user_id}/insights", token, params={"metric": metrics, "since": since, "until": until})
        if ok_i and isinstance(b_i, dict):
            page_obj["insights"] = b_i.get("data", b_i)
        else:
            page_obj["insights_error"] = {"status": s_i, "body": b_i}

    return jsonify({"success": True, "page": page_obj})

# Route: insights (page metrics + posts summary) used by FacebookInsights.tsx
@app.route("/api/facebook/insights2", methods=["GET"])
def api_facebook_insights2():
    """
    Query params:
      provider_user_id (page id) optional -> if missing, pick first account for user 1
      limit (optional) number of posts to fetch (default 10)
    Returns:
      { success: true, page_insights: {...}, posts: [...] }
    """
    provider_user_id = request.args.get("provider_user_id")
    limit = int(request.args.get("limit") or 10)

    # pick account
    sa = _choose_account_for_default_user(default_uid=1, provider="facebook", provider_user_id=provider_user_id)
    if not sa:
        return jsonify({"success": False, "error": "no_social_account_found"}), 404

    token = sa.access_token or None
    if not token:
        token = f"{FB_APP_ID}|{FB_APP_SECRET}"  # fall back to app token (may have limited access)

    page_id = sa.provider_user_id

    # 1) Basic page fields
    ok_page, status_page, page_body = _graph_get(f"{page_id}", token, params={"fields":"id,name,link,fan_count,category,picture.width(200).height(200)"})
    if not ok_page:
        return jsonify({"success": False, "error": "page_fetch_failed", "details": {"status": status_page, "body": page_body}}), status_page if status_page else 500

    # 2) Fetch recent insights (last 30 days)
    try:
        since_date = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d")
        until_date = datetime.utcnow().strftime("%Y-%m-%d")
        # request some common page-level metrics
        metrics = "page_impressions,page_engaged_users,page_consumptions,page_views_total"
        ok_i, status_i, insights_body = _graph_get(f"{page_id}/insights", token, params={"metric": metrics, "since": since_date, "until": until_date})
    except Exception as e:
        ok_i, status_i, insights_body = False, 0, {"error": str(e)}

    page_insights = {}
    if ok_i and isinstance(insights_body, dict):
        try:
            # Graph returns data array where each element has 'name' and 'values'
            for item in insights_body.get("data", []):
                name = item.get("name")
                values = item.get("values") or []
                # pick last value numeric
                if values:
                    last_val = values[-1].get("value")
                    page_insights[name] = last_val
            # Normalize into the fields frontend expects
            page_insights_normalized = {
                "fan_count": page_body.get("fan_count"),
                "talking_about_count": page_insights.get("page_engaged_users") or 0,
                "page_views": page_insights.get("page_views_total") or 0,
                "page_impressions": page_insights.get("page_impressions") or 0,
                "engagement_rate": 0.0,
            }
            # compute engagement_rate if possible
            try:
                impressions = float(page_insights_normalized.get("page_impressions") or 0) or 1
                engaged = float(page_insights_normalized.get("talking_about_count") or 0)
                page_insights_normalized["engagement_rate"] = round((engaged / impressions) * 100, 2) if impressions else 0.0
            except Exception:
                page_insights_normalized["engagement_rate"] = 0.0
        except Exception as exc:
            logger.exception("Failed to normalize insights: %s", exc)
            page_insights_normalized = {
                "fan_count": page_body.get("fan_count"),
                "talking_about_count": None,
                "page_views": None,
                "page_impressions": None,
                "engagement_rate": None,
            }
    else:
        # graph insights failed; return basic placeholders
        page_insights_normalized = {
            "fan_count": page_body.get("fan_count"),
            "talking_about_count": None,
            "page_views": None,
            "page_impressions": None,
            "engagement_rate": None,
            "insights_error": {"status": status_i, "body": insights_body}
        }

    # 3) Fetch recent posts and simple metrics (likes/comments/shares)
    posts_result = []
    try:
        # request posts with comment & reaction counts and shares
        fields = "id,message,created_time,shares,comments.limit(0).summary(true),reactions.limit(0).summary(true)"
        ok_p, status_p, posts_body = _graph_get(f"{page_id}/posts", token, params={"fields": fields, "limit": limit})
        if ok_p and isinstance(posts_body, dict):
            for p in posts_body.get("data", []):
                pid = p.get("id")
                message = p.get("message")
                created_time = p.get("created_time")
                shares = (p.get("shares") or {}).get("count", 0)
                comments = (p.get("comments") or {}).get("summary", {}).get("total_count", 0)
                reactions = (p.get("reactions") or {}).get("summary", {}).get("total_count", 0)
                posts_result.append({
                    "id": pid,
                    "message": message,
                    "created_time": created_time,
                    "likes": reactions,
                    "comments": comments,
                    "shares": shares,
                    "raw": p
                })
        else:
            # try older "feed" endpoint fallback
            posts_result = []
    except Exception as exc:
        logger.exception("Failed to fetch posts for %s: %s", page_id, exc)
        posts_result = []

    response = {
        "success": True,
        "page": page_body,
        "page_insights": page_insights_normalized,
        "posts": posts_result,
    }
    return jsonify(response)
@app.route("/api/workspace/assets", methods=["GET"])
def api_workspace_assets():
    try:
        workspace_id = request.args.get("workspace_id") or request.args.get("id")
        if not workspace_id:
            return jsonify({"success": False, "error": "bad_request", "details": "workspace_id required"}), 400
        try:
            wid = int(workspace_id)
        except Exception:
            return jsonify({"success": False, "error": "bad_request", "details": "workspace_id must be integer"}), 400

        ws = Workspace.query.filter_by(id=wid).first()
        if not ws:
            return jsonify({"success": True, "assets": []}), 200

        def _parse_paths_field(field_value):
            if not field_value:
                return []
            if isinstance(field_value, list):
                return [str(x) for x in field_value if x]
            if isinstance(field_value, dict):
                return []
            if isinstance(field_value, str):
                s = field_value.strip()
                try:
                    parsed = json.loads(s)
                    if isinstance(parsed, list):
                        return [str(x) for x in parsed if x]
                except Exception:
                    pass
                parts = [p.strip() for p in s.split(",") if p.strip()]
                if parts:
                    return parts
                return [s]
            return []

        # try multiple attribute names safely
        creatives_field = (
            getattr(ws, "creatives_paths", None)
            or getattr(ws, "creatives_path", None)
            or getattr(ws, "creatives", None)
            or getattr(ws, "creatives_list", None)
        )
        cp = _parse_paths_field(creatives_field)

        assets_out = []
        for p in cp:
            url = p
            if not (p.startswith("http://") or p.startswith("https://")):
                try:
                    url = url_for("uploaded_workspace_file", user_id=ws.user_id, filename=os.path.basename(p), _external=True)
                except Exception:
                    url = p
            ext = os.path.splitext(p)[1].lower()
            atype = "image" if ext in [".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp"] else "file"
            assets_out.append({"name": os.path.basename(p) or p, "url": url, "type": atype})

        # if still empty, try a JSON 'creatives' structure (objects)
        if not assets_out and getattr(ws, "creatives", None):
            raw_creatives = getattr(ws, "creatives")
            try:
                parsed = json.loads(raw_creatives) if isinstance(raw_creatives, str) else raw_creatives
                if isinstance(parsed, list):
                    for c in parsed:
                        u = c.get("url") or c.get("path") or c.get("src")
                        if u and not (u.startswith("http://") or u.startswith("https://")):
                            try:
                                u = url_for("uploaded_workspace_file", user_id=ws.user_id, filename=os.path.basename(u), _external=True)
                            except Exception:
                                pass
                        assets_out.append({"name": c.get("name") or os.path.basename(u or ""), "url": u, "type": c.get("type") or "file"})
            except Exception:
                current_app.logger.exception("parsing creatives JSON failed")

        return jsonify({"success": True, "assets": assets_out}), 200

    except Exception as e:
        current_app.logger.exception("api_workspace_assets failed")
        return jsonify({"success": False, "error": "internal_server_error", "details": str(e)}), 500
# ---------- Helper: safe parse creatives list ----------
def _parse_paths_field(field_value):
    """
    Accepts:
      - None -> []
      - JSON string -> parsed list
      - list -> list
      - comma-separated string -> split
    Returns list of strings.
    """
    if not field_value:
        return []
    if isinstance(field_value, list):
        return [str(x) for x in field_value if x]
    if isinstance(field_value, (dict, int, float)):
        # unexpected types -> empty
        return []
    if isinstance(field_value, str):
        s = field_value.strip()
        # try JSON parse
        try:
            parsed = json.loads(s)
            if isinstance(parsed, list):
                return [str(x) for x in parsed if x]
        except Exception:
            pass
        # fallback comma-split
        parts = [p.strip() for p in s.split(",") if p.strip()]
        return parts
    return []
#------------------------creatiives pipeline merge--------------------------

# ai_image_backend.py
# Full backend with:
#  - theme generation and per-theme social content (caption/hashtags/cta/alt_text)
#  - image generation (single & multi-image)
#  - edit endpoint supporting both models.generate_content and chat-based edit (client.chats.create)
#  - ImageConfig shim fallback for older google-genai SDKs
#  - Modified to save assets to DigitalOcean Spaces (S3-compatible) in an organized manner (outputs/ for generated, saved/ for saved)
#  - Added background cleanup for outputs/ objects older than 24 hours
#  - Added SQLAlchemy integration to store generated and saved URLs in 'creatives' table with user_id and workspace_id
#  - Added Conversation model to save each prompt/response as a conversation in 'conversations' table, including image URLs

# -*- coding: utf-8 -*-
import os
import sys
import uuid
import mimetypes
import base64
import json
import re
import textwrap
import threading
import urllib.request
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from urllib.parse import urljoin 

import boto3
from botocore.exceptions import ClientError

from flask import Flask, render_template, request, jsonify, send_from_directory, abort, make_response, redirect
from flask_cors import CORS


# google-genai SDK imports (may vary by SDK version)
from google import genai
from google.genai.types import HttpOptions, Part, GenerateContentConfig

# ImageConfig may not exist in older SDKs — provide a robust fallback
try :
    from google.genai.types import ImageConfig  # type: ignore
    IMAGE_CONFIG_IS_CLASS = True
except Exception:
    # fallback builder — returns a plain dict or simple object usable by GenerateContentConfig
    def ImageConfig(**kwargs):
        # return a plain dict — many SDK wrappers accept dicts for nested config on older versions
        return kwargs
    IMAGE_CONFIG_IS_CLASS = False

# --- Configuration ---
MODEL_ID = os.environ.get("MODEL_ID", "gemini-2.5-flash-image-preview")  # image-capable model
TEXT_MODEL = os.environ.get("TEXT_MODEL", "gemini-flash-latest")        # text-capable model

# DigitalOcean Spaces configuration
SPACE_NAME = 'sociovia'
SPACE_REGION = 'blr1'
SPACE_ENDPOINT = f'https://{SPACE_REGION}.digitaloceanspaces.com'
SPACE_CDN = 'https://sociovia.blr1.cdn.digitaloceanspaces.com'
ACCESS_KEY = "DO801KRD6VWJZMATNUEB"
SECRET_KEY = "M9iHgem8RnrKjxDrL4Sq8im6SKHglHdGTmFoFRTX42k"

# Initialize S3 client
if ACCESS_KEY and SECRET_KEY:
    s3 = boto3.client('s3',
                      aws_access_key_id=ACCESS_KEY,
                      aws_secret_access_key=SECRET_KEY,
                      endpoint_url=SPACE_ENDPOINT)
    print("[startup] S3 client initialized for DigitalOcean Spaces.")
else:
    s3 = None
    print("[startup] Warning: DO_ACCESS_KEY_ID or DO_SECRET_ACCESS_KEY not set. Cannot use Spaces storage.", file=sys.stderr)

# Local index for saved images (consider moving to DB for production)
OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "outputs"))  # Local temp if needed, but not used for storage
SAVED_INDEX_PATH = os.path.join(OUTPUT_DIR, "saved_index.json")
os.makedirs(OUTPUT_DIR, exist_ok=True)  # For index only
_saved_index_lock = threading.Lock()

EXTERNAL_BASE_URL = os.environ.get("EXTERNAL_BASE_URL")  # e.g. "https://ai.example.com"
if not EXTERNAL_BASE_URL:
    EXTERNAL_BASE_URL = "http://127.0.0.1:5000"
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 10_485_760))  # 10 MB default
DOWNLOAD_TIMEOUT = int(os.environ.get("DOWNLOAD_TIMEOUT", 15))  # seconds for external downloads


# --- Init GenAI client (Vertex mode) ---
import os, json, tempfile
from google import genai
from google.genai.types import HttpOptions

def init_client():
    # Hardcoded credentials (paste your full JSON content below)
    SERVICE_ACCOUNT_JSON = {
  "type": "service_account",
  "project_id": "angular-sorter-473216-k8",
  "private_key_id": "8162683bcc131e691f316cfa3c801a5d2f7d2ac6",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCofJjdlfKPPcu7\nLyLXFphE8upuVNV4WtE34Pr4hXf5IFqR9jgM91lVeSMCxpUUC1WJlK8QOGyYvJn8\nNvv1vTNpUr+qTFiJ1GMW5MAnz07SuBzyT91LItUpUjWu+gp4hnZREudoGSOo1RsE\nBWqiP68CthekICQaTf+Kvr0JmttEi1UUihHAm79eB+Mq9i/G1Yqrlrwyh1d4MjVX\nz7Ys+2YPIc9+qF3SXBxe5fTKXHxkVrnxJDauF+RTJI0tVgxAXzxHyFUXzkwErZWT\nTfwJOUEVXsFZ3ped+bcATxumTYrunpPbDv+8kRKqoZhYwHrDA2JeWB6gYKKqa8yU\nQE6t6CHjAgMBAAECggEAHXBf2V/I2QRoI5Wx1bkp8+op0gtanUPpCIVz9JaFhu8D\nRDusQX+6iTe4SVTfWXg9guOKzx+8wdc6ZJpK3f4oDIAb4yqh0btdcPOZK5uKX0Ey\nNZiExwsYCbdGkAM6byK3a6UM7+BsnaRWqxYzMpREBQpCCThgdoQoYVrAdvwq0cfp\nme9g2Y6kmhueKYf1X15jadQAKjdhh6GdufBra/exhjpGpfpr1uM3dGeyEc+QX5jW\nIILyO+i1qzeL60+dbT1Q3Z2Ww9Jyup92d/LX2oOEuwU0qI2j7gYV1rgd7qi0EBWx\nH39a0bLiVEjfXsly2DyzgiAdc6Hcw246RqRO7tInKQKBgQDn6fTqMC8xf8/61u6Z\nTRbFb0jREvan79+q8D/y02tJ2r95wnsDlktE0OVuclZlpc1ge/2s5gz2clwiciao\nezKthe0ETh+fG4hKQ+jI11aXCuWvoThNNTQbhT9BU8mDXQpYGVQsTpuNjs5T2lqz\n0nZHDBnLz9305uAEudBAoPdVNQKBgQC5/ELd0A+YBfZxWHnOsaQPS+wLIeZ+gVgT\ntBVVNwUn5g1/BWoNriuSgUznsYYHYcxyQ+BBmMLALwv/FvHwSB6gnw92wv46g0lx\nJl1m8PotanL+26zJFipqCIhQv2uq6EJcU01c/E6hf0h9Cj07OIxOvoXIev3DQ46x\ni3Z7CKV1twKBgCtetU6WdDztihd+2mAQ6pFBnnx672W4ljuBcnQW1ZmaLvS2SgsB\nsFHOPxnIiB+6Qg4pIeeTnhj4igJnFpOrdm68/PYxJfi7TWGWEZJ9stPMVefiXoUR\nzgzXflzZLnZCkAypr/QZPz3Z1vwXeZ7nXPcsbCaRWRDTnFFF7ownjhmBAoGAObVD\nTi4T2JjpCexpBzBpdnGZUS74pQIfQSXchK9owyOHxoT4jjwfuvqx0SZtLvcyh7X1\n7ISo0RcIAuOsuGC4WCBinPgOCDvaWuiLjLhy+AqSme+xokdla7cwDNYIY2Rjyt/y\nHksPXt7usBWwQCLgrkJBop4/BQp+SSq73ZsmM+sCgYEAs4/2Ed3hZW0dsVxntNCb\nfi0ShGAiK6yHwKa8gio3+1bCvfZz23O2PQxPRjNTF5WnQST6yMR/72wNX7SvRzai\nz5RVEV9Dt9H09DMuLO3q8xtLyanBv3LM6P+/n+JMYF1+xo6HGzGqmEAL/EzjOORQ\nMM5pl3UI0wH26s+06b4p4tE=\n-----END PRIVATE KEY-----\n",
  "client_email": "sql-sa@angular-sorter-473216-k8.iam.gserviceaccount.com",
  "client_id": "105513727061092469003",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/sql-sa%40angular-sorter-473216-k8.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}
    project = SERVICE_ACCOUNT_JSON["project_id"]
    location = os.environ.get("GOOGLE_CLOUD_LOCATION") or "global"

    # Write the ADC JSON to a temporary file
    adc_path = os.path.join(tempfile.gettempdir(), "adc.json")
    with open(adc_path, "w") as f:
        json.dump(SERVICE_ACCOUNT_JSON, f)

    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = adc_path

    print("[env] GCP_PROJECT:", project)
    print("[env] LOCATION:", location)
    print("[env] ADC PATH:", adc_path)
    print("[env] ADC EXISTS:", os.path.exists(adc_path))

    try:
        client = genai.Client(
            http_options=HttpOptions(api_version="v1"),
            project=project,
            location=location,
            vertexai=True,
        )
        print("[startup] genai.Client initialized (Vertex mode).")
        return client
    except Exception as e:
        print("[startup] genai.Client init FAILED:", e)
        return None

GENAI_CLIENT = init_client()
if not GENAI_CLIENT:
    print("Warning: GENAI_CLIENT not initialized. Ensure google-genai is installed and ADC is configured.", file=sys.stderr)

# --- Saved-index utilities (local for now) ---
def _load_saved_index() -> Dict[str, Any]:
    with _saved_index_lock:
        if not os.path.exists(SAVED_INDEX_PATH):
            return {}
        try:
            with open(SAVED_INDEX_PATH, "r", encoding="utf-8") as f:
                return json.load(f) or {}
        except Exception as e:
            print("[saved_index] failed to load index:", e)
            return {}

def _save_saved_index(index: Dict[str, Any]):
    with _saved_index_lock:
        tmp = SAVED_INDEX_PATH + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(index, f, indent=2, ensure_ascii=False)
            os.replace(tmp, SAVED_INDEX_PATH)
        except Exception as e:
            print("[saved_index] failed to write index:", e)

# ensure index loaded on startup (lazy)
_SAVED_INDEX = _load_saved_index()

def _register_saved(id: str, meta: Dict[str, Any]):
    global _SAVED_INDEX
    _SAVED_INDEX = _SAVED_INDEX or {}
    _SAVED_INDEX[id] = meta
    _save_saved_index(_SAVED_INDEX)

# --- Helpers to save binary/image parts from GenAI response to Spaces ---
def _save_inline_part(inline, prefix="img"):
    data = getattr(inline, "data", None)
    if not data:
        return None
    if isinstance(data, str):
        try:
            data = base64.b64decode(data)
        except Exception as e:
            print("[save] inline base64 decode failed:", e)
            return None
    if not isinstance(data, (bytes, bytearray)):
        print("[save] inline data not bytes, skipping")
        return None
    mime = getattr(inline, "mime_type", "image/png") or "image/png"
    ext = mimetypes.guess_extension(mime) or ".png"
    fname = f"{prefix}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}_{uuid.uuid4().hex}{ext}"
    key = f"outputs/{fname}"  # Organized under outputs/
    if not s3:
        print("[save] S3 client not available")
        return None
    try:
        s3.put_object(Bucket=SPACE_NAME, Key=key, Body=data, ContentType=mime, ACL='public-read')
        print(f"[save] uploaded {key} to {SPACE_NAME}")
        return fname
    except Exception as e:
        print("[save] upload failed:", e)
        return None

def save_images_from_response(response, prefix="img"):
    saved = []
    for ci, cand in enumerate(getattr(response, "candidates", []) or []):
        content = getattr(cand, "content", None)
        if not content:
            continue
        for pi, part in enumerate(getattr(content, "parts", []) or []):
            inline = getattr(part, "inline_data", None)
            if inline and getattr(inline, "data", None):
                fname = _save_inline_part(inline, prefix=f"{prefix}_c{ci}_p{pi}")
                if fname:
                    saved.append(fname)
    return saved

# --- Background cleanup for outputs/ (24hr expiry) ---
def cleanup_outputs():
    while True:
        time.sleep(3600)  # Run every hour
        if not s3:
            continue
        try:
            now = datetime.now(timezone.utc)
            continuation_token = None
            while True:
                kwargs = {
                    'Bucket': SPACE_NAME,
                    'Prefix': 'outputs/',
                    'MaxKeys': 1000
                }
                if continuation_token:
                    kwargs['ContinuationToken'] = continuation_token
                response = s3.list_objects_v2(**kwargs)
                for obj in response.get('Contents', []):
                    if now - obj['LastModified'] > timedelta(hours=24):
                        s3.delete_object(Bucket=SPACE_NAME, Key=obj['Key'])
                        print(f"[cleanup] Deleted expired object: {obj['Key']}")
                if response.get('IsTruncated'):
                    continuation_token = response.get('NextContinuationToken')
                else:
                    break
        except Exception as e:
            print("[cleanup] Failed to clean outputs:", e)

# Start cleanup thread if s3 is available
if s3:
    cleanup_thread = threading.Thread(target=cleanup_outputs, daemon=True)
    cleanup_thread.start()
    print("[startup] Started background cleanup thread for outputs/")

# --- Flask app ---

app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://dbuser:StrongPasswordHere@34.10.193.3:5432/postgres"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Define Creative model


# Define Conversation model
class Conversation(db.Model):
    __tablename__ = 'conversationss'
    id = db.Column(db.String(32), primary_key=True)
    user_id = db.Column(db.String(128), nullable=False)
    workspace_id = db.Column(db.String(128), nullable=False)
    prompt = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))



def _build_base_url():
    return EXTERNAL_BASE_URL.rstrip("/")

def escape_for_inline(s: str) -> str:
    if s is None:
        return ""
    return s.replace("\\", "\\\\").replace('"', '\\"')

# --- master prompt for themes (updated to NOT force image-only) ---
def master_prompt_json(user_input: str, *, has_image: bool = False,
                       image_hint: Optional[str] = None,
                       num_themes: int = 3,
                       include_example: bool = True) -> str:
    ui_raw = (user_input or "").strip()
    ui = escape_for_inline(ui_raw)
    if num_themes < 1:
        num_themes = 1

    img_note = ""
    if has_image:
        # IMPORTANT: treat uploaded image as branding by default and prioritize user's prompt
        img_note = (
            "If an image/logo is provided, treat it primarily as a branding/logo asset and prioritize "
            "the user's textual prompt for message, tone and content. Do NOT let the image content "
            "override the user's explicit instructions. Provide logo placement suggestions if relevant."
        )
        if image_hint:
            img_note += f" Image hint: {escape_for_inline(image_hint)}."

    example = ""
    if include_example:
        example_obj = {
            "title": "Sunlit Alley",
            "one_line": "A quiet narrow alley at golden hour with scattered leaves.",
            "visual_prompt": ("Wide-angle composition, low sun backlighting, long shadows, "
                              "35mm lens, warm golden palette, wet cobblestone reflections, "
                              "photorealistic, high detail, shallow depth of field."),
            "keywords": ["alley", "golden hour", "wet cobblestone", "long shadows", "backlight", "photorealistic"],
            "aspect_ratio": "16:9; centered vertical leading lines",
            "attached_prompt": ui_raw
        }
        example = json.dumps(example_obj, ensure_ascii=False)

    instruction = textwrap.dedent(f"""
    You are a prompt-engineering assistant for an IMAGE generation model.
    Produce EXACTLY one JSON object as output (only valid JSON, no leading/trailing text).
    The JSON must have a single key "themes" which is an array of exactly {num_themes} theme objects.
    Do NOT output any explanatory prose outside of the JSON.

    REQUIRED keys for each theme object:
      - title: short string (<= 8 words)
      - one_line: one short sentence describing the concept
      - visual_prompt: one paragraph string ready to send to an IMAGE model (composition, lighting, camera angle/lens, color palette, materials, realism)
      - keywords: array of 5-10 short strings (no commas inside strings)
      - aspect_ratio: e.g. "16:9", "4:5" plus a short composition hint
      - attached_prompt: the exact original user input (verbatim). This must be present in every theme object.

    RULES:
      - Produce exactly {num_themes} distinct themes; each must differ in composition, mood, and palette.
      - Keep the user's raw request verbatim in attached_prompt for every theme.
      - If an image is provided, follow these restrictions: {img_note}
      - Avoid hallucinations; do not invent brand names or specific person names.
      - All text must be in English.
      - No extra keys; include only the six required keys per theme object.
      - Strings must not contain unescaped newlines except within visual_prompt (visual_prompt may be a single paragraph).
      - keywords must be simple tokens (no commas inside elements).
      - title must be <= 8 words.

    VALIDATION CHECKS the model must satisfy before returning:
      1) The top-level object is valid JSON with a single "themes" key.
      2) "themes" is an array of length {num_themes}.
      3) Each theme object contains exactly these keys: ["title","one_line","visual_prompt","keywords","aspect_ratio","attached_prompt"].
      4) attached_prompt equals the user's raw input verbatim.
      5) keywords length is between 5 and 10.
      6) title <= 8 words.
      If any check fails, output a single JSON object: {{ "error": "validation_failed", "reason": "<short reason>" }}.

    RETURN FORMAT:
      {{ "themes": [ theme1, theme2, ... ] }}

    EXAMPLE THEME (for format guidance, NOT to be repeated verbatim):
    {example}

    User request (raw): "{ui}"
    """).strip()

    return instruction

# --- Low-level helpers to call model for text or image ---
def _generate_text_from_prompt(prompt_text: str, model_id: str = TEXT_MODEL, *, response_modalities: List[str] = ["TEXT"], candidate_count: int = 1) -> Dict[str, Any]:
    if not GENAI_CLIENT:
        raise RuntimeError("GenAI client not initialized")
    cfg = GenerateContentConfig(
        response_modalities=response_modalities,
        candidate_count=max(1, int(candidate_count or 1)),
    )
    resp = GENAI_CLIENT.models.generate_content(
        model=model_id,
        contents=[prompt_text],
        config=cfg,
    )
    return resp

def _generate_image_from_prompt(prompt_text: str, model_id: str = MODEL_ID) -> Any:
    if not GENAI_CLIENT:
        raise RuntimeError("GenAI client not initialized")
    cfg = GenerateContentConfig(
        response_modalities=["TEXT", "IMAGE"],  # Changed to allow mixed output
        candidate_count=1,
    )
    # Prefix prompt to explicitly request image generation
    prompt_text = f"Generate an image of: {prompt_text}"
    resp = GENAI_CLIENT.models.generate_content(
        model=model_id,
        contents=[prompt_text],
        config=cfg,
    )
    return resp

def _generate_image_with_input_image(prompt_text: str, file_bytes: Optional[bytes], mime_type: Optional[str], file_uri: Optional[str] = None, model_id: str = MODEL_ID, aspect_ratio: Optional[str] = None) -> Any:
    if not GENAI_CLIENT:
        raise RuntimeError("GenAI client not initialized")
    contents = []
    if file_bytes is not None:
        contents.append(Part.from_bytes(data=file_bytes, mime_type=mime_type or "image/jpeg"))
    elif file_uri:
        if mime_type:
            contents.append(Part.from_uri(file_uri=file_uri, mime_type=mime_type))
        else:
            contents.append(Part.from_uri(file_uri=file_uri))
    else:
        raise ValueError("file_bytes or file_uri required for image-guided generation")

    # Prefix prompt to explicitly request image generation
    prompt_text = f"Generate an image based on the following: {prompt_text}"
    contents.append(prompt_text)
    print("Contents for image gen:", contents)

    cfg_kwargs = {"response_modalities": ["TEXT", "IMAGE"], "candidate_count": 1}  # Changed to allow mixed output
    if aspect_ratio:
        cfg_kwargs["image_config"] = ImageConfig(aspect_ratio=aspect_ratio)
    cfg = GenerateContentConfig(**cfg_kwargs)

    resp = GENAI_CLIENT.models.generate_content(
        model=model_id,
        contents=contents,
        config=cfg,
    )
    return resp

# Additional helpers for multi-image and edit flows
def _generate_image_with_input_images(prompt_text: str, parts: List[Part], model_id: str = MODEL_ID, aspect_ratio: Optional[str] = None) -> Any:
    if not GENAI_CLIENT:
        raise RuntimeError("GenAI client not initialized")
    cfg_kwargs = {"response_modalities": ["TEXT", "IMAGE"], "candidate_count": 1}  # Changed to allow mixed output
    if aspect_ratio:
        cfg_kwargs["image_config"] = ImageConfig(aspect_ratio=aspect_ratio)
    cfg = GenerateContentConfig(**cfg_kwargs)

    # Prefix prompt to explicitly request image generation
    prompt_text = f"Generate an image based on the following: {prompt_text}"
    contents = parts + [prompt_text]
    resp = GENAI_CLIENT.models.generate_content(model=model_id, contents=contents, config=cfg)
    return resp

def _generate_image_edit_with_instruction(prompt_text: str, part: Part, model_id: str = MODEL_ID, aspect_ratio: Optional[str] = None) -> Any:
    # A single-image edit: send image part then instruction text using models.generate_content
    if not GENAI_CLIENT:
        raise RuntimeError("GenAI client not initialized")
    cfg_kwargs = {"response_modalities": ["TEXT", "IMAGE"], "candidate_count": 1}  # Changed to allow mixed output
    if aspect_ratio:
        cfg_kwargs["image_config"] = ImageConfig(aspect_ratio=aspect_ratio)
    cfg = GenerateContentConfig(**cfg_kwargs)
    contents = [part, prompt_text]
    resp = GENAI_CLIENT.models.generate_content(model=model_id, contents=contents, config=cfg)
    return resp

def _chat_image_edit_with_instruction(prompt_text: str, part: Part, model_id: str = MODEL_ID, aspect_ratio: Optional[str] = None) -> Any:
    # Chat-style edit: create a chat and send message (mirrors the snippet you pasted)
    if not GENAI_CLIENT:
        raise RuntimeError("GenAI client not initialized")
    try:
        chat = GENAI_CLIENT.chats.create(model=model_id)
    except Exception as e:
        print("[chat_edit] chats.create failed:", e)
        raise

    cfg_kwargs = {"response_modalities": ["TEXT", "IMAGE"], "candidate_count": 1}  # Changed to allow mixed output
    if aspect_ratio:
        cfg_kwargs["image_config"] = ImageConfig(aspect_ratio=aspect_ratio)
    cfg = GenerateContentConfig(**cfg_kwargs)

    # send_message takes `message` list: [Part, "instruction"]
    response = chat.send_message(
        message=[part, prompt_text],
        config=cfg,
    )
    return response

# --- Utilities to extract text from a response (concatenate parts) ---
def extract_text_from_response(response: Any) -> str:
    texts = []
    for cand in getattr(response, "candidates", []) or []:
        content = getattr(cand, "content", None)
        if not content:
            continue
        for part in getattr(content, "parts", []) or []:
            t = getattr(part, "text", None)
            if t:
                texts.append(t)
    return "\n".join(texts)

# --- Robust JSON extraction helpers ---
def _extract_json_from_fenced(text: str) -> Optional[str]:
    m = re.search(r"```json\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r"```(?:[\w+-]*)\s*(.*?)```", text, flags=re.DOTALL)
    if m:
        return m.group(1).strip()
    return None

def _extract_balanced_json_candidates(text: str) -> List[str]:
    candidates = []
    for i, ch in enumerate(text):
        if ch != "{":
            continue
        stack = []
        for j in range(i, len(text)):
            if text[j] == "{":
                stack.append("{")
            elif text[j] == "}":
                if stack:
                    stack.pop()
                if not stack:
                    candidate = text[i:j+1]
                    candidates.append(candidate)
                    break
    return candidates

def parse_json_from_model_text(raw_text: str, *, retry_forced: bool = True) -> Dict[str, Any]:
    if not raw_text or not raw_text.strip():
        raise ValueError("empty model text")

    fenced = _extract_json_from_fenced(raw_text)
    if fenced:
        try:
            return json.loads(fenced)
        except Exception as e:
            print("[parse_json] fenced block parse failed:", e)

    candidates = _extract_balanced_json_candidates(raw_text)
    if candidates:
        candidates = sorted(candidates, key=len, reverse=True)
        for cand in candidates:
            try:
                parsed = json.loads(cand)
                return parsed
            except Exception as e:
                print("[parse_json] candidate parse failed:", e)
        print("[parse_json] no balanced candidate parsed successfully")

    if retry_forced:
        try:
            reformat_prompt = (
                "The model returned the following text. Extract and return ONLY a valid JSON object "
                "that preserves the original structure. Do not add explanation or text. "
                "Input:\n\n"
                + raw_text
            )
            resp = _generate_text_from_prompt(reformat_prompt, model_id=TEXT_MODEL, response_modalities=["TEXT"], candidate_count=1)
            reformatted = extract_text_from_response(resp)
            fenced2 = _extract_json_from_fenced(reformatted) or reformatted
            try:
                return json.loads(fenced2)
            except Exception as e:
                candidates2 = _extract_balanced_json_candidates(reformatted)
                for cand in sorted(candidates2, key=len, reverse=True):
                    try:
                        return json.loads(cand)
                    except:
                        continue
                raise ValueError(f"reformat attempt failed to yield parseable JSON: {e}; reformatted raw: {reformatted}")
        except Exception as e:
            raise ValueError(f"failed to auto-reformat model output to JSON: {e}") from e

    raise ValueError("no parseable JSON found in model text")

# --- Content prompt builder: produce caption/hashtags/cta/alt_text from user prompt + theme ---
def build_content_prompt_from_theme(user_prompt: str, theme: Dict[str, Any]) -> str:
    theme_title = theme.get("title", "")
    theme_one_line = theme.get("one_line", "")
    attached = theme.get("attached_prompt", "")
    ui = escape_for_inline(user_prompt or "")
    inst = textwrap.dedent(f"""
    You are a professional social-media copywriter. Produce EXACTLY one JSON object (no surrounding prose).
    Keys required:
      - caption: a friendly, concise social caption suited to the user's request (<=220 chars)
      - hashtags: array of up to 6 short hashtags (without # symbol)
      - cta: a short call-to-action (or empty string if none)
      - alt_text: descriptive alt text <=125 chars

    Input:
      - user_prompt (verbatim): "{ui}"
      - theme_title: "{escape_for_inline(theme_title)}"
      - theme_one_line: "{escape_for_inline(theme_one_line)}"
      - attached_prompt: "{escape_for_inline(attached)}"

    IMPORTANT RULES:
      - PRIORITIZE the user's prompt for message, tone, and intent. If the theme suggests a visual direction,
        use it only to inform the imagery and style — not the message content.
      - Use culturally appropriate language when the user's prompt mentions a festival or occasion.
      - Caption must be natural, not overly promotional unless the user's prompt explicitly asks for promotion.
      - hashtags should be relevant and concise (no spaces), and do not include personal data.
      - Output must be VALID JSON and contain ONLY the four required keys.

    Output example:
    {{ "caption": "Happy Dussehra from Sociovia! Wishing you victory and joy.", "hashtags": ["Dussehra2025","Sociovia"], "cta": "Share your celebration!", "alt_text": "Sociovia logo with festive Dussehra greeting" }}
    """).strip()
    return inst

# Platform -> default aspect ratio map (common social sizes)
PLATFORM_ASPECT_MAP = {
    "instagram_post": "4:5",
    "instagram_square": "1:1",
    "instagram_story": "9:16",
    "tiktok": "9:16",
    "twitter_post": "16:9",
    "facebook_post": "1.91:1",
    "linkedin_post": "1.91:1",
}

# --- New helper: resolve local outputs path from a URL or path ---
def _extract_output_filename_from_url(url: str) -> Optional[str]:
    """
    If url references our outputs (either a path '/outputs/...' or full EXTERNAL_BASE_URL + /outputs/...),
    return the filename (basename) so it can be copied locally.
    """
    if not url:
        return None
    try:
        # Normalize
        if url.startswith(_build_base_url()):
            # http(s)://host/outputs/<fname>
            path = url[len(_build_base_url()):]
            if path.startswith("/"):
                # find /outputs/<...>
                idx = path.find("/outputs/")
                if idx >= 0:
                    rel = path[idx + 1:]  # outputs/...
                else:
                    rel = path.lstrip("/")
            else:
                rel = path
            # If rel begins with outputs/, strip it
            if rel.startswith("outputs/"):
                fname = os.path.basename(rel)
                return fname
        # direct absolute path like /outputs/<fname>
        if "/outputs/" in url:
            return os.path.basename(url)
        # else maybe just a filename
        if url.startswith("http://") or url.startswith("https://"):
            # fallback: parse name from URL path
            from urllib.parse import urlparse
            parsed = urlparse(url)
            fname = os.path.basename(parsed.path)
            if fname:
                return fname
        # last resort: if it's a plain filename
        if os.path.basename(url) == url:
            return url
    except Exception:
        pass
    return None

# --- Helper to download external URL to memory ---
def _download_external_to_bytes(url: str) -> Optional[tuple[bytes, str]]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ai-image-backend/1.0"})
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as r:
            # If content-length present, check
            cl = r.getheader("Content-Length")
            if cl:
                try:
                    if int(cl) > MAX_UPLOAD_BYTES:
                        print("[download] remote file too large", cl)
                        return None
                except Exception:
                    pass
            data = r.read(MAX_UPLOAD_BYTES + 1)
            if len(data) > MAX_UPLOAD_BYTES:
                print("[download] remote file exceeded MAX_UPLOAD_BYTES")
                return None
            mime = r.getheader("Content-Type") or "image/png"
        return data, mime
    except Exception as e:
        print("[download] failed to fetch external url:", e)
        return None

# --- Helper to check if object exists in Spaces ---
def _object_exists(key: str) -> bool:
    if not s3:
        return False
    try:
        s3.head_object(Bucket=SPACE_NAME, Key=key)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == "404":
            return False
        raise

# --- Endpoints for saving / posting images ---

@app.route("/api/v1/save-image", methods=["POST"])
def save_image_endpoint():
    """
    Save a generated or external image into the workspace 'saved' folder in Spaces.
    Accepts application/json { "url": "<image url>" }
    or form-encoded 'url' parameter.
    Returns: { success: true, id: "<saved-id>", url: "<cdn url>" }
    """
    try:
        data = request.get_json(force=False, silent=True) or {}
        if not data:
            data = request.form.to_dict() or {}
        url = data.get("url")
        user_id = data.get("user_id") or request.headers.get("X-User-Id")
        workspace_id = data.get("workspace_id") or request.headers.get("X-Workspace-Id")
        if not url:
            return jsonify({"success": False, "error": "url_required"}), 400

        # if url is local outputs path or points to our base, copy from Spaces
        filename_hint = _extract_output_filename_from_url(url)
        ext = ".png"
        if filename_hint:
            ext = os.path.splitext(filename_hint)[1] or ext

        saved_id = uuid.uuid4().hex
        saved_fname = f"{saved_id}{ext}"
        saved_key = f"saved/{saved_fname}"  # Organized under saved/

        # 1) If filename_hint references our outputs: copy object in Spaces
        copied = False
        if filename_hint:
            source_key = f"outputs/{filename_hint}"
            if _object_exists(source_key):
                try:
                    s3.copy_object(
                        Bucket=SPACE_NAME,
                        CopySource={'Bucket': SPACE_NAME, 'Key': source_key},
                        Key=saved_key,
                        ACL='public-read'
                    )
                    copied = True
                    print(f"[save-image] copied {source_key} to {saved_key} in Spaces")
                except Exception as e:
                    print("[save-image] failed to copy from outputs in Spaces:", e)
                    # fallthrough to try download if url is full http(s)

        # 2) If not copied and url is http(s), attempt to download and upload
        if not copied and (url.startswith("http://") or url.startswith("https://")):
            download_result = _download_external_to_bytes(url)
            if download_result:
                data, mime = download_result
                try:
                    s3.put_object(Bucket=SPACE_NAME, Key=saved_key, Body=data, ContentType=mime, ACL='public-read')
                    copied = True
                    print(f"[save-image] uploaded external {url} to {saved_key} in Spaces")
                except Exception as e:
                    print("[save-image] failed to upload external to Spaces:", e)

        # 3) If not copied and not http, maybe client passed a fname in outputs/
        if not copied and not (url.startswith("http://") or url.startswith("https://")):
            # treat as possible key name under outputs/
            source_key = f"outputs/{url}"
            if _object_exists(source_key):
                try:
                    s3.copy_object(
                        Bucket=SPACE_NAME,
                        CopySource={'Bucket': SPACE_NAME, 'Key': source_key},
                        Key=saved_key,
                        ACL='public-read'
                    )
                    copied = True
                    print(f"[save-image] copied {source_key} to {saved_key} in Spaces (by name)")
                except Exception as e:
                    print("[save-image] failed to copy from outputs by name in Spaces:", e)

        # final check
        if not copied:
            return jsonify({"success": False, "error": "could_not_save_image"}), 500

        # register in saved index
        saved_url = f"{SPACE_CDN}/{saved_key}"
        meta = {
            "id": saved_id,
            "filename": saved_fname,
            "saved_key": saved_key,
            "saved_url": saved_url,
            "original_url": url,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        _register_saved(saved_id, meta)

        # Store in DB if user_id and workspace_id provided
        print(f"[save-image] Received user_id: {user_id}, workspace_id: {workspace_id}")
        try:
            if user_id and workspace_id:
                creative = Creative(
                    id=saved_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    url=saved_url,
                    filename=saved_fname,
                    type='saved'
                )
                db.session.add(creative)
                db.session.commit()
                print(f"[save-image] Stored saved image {saved_id} in DB for user {user_id} / workspace {workspace_id}")
        except Exception as e:
            print(f"[save-image] DB commit failed: {str(e)}")
            db.session.rollback()

        return jsonify({"success": True, "id": saved_id, "url": saved_url}), 200
    except Exception as e:
        print("[save-image] exception:", e)
        return jsonify({"success": False, "error": "server_error", "details": str(e)}), 500

@app.route("/api/v1/saved-images", methods=["GET"])
def list_saved_images():
    """
    List saved images metadata.
    """
    try:
        index = _load_saved_index()
        # convert to list sorted by saved_at desc
        arr = sorted(index.values(), key=lambda x: x.get("saved_at", ""), reverse=True)
        return jsonify({"success": True, "items": arr}), 200
    except Exception as e:
        print("[saved-images] failed:", e)
        return jsonify({"success": False, "error": "server_error", "details": str(e)}), 500

@app.route("/api/v1/post-image", methods=["POST"])
def post_image_endpoint():
    """
    Simulated posting endpoint.
    Body: { "image_id": "<saved-id>", "platforms": ["facebook","instagram"] }
    NOTE: This is a stub. Real posting requires OAuth and platform integrations on the server.
    """
    try:
        data = request.get_json() or {}
        image_id = data.get("image_id")
        platforms = data.get("platforms") or []
        if not image_id:
            return jsonify({"success": False, "error": "image_id_required"}), 400

        index = _load_saved_index()
        saved = index.get(image_id)
        if not saved:
            return jsonify({"success": False, "error": "image_not_found"}), 404

        # Simulate posting: log and return success.
        # Real implementation must handle OAuth tokens, target accounts, media upload endpoints, caption, scheduling etc.
        print(f"[post-image] posting saved image {image_id} to platforms: {platforms}. meta: {saved}")

        # Placeholder response structure
        result = {"success": True, "image_id": image_id, "posted_to": platforms, "message": "Simulated post; implement real integrations server-side."}
        return jsonify(result), 200
    except Exception as e:
        print("[post-image] exception:", e)
        return jsonify({"success": False, "error": "server_error", "details": str(e)}), 500

# --- Endpoints (existing) ---

@app.route("/api/v1/workspace-info", methods=["GET"])
def workspace_info():
    # small convenience endpoint for frontend header/title
    # Also include linked_platforms to help the frontend show options when posting
    return jsonify({
        "title": "sociovia.ai",
        "workspace": os.environ.get("WORKSPACE_NAME", "dname"),
        "owner": os.environ.get("WORKSPACE_OWNER", "owner@example.com"),
        "storage_used": 0,  # TODO: Query Spaces for size if needed
        "linked_platforms": ["facebook", "instagram", "twitter", "linkedin"],
    })

@app.route("/api/v1/generate", methods=["POST"])
def generate():
    if not GENAI_CLIENT:
        return jsonify({"success": False, "error": "genai_client_not_initialized"}), 500

    data = request.get_json() or {}
    user_prompt = data.get("prompt") or data.get("text") or ""
    user_id = data.get("user_id") or request.headers.get("X-User-Id")
    workspace_id = data.get("workspace_id") or request.headers.get("X-Workspace-Id")
    if not user_prompt:
        return jsonify({"success": False, "error": "prompt_required"}), 400

    master = master_prompt_json(user_prompt, has_image=False)
    try:
        resp_text = _generate_text_from_prompt(master, model_id=TEXT_MODEL, candidate_count=1, response_modalities=["TEXT"])
    except Exception as e:
        print("[generate] theme generation failed:", e)
        return jsonify({"success": False, "error": "theme_generation_failed", "details": str(e)}), 500

    raw_text = extract_text_from_response(resp_text)
    try:
        parsed = parse_json_from_model_text(raw_text, retry_forced=True)
        themes = parsed.get("themes") if isinstance(parsed, dict) else None
        if not isinstance(themes, list) or len(themes) != 3:
            raise ValueError("Expected 'themes' array of length 3")
    except Exception as e:
        print("[generate] failed to parse JSON themes:", e)
        return jsonify({"success": False, "error": "invalid_theme_json", "raw_response": raw_text, "details": str(e)}), 500

    results = []
    saved_files = []
    for idx, theme in enumerate(themes):
        visual_prompt = theme.get("visual_prompt") if isinstance(theme, dict) else None
        if not visual_prompt:
            print(f"[generate] theme {idx} missing visual_prompt")
            results.append({"theme_index": idx, "error": "missing_visual_prompt"})
            continue

        try:
            img_resp = _generate_image_from_prompt(visual_prompt, model_id=MODEL_ID)
        except Exception as e:
            print(f"[generate] image gen failed for theme {idx}:", e)
            results.append({"theme_index": idx, "error": "image_generation_failed", "details": str(e)})
            continue

        saved = save_images_from_response(img_resp, prefix=f"gen_theme{idx}")
        saved_files.extend(saved)
        results.append({"theme_index": idx, "theme": theme, "files": saved})

    urls = [f"{SPACE_CDN}/outputs/{fn}" for fn in saved_files]

    # Store generated URLs in DB if user_id and workspace_id provided
    print(f"[generate] Received user_id: {user_id}, workspace_id: {workspace_id}")
    try:
        if user_id and workspace_id:
            for fn, url in zip(saved_files, urls):
                creative_id = uuid.uuid4().hex
                creative = Creative(
                    id=creative_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    url=url,
                    filename=fn,
                    type='generated'
                )
                db.session.add(creative)
            db.session.commit()
            print(f"[generate] Stored {len(saved_files)} generated images in DB for user {user_id} / workspace {workspace_id}")
    except Exception as e:
        print(f"[generate] DB commit failed: {str(e)}")
        db.session.rollback()

    # Save conversation
    try:
        if user_id and workspace_id:
            conv_id = uuid.uuid4().hex
            response_data = {
                "success": True,
                "themes": themes,
                "results": results,
                "files": saved_files,
                "urls": urls
            }
            conversation = Conversation(
                id=conv_id,
                user_id=user_id,
                workspace_id=workspace_id,
                prompt=user_prompt,
                response=json.dumps(response_data)
            )
            db.session.add(conversation)
            db.session.commit()
            print(f"[generate] Stored conversation {conv_id} in DB for user {user_id} / workspace {workspace_id}")
    except Exception as e:
        print(f"[generate] Conversation DB commit failed: {str(e)}")
        db.session.rollback()

    return jsonify({
        "success": True,
        "themes": themes,
        "results": results,
        "files": saved_files,
        "urls": urls
    }), 200

@app.route("/api/v1/generate-from-image", methods=["POST"])
def generate_from_image_endpoint():
    """
    Handles two modes:
     - edit_only / single_edit: do a single-image edit using the provided image & prompt (no theme generation)
     - default: run theme generation (text model) and then produce one image per theme (existing behavior)
    Accepts multipart/form-data (preferred for uploads) or JSON with file_uri / file_bytes.
    """
    if not GENAI_CLIENT:
        return jsonify({"success": False, "error": "genai_client_not_initialized"}), 500

    file_bytes = None
    file_uri = None
    mime_type = None
    prompt = ""
    edit_only = False
    user_id = None
    workspace_id = None

    try:
        # Support multipart/form-data (file upload) and JSON bodies
        if request.content_type and request.content_type.startswith("multipart/form-data"):
            f = request.files.get("file")
            prompt = request.form.get("prompt") or request.form.get("text") or ""
            edit_only = (request.form.get("edit_only") or request.form.get("single_edit") or "").lower() in ("1", "true", "yes", "on")
            # allow a client to send an explicit image_url / file_uri in multi-part as well
            file_uri = request.form.get("image_url") or request.form.get("file_uri") or request.form.get("target_url")
            user_id = request.form.get("user_id") or request.headers.get("X-User-Id")
            workspace_id = request.form.get("workspace_id") or request.headers.get("X-Workspace-Id")
            if not f and not file_uri:
                return jsonify({"success": False, "error": "file_and_prompt_required"}), 400
            if f:
                mime_type = f.mimetype or mimetypes.guess_type(f.filename)[0] or "image/png"
                file_bytes = f.read()
                if len(file_bytes) > MAX_UPLOAD_BYTES:
                    return jsonify({"success": False, "error": "file_too_large"}), 400
        else:
            data = request.get_json() or {}
            prompt = data.get("prompt") or data.get("text") or ""
            file_uri = data.get("file_uri")
            edit_only = bool(data.get("edit_only") or data.get("single_edit"))
            user_id = data.get("user_id") or request.headers.get("X-User-Id")
            workspace_id = data.get("workspace_id") or request.headers.get("X-Workspace-Id")
            if not prompt:
                return jsonify({"success": False, "error": "prompt_required"}), 400
            if not (file_uri or data.get("file_bytes")):
                return jsonify({"success": False, "error": "prompt_and_file_uri_or_upload_required"}), 400
            if data.get("file_bytes"):
                try:
                    file_bytes = base64.b64decode(data.get("file_bytes"))
                    mime_type = data.get("mime_type") or "image/png"
                    if len(file_bytes) > MAX_UPLOAD_BYTES:
                        return jsonify({"success": False, "error": "file_too_large"}), 400
                except Exception:
                    return jsonify({"success": False, "error": "invalid_base64_file_bytes"}), 400
    except Exception as e:
        print("[generate_from_image_endpoint] request parse failed:", e)
        return jsonify({"success": False, "error": "bad_request", "details": str(e)}), 400

    # If edit_only -> do a single-image edit using the provided image, do not run theme generation
    if edit_only:
        # Build the final prompt for single-edit: incorporate user's prompt and watermark instructions
        final_prompt_parts = [prompt.strip()]

        # Simple watermark inference: look for phrases like 'made with love' or 'made with sociovia'
        lower = (prompt or "").lower()
        watermark_text = None
        if "made with love" in lower:
            watermark_text = "Made with love"
        elif "made with sociovia" in lower or "sociovia.ai" in lower or "sociovia" in lower:
            watermark_text = "Made with Sociovia.ai"
        else:
            # look for quoted watermark text "..." in the prompt
            m = re.search(r'["“”\'](.{2,40}?)["“”\']', prompt)
            if m:
                watermark_text = m.group(1).strip()

        if watermark_text:
            # Try to detect corner preference
            corner = "bottom-right"
            if "bottom-left" in lower or "left corner" in lower or "bottom left" in lower:
                corner = "bottom-left"
            elif "top-right" in lower or "top right" in lower:
                corner = "top-right"
            elif "top-left" in lower or "top left" in lower:
                corner = "top-left"

            wm_inst = (
                f'Also add a subtle watermark reading \"{watermark_text}\" in the {corner}. '
                "Make it very light and unobtrusive (about 10-18% opacity), small sans-serif, "
                "without covering the main subject. Ensure watermark contrasts slightly for legibility but does not distract."
            )
            final_prompt_parts.append(wm_inst)
        else:
            # If user asked generically for "add watermark" but no explicit text, use default light branding
            if "watermark" in lower or "made with" in lower:
                final_prompt_parts.append(
                    "Also add a subtle watermark in the bottom-right reading 'Made with Sociovia.ai'. "
                    "Keep it very light (10-18% opacity), small, unobtrusive, and placed in the corner."
                )

        final_image_prompt = "\n\n".join([p for p in final_prompt_parts if p])

        # Now call the image model once with the provided file_uri or file_bytes
        try:
            img_resp = None
            if file_bytes is not None:
                img_resp = _generate_image_with_input_image(final_image_prompt, file_bytes=file_bytes, mime_type=mime_type, file_uri=None, model_id=MODEL_ID)
            elif file_uri:
                img_resp = _generate_image_with_input_image(final_image_prompt, file_bytes=None, mime_type=mime_type, file_uri=file_uri, model_id=MODEL_ID)
            else:
                return jsonify({"success": False, "error": "no_image_for_edit"}), 400

            saved = save_images_from_response(img_resp, prefix="edit_single")
            urls = [f"{SPACE_CDN}/outputs/{fn}" for fn in saved]

            # Store in DB if user_id and workspace_id provided
            print(f"[generate-from-image][edit_only] Received user_id: {user_id}, workspace_id: {workspace_id}")
            try:
                if user_id and workspace_id:
                    for fn, url in zip(saved, urls):
                        creative_id = uuid.uuid4().hex
                        creative = Creative(
                            id=creative_id,
                            user_id=user_id,
                            workspace_id=workspace_id,
                            url=url,
                            filename=fn,
                            type='generated'
                        )
                        db.session.add(creative)
                    db.session.commit()
                    print(f"[generate-from-image][edit_only] Stored {len(saved)} generated images in DB for user {user_id} / workspace {workspace_id}")
            except Exception as e:
                print(f"[generate-from-image][edit_only] DB commit failed: {str(e)}")
                db.session.rollback()

            # Save conversation (prompt is instructions here)
            try:
                if user_id and workspace_id:
                    conv_id = uuid.uuid4().hex
                    response_data = {
                        "success": True,
                        "edit_mode": True,
                        "files": saved,
                        "urls": urls
                    }
                    conversation = Conversation(
                        id=conv_id,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        prompt=prompt,  # Use prompt as instructions for edit
                        response=json.dumps(response_data)
                    )
                    db.session.add(conversation)
                    db.session.commit()
                    print(f"[generate-from-image][edit_only] Stored conversation {conv_id} in DB for user {user_id} / workspace {workspace_id}")
            except Exception as e:
                print(f"[generate-from-image][edit_only] Conversation DB commit failed: {str(e)}")
                db.session.rollback()

            return jsonify({
                "success": True,
                "edit_mode": True,
                "files": saved,
                "urls": urls
            }), 200

        except Exception as e:
            print("[generate_from_image_endpoint][edit_only] image gen failed:", e)
            return jsonify({"success": False, "error": "image_generation_failed", "details": str(e)}), 500

    # --- Else: original multi-theme behavior (unchanged) ---
    image_hint = f"URI: {file_uri}" if file_uri else ("uploaded image bytes" if file_bytes else None)
    master = master_prompt_json(prompt, has_image=True, image_hint=image_hint)

    # Call model to get JSON themes (send image as Part and request TEXT via TEXT_MODEL)
    try:
        contents = []
        if file_bytes is not None:
            contents.append(Part.from_bytes(data=file_bytes, mime_type=mime_type or "image/png"))
        elif file_uri:
            if mime_type:
                contents.append(Part.from_uri(file_uri=file_uri, mime_type=mime_type))
            else:
                contents.append(Part.from_uri(file_uri=file_uri))
        else:
            return jsonify({"success": False, "error": "file_or_uri_required"}), 400
        contents.append(master)

        cfg = GenerateContentConfig(
            response_modalities=["TEXT"],
            candidate_count=1,
        )

        resp = GENAI_CLIENT.models.generate_content(
            model=TEXT_MODEL,
            contents=contents,
            config=cfg,
        )
    except Exception as e:
        print("[generate_from_image_endpoint] theme generation failed:", e)
        return jsonify({"success": False, "error": "theme_generation_failed", "details": str(e)}), 500

    raw_text = extract_text_from_response(resp)
    print("[DEBUG] RAW THEMES RESPONSE (text model):")
    print(raw_text)
    try:
        parsed = parse_json_from_model_text(raw_text, retry_forced=True)
        themes = parsed.get("themes") if isinstance(parsed, dict) else None
        if not isinstance(themes, list) or len(themes) != 3:
            raise ValueError("Expected 'themes' array of length 3")
    except Exception as e:
        print("[generate_from_image_endpoint] failed to parse JSON themes:", e)
        return jsonify({"success": False, "error": "invalid_theme_json", "raw_response": raw_text, "details": str(e)}), 500

    # For each theme: generate social content (caption/hashtags/cta/alt_text), then image.
    results = []
    saved_files = []
    for idx, theme in enumerate(themes):
        visual_prompt = theme.get("visual_prompt") if isinstance(theme, dict) else None
        if not visual_prompt:
            print(f"[generate_from_image_endpoint] theme {idx} missing visual_prompt")
            results.append({"theme_index": idx, "error": "missing_visual_prompt"})
            continue

        # 1) content generation prioritized by user prompt
        content_inst = build_content_prompt_from_theme(prompt, theme)
        try:
            content_resp = _generate_text_from_prompt(content_inst, model_id=TEXT_MODEL, candidate_count=1)
            content_raw = extract_text_from_response(content_resp)
            print(f"[DEBUG] RAW CONTENT RESPONSE (theme {idx}):")
            print(content_raw)
            content_parsed = parse_json_from_model_text(content_raw, retry_forced=True)
        except Exception as e:
            print(f"[generate_from_image_endpoint] content gen/parse failed for theme {idx}:", e)
            # fallback minimal content
            content_parsed = {
                "caption": (prompt or "")[:220],
                "hashtags": [],
                "cta": "",
                "alt_text": (prompt or "")[:125]
            }

        # 2) build final image prompt: combine visual_prompt + user prompt + generated content (pass prompt as parameter)
        caption_text = content_parsed.get("caption", "")
        cta = content_parsed.get("cta", "")
        # Include instruction to place logo as branding asset
        final_image_prompt = (
            f"{visual_prompt}\n\nUser prompt (priority): {escape_for_inline(prompt)}\n"
            f"Caption (reserve readable space): {escape_for_inline(caption_text)}\n"
            f"Optional CTA (if space): {escape_for_inline(cta)}\n"
            f"Place the uploaded logo at bottom-right occupying approximately 8% of the canvas width. "
            "Treat the uploaded file strictly as the brand logo; do not modify its colors or crop important parts. "
            "Ensure a clear area for caption text (legible contrast)."
        )

        try:
            img_resp = _generate_image_with_input_image(final_image_prompt, file_bytes=file_bytes, mime_type=mime_type, file_uri=file_uri, model_id=MODEL_ID)
        except Exception as e:
            print(f"[generate_from_image_endpoint] image gen failed for theme {idx}:", e)
            results.append({"theme_index": idx, "error": "image_generation_failed", "details": str(e), "content": content_parsed})
            continue

        saved = save_images_from_response(img_resp, prefix=f"fromimg_theme{idx}")
        saved_files.extend(saved)
        results.append({"theme_index": idx, "theme": theme, "content": content_parsed, "files": saved})

    urls = [f"{SPACE_CDN}/outputs/{fn}" for fn in saved_files]

    # Store generated URLs in DB if user_id and workspace_id provided
    print(f"[generate-from-image] Received user_id: {user_id}, workspace_id: {workspace_id}")
    try:
        if user_id and workspace_id:
            for fn, url in zip(saved_files, urls):
                creative_id = uuid.uuid4().hex
                creative = Creative(
                    id=creative_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    url=url,
                    filename=fn,
                    type='generated'
                )
                db.session.add(creative)
            db.session.commit()
            print(f"[generate-from-image] Stored {len(saved_files)} generated images in DB for user {user_id} / workspace {workspace_id}")
    except Exception as e:
        print(f"[generate-from-image] DB commit failed: {str(e)}")
        db.session.rollback()

    # Save conversation
    try:
        if user_id and workspace_id:
            conv_id = uuid.uuid4().hex
            response_data = {
                "success": True,
                "themes": themes,
                "results": results,
                "files": saved_files,
                "urls": urls
            }
            conversation = Conversation(
                id=conv_id,
                user_id=user_id,
                workspace_id=workspace_id,
                prompt=prompt,
                response=json.dumps(response_data)
            )
            db.session.add(conversation)
            db.session.commit()
            print(f"[generate-from-image] Stored conversation {conv_id} in DB for user {user_id} / workspace {workspace_id}")
    except Exception as e:
        print(f"[generate-from-image] Conversation DB commit failed: {str(e)}")
        db.session.rollback()

    return jsonify({
        "success": True,
        "themes": themes,
        "results": results,
        "files": saved_files,
        "urls": urls
    }), 200


# --- New endpoint: generate from multiple images (URIs or uploads) ---
@app.route("/api/v1/generate-from-images", methods=["POST"])
def generate_from_images_endpoint():
    """
    Generate images using multiple input images (uploaded files or URIs).

    Accepts multipart/form-data:
      - files: multiple files (form field name `files`)
      - files[]: multiple files (some frontends send this name)
      - file: single file
      - uploaded_files: repeated field containing either tokens (uploaded_xxx) or direct URL[](https://...)
      - prompt: required textual prompt (unless file_uris-only flow)
      - platform / aspect_ratio / use_themes

    Or JSON body:
      { "file_uris": ["gs://...","https://..."], "prompt": "...", "platform": "instagram_post" }
    """
    if not GENAI_CLIENT:
        return jsonify({"success": False, "error": "genai_client_not_initialized"}), 500

    prompt = ""
    file_bytes_list: List[bytes] = []
    file_uris: List[str] = []
    mime_types: List[str] = []
    aspect_ratio = None
    platform = None
    use_themes = False
    user_id = None
    workspace_id = None

    try:
        content_type = request.content_type or ""
        print(f"[generate-from-images] content_type: {content_type}", flush=True)

        if content_type.startswith("multipart/form-data"):
            # Prefer common field names: 'files', 'files[]', or single 'file'. Also fallback to any files in request.files.
            prompt = request.form.get("prompt") or request.form.get("text") or ""
            platform = request.form.get("platform")
            aspect_ratio = request.form.get("aspect_ratio")
            use_themes = (request.form.get("use_themes") or "").lower() in ("1", "true", "yes")
            user_id = request.form.get("user_id") or request.headers.get("X-User-Id")
            workspace_id = request.form.get("workspace_id") or request.headers.get("X-Workspace-Id")

            # uploaded_files may contain tokens or URLs
            uploaded_files_fields = request.form.getlist("uploaded_files") or []
            if uploaded_files_fields:
                print(f"[generate-from-images] uploaded_files form entries: {uploaded_files_fields}", flush=True)
                for entry in uploaded_files_fields:
                    if not entry:
                        continue
                    if entry.startswith("http://") or entry.startswith("https://") or entry.startswith("gs://"):
                        file_uris.append(entry)
                    else:
                        # treat token (client-side uploaded id) as non-resolvable by this endpoint - log it
                        print(f"[generate-from-images] received uploaded_files token (not a URL): {entry}", flush=True)

            # Try multiple file field names
            files = request.files.getlist("files") or request.files.getlist("files[]") or []
            if not files:
                single = request.files.get("file")
                if single:
                    files = [single]

            # Ultimate fallback: any files present in request.files
            if not files and request.files:
                files = list(request.files.values())

            print(f"[generate-from-images] form keys: {list(request.form.keys())}", flush=True)
            print(f"[generate-from-images] files keys: {list(request.files.keys())}", flush=True)
            print(f"[generate-from-images] received {len(files)} uploaded file(s)", flush=True)

            for idx, f in enumerate(files):
                fname = getattr(f, "filename", None)
                if not f or not fname:
                    print(f"[generate-from-images] skipping empty file at index {idx}", flush=True)
                    continue
                try:
                    b = f.read()
                except Exception as e:
                    print(f"[generate-from-images] failed to read file[{idx}] {fname}: {e}", flush=True)
                    continue
                size = len(b) if b else 0
                print(f"[generate-from-images] file[{idx}] name={fname} mimetype={getattr(f,'mimetype',None)} size={size}", flush=True)
                if size > MAX_UPLOAD_BYTES:
                    print(f"[generate-from-images] file[{idx}] too large: {size} > {MAX_UPLOAD_BYTES}", flush=True)
                    return jsonify({"success": False, "error": "file_too_large"}), 400
                file_bytes_list.append(b)
                mime_types.append(f.mimetype or mimetypes.guess_type(fname)[0] or "image/png")

        else:
            # JSON body flow
            data = request.get_json() or {}
            print(f"[generate-from-images] JSON body: keys={list(data.keys())}", flush=True)
            prompt = data.get("prompt") or data.get("text") or ""
            file_uris = data.get("file_uris") or data.get("image_urls") or []
            platform = data.get("platform")
            aspect_ratio = data.get("aspect_ratio")
            use_themes = bool(data.get("use_themes"))
            user_id = data.get("user_id") or request.headers.get("X-User-Id")
            workspace_id = data.get("workspace_id") or request.headers.get("X-Workspace-Id")
    except Exception as e:
        print("[generate-from-images] request parse failed:", e, flush=True)
        return jsonify({"success": False, "error": "bad_request", "details": str(e)}), 400

    # compute final aspect ratio
    if not aspect_ratio and platform:
        aspect_ratio = PLATFORM_ASPECT_MAP.get(platform)
    print(f"[generate-from-images] final aspect_ratio: {aspect_ratio} use_themes: {use_themes}", flush=True)
    print(f"[generate-from-images] prompt length: {len(prompt or '')}", flush=True)
    print(f"[generate-from-images] initial file_bytes_list count: {len(file_bytes_list)} file_uris count: {len(file_uris)}", flush=True)

    # If user explicitly requested themes, run themed flow
    if use_themes:
        try:
            first = None
            if file_bytes_list:
                first = Part.from_bytes(data=file_bytes_list[0], mime_type=mime_types[0] if mime_types else "image/png")
            elif file_uris:
                first = Part.from_uri(file_uri=file_uris[0])

            master = master_prompt_json(prompt or "", has_image=bool(first), image_hint=(file_uris[0] if file_uris else "uploaded image"))
            contents = []
            if first:
                contents.append(first)
            contents.append(master)
            cfg = GenerateContentConfig(response_modalities=["TEXT"], candidate_count=1)
            resp = GENAI_CLIENT.models.generate_content(model=TEXT_MODEL, contents=contents, config=cfg)
            raw_text = extract_text_from_response(resp)
            print("[generate-from-images] RAW THEMES RESPONSE (text model):", flush=True)
            print(raw_text, flush=True)
            parsed = parse_json_from_model_text(raw_text, retry_forced=True)
            themes = parsed.get("themes")
        except Exception as e:
            print("[generate-from-images] theme generation failed:", e, flush=True)
            return jsonify({"success": False, "error": "theme_generation_failed", "details": str(e), "raw_response": (raw_text if 'raw_text' in locals() else '')}), 500

        # For each theme, generate image referencing all provided images
        results = []
        saved_files = []
        for idx, theme in enumerate(themes):
            visual_prompt = theme.get("visual_prompt")
            if not visual_prompt:
                results.append({"theme_index": idx, "error": "missing_visual_prompt"})
                continue
            parts = []
            for i, b in enumerate(file_bytes_list):
                parts.append(Part.from_bytes(data=b, mime_type=mime_types[i] if i < len(mime_types) else "image/png"))
            for uri in file_uris:
                parts.append(Part.from_uri(file_uri=uri))

            final_prompt = f"{visual_prompt}\n\nUser prompt (priority): {escape_for_inline(prompt or '')}\nAttached_prompt: {escape_for_inline(theme.get('attached_prompt',''))}"
            print(f"[generate-from-images] theme[{idx}] final_prompt snippet: {final_prompt[:300]}...", flush=True)
            try:
                img_resp = _generate_image_with_input_images(final_prompt, parts, model_id=MODEL_ID, aspect_ratio=aspect_ratio)
            except Exception as e:
                print(f"[generate-from-images] image generation failed for theme {idx}:", e, flush=True)
                results.append({"theme_index": idx, "error": "image_generation_failed", "details": str(e)})
                continue
            saved = save_images_from_response(img_resp, prefix=f"multi_theme{idx}")
            print(f"[generate-from-images] saved for theme {idx}: {saved}", flush=True)
            saved_files.extend(saved)
            results.append({"theme_index": idx, "theme": theme, "files": saved})

        urls = [f"{SPACE_CDN}/outputs/{fn}" for fn in saved_files]
        print(f"[generate-from-images] returning saved files: {saved_files}", flush=True)

        # Store generated URLs in DB if user_id and workspace_id provided
        print(f"[generate-from-images][themes] Received user_id: {user_id}, workspace_id: {workspace_id}")
        try:
            if user_id and workspace_id:
                for fn, url in zip(saved_files, urls):
                    creative_id = uuid.uuid4().hex
                    creative = Creative(
                        id=creative_id,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        url=url,
                        filename=fn,
                        type='generated'
                    )
                    db.session.add(creative)
                db.session.commit()
                print(f"[generate-from-images][themes] Stored {len(saved_files)} generated images in DB for user {user_id} / workspace {workspace_id}")
        except Exception as e:
            print(f"[generate-from-images][themes] DB commit failed: {str(e)}")
            db.session.rollback()

        # Save conversation
        try:
            if user_id and workspace_id:
                conv_id = uuid.uuid4().hex
                response_data = {
                    "success": True,
                    "themes": themes,
                    "results": results,
                    "files": saved_files,
                    "urls": urls
                }
                conversation = Conversation(
                    id=conv_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    prompt=prompt,
                    response=json.dumps(response_data)
                )
                db.session.add(conversation)
                db.session.commit()
                print(f"[generate-from-images][themes] Stored conversation {conv_id} in DB for user {user_id} / workspace {workspace_id}")
        except Exception as e:
            print(f"[generate-from-images][themes] Conversation DB commit failed: {str(e)}")
            db.session.rollback()

        return jsonify({
            "success": True,
            "themes": themes,
            "results": results,
            "files": saved_files,
            "urls": urls
        }), 200

    # Default (no themes): direct multi-image-guided generation
    parts = []
    for i, b in enumerate(file_bytes_list):
        parts.append(Part.from_bytes(data=b, mime_type=mime_types[i] if i < len(mime_types) else "image/png"))
    for uri in file_uris:
        parts.append(Part.from_uri(file_uri=uri))

    print(f"[generate-from-images] final parts count: {len(parts)}", flush=True)

    if not parts and not prompt:
        print("[generate-from-images] no inputs provided", flush=True)
        return jsonify({"success": False, "error": "no_inputs"}), 400

    final_prompt = (
        f"User prompt (priority): {escape_for_inline(prompt or '')}\n"
        f"This composition should sensibly blend/arrange the supplied reference images as instructed. "
        f"Do NOT invent recognizable personal details. Ensure composition leaves clear readable space if caption overlay is requested."
    )

    print("[generate-from-images] sending to image model with prompt snippet:", flush=True)
    print(final_prompt[:400], flush=True)

    try:
        img_resp = _generate_image_with_input_images(final_prompt, parts, model_id=MODEL_ID, aspect_ratio=aspect_ratio)
        print("[generate-from-images] image model call succeeded", flush=True)
    except Exception as e:
        print("[generate-from-images] image generation failed:", e, flush=True)
        return jsonify({"success": False, "error": "image_generation_failed", "details": str(e)}), 500

    saved = save_images_from_response(img_resp, prefix="gen_multi")
    print(f"[generate-from-images] saved files: {saved}", flush=True)
    urls = [f"{SPACE_CDN}/outputs/{fn}" for fn in saved]

    # Store generated URLs in DB if user_id and workspace_id provided
    print(f"[generate-from-images] Received user_id: {user_id}, workspace_id: {workspace_id}")
    try:
        if user_id and workspace_id:
            for fn, url in zip(saved, urls):
                creative_id = uuid.uuid4().hex
                creative = Creative(
                    id=creative_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    url=url,
                    filename=fn,
                    type='generated'
                )
                db.session.add(creative)
            db.session.commit()
            print(f"[generate-from-images] Stored {len(saved)} generated images in DB for user {user_id} / workspace {workspace_id}")
    except Exception as e:
        print(f"[generate-from-images] DB commit failed: {str(e)}")
        db.session.rollback()

    # Save conversation
    try:
        if user_id and workspace_id:
            conv_id = uuid.uuid4().hex
            response_data = {
                "success": True,
                "files": saved,
                "urls": urls
            }
            conversation = Conversation(
                id=conv_id,
                user_id=user_id,
                workspace_id=workspace_id,
                prompt=prompt,
                response=json.dumps(response_data)
            )
            db.session.add(conversation)
            db.session.commit()
            print(f"[generate-from-images] Stored conversation {conv_id} in DB for user {user_id} / workspace {workspace_id}")
    except Exception as e:
        print(f"[generate-from-images] Conversation DB commit failed: {str(e)}")
        db.session.rollback()

    return jsonify({
        "success": True,
        "files": saved,
        "urls": urls
    }), 200

# --- New endpoint: edit a single image with instructions (supports chat-style via use_chat=1) ---
@app.route("/api/v1/edit-image", methods=["POST"])
def edit_image_endpoint():
    """
    Edit a single image using an instruction text.

    multipart/form-data expected:
      - file: the image to edit (required)
      - instructions: textual edit instructions (required)
      - platform / aspect_ratio: optional to guide result size
      - use_chat: optional (1/0). If 1, use chat-style API (client.chats.create(...)). Default uses models.generate_content.

    Or JSON:
      { "file_uri": "gs://...", "instructions": "change color to purple", "use_chat": true }
    """
    if not GENAI_CLIENT:
        return jsonify({"success": False, "error": "genai_client_not_initialized"}), 500

    try:
        use_chat = False
        user_id = None
        workspace_id = None
        if request.content_type and request.content_type.startswith("multipart/form-data"):
            f = request.files.get("file")
            instructions = request.form.get("instructions") or request.form.get("prompt")
            platform = request.form.get("platform")
            aspect_ratio = request.form.get("aspect_ratio")
            use_chat = request.form.get("use_chat") in ("1", "true", "True")
            user_id = request.form.get("user_id") or request.headers.get("X-User-Id")
            workspace_id = request.form.get("workspace_id") or request.headers.get("X-Workspace-Id")
            if not f or not instructions:
                return jsonify({"success": False, "error": "file_and_instructions_required"}), 400
            b = f.read()
            if len(b) > MAX_UPLOAD_BYTES:
                return jsonify({"success": False, "error": "file_too_large"}), 400
            mime = f.mimetype or mimetypes.guess_type(f.filename)[0] or "image/png"
            part = Part.from_bytes(data=b, mime_type=mime)
        else:
            data = request.get_json() or {}
            instructions = data.get("instructions") or data.get("prompt")
            file_uri = data.get("file_uri")
            platform = data.get("platform")
            aspect_ratio = data.get("aspect_ratio")
            use_chat = bool(data.get("use_chat"))
            user_id = data.get("user_id") or request.headers.get("X-User-Id")
            workspace_id = data.get("workspace_id") or request.headers.get("X-Workspace-Id")
            if not instructions or not file_uri:
                return jsonify({"success": False, "error": "instructions_and_file_uri_required"}), 400
            part = Part.from_uri(file_uri=file_uri)
    except Exception as e:
        return jsonify({"success": False, "error": "bad_request", "details": str(e)}), 400

    if not aspect_ratio and platform:
        aspect_ratio = PLATFORM_ASPECT_MAP.get(platform)

    final_instruction = (
        f"Edit the provided image according to these instructions: {escape_for_inline(instructions)}. "
        "Do not add text overlays unless explicitly requested. Preserve important subject details and avoid hallucinated logos."
    )

    try:
        if use_chat:
            # chat-style edit (mirrors docs snippet)
            resp = _chat_image_edit_with_instruction(final_instruction, part, model_id=MODEL_ID, aspect_ratio=aspect_ratio)
        else:
            # models.generate_content style edit
            resp = _generate_image_edit_with_instruction(final_instruction, part, model_id=MODEL_ID, aspect_ratio=aspect_ratio)
    except Exception as e:
        print("[edit_image_endpoint] image edit failed:", e)
        return jsonify({"success": False, "error": "image_edit_failed", "details": str(e)}), 500

    saved = save_images_from_response(resp, prefix="edit")
    urls = [f"{SPACE_CDN}/outputs/{fn}" for fn in saved]

    # Store generated URLs in DB if user_id and workspace_id provided
    print(f"[edit-image] Received user_id: {user_id}, workspace_id: {workspace_id}")
    try:
        if user_id and workspace_id:
            for fn, url in zip(saved, urls):
                creative_id = uuid.uuid4().hex
                creative = Creative(
                    id=creative_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    url=url,
                    filename=fn,
                    type='generated'
                )
                db.session.add(creative)
            db.session.commit()
            print(f"[edit-image] Stored {len(saved)} generated images in DB for user {user_id} / workspace {workspace_id}")
    except Exception as e:
        print(f"[edit-image] DB commit failed: {str(e)}")
        db.session.rollback()

    # Save conversation (prompt is instructions)
    try:
        if user_id and workspace_id:
            conv_id = uuid.uuid4().hex
            response_data = {
                "success": True,
                "files": saved,
                "urls": urls
            }
            conversation = Conversation(
                id=conv_id,
                user_id=user_id,
                workspace_id=workspace_id,
                prompt=instructions,
                response=json.dumps(response_data)
            )
            db.session.add(conversation)
            db.session.commit()
            print(f"[edit-image] Stored conversation {conv_id} in DB for user {user_id} / workspace {workspace_id}")
    except Exception as e:
        print(f"[edit-image] Conversation DB commit failed: {str(e)}")
        db.session.rollback()

    return jsonify({
        "success": True,
        "files": saved,
        "urls": urls
    }), 200

# Serve outputs (redirect to CDN)
@app.route("/outputs/<path:filename>", methods=["GET", "OPTIONS"])
def serve_output(filename):
    if request.method == "OPTIONS":
        resp = make_response()
        origin = request.headers.get("Origin")
        if origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Vary"] = "Origin"
        else:
            resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, Accept"
        return resp
    # Redirect to CDN
    cdn_url = f"{SPACE_CDN}/outputs/{filename}"
    return redirect(cdn_url)



#==================================================after  merge updatse========================================================

#----------------------------------------------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        #db.create_all()
        debug_flag = os.getenv("FLASK_ENV", "development") != "production"
        app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=debug_flag)



















