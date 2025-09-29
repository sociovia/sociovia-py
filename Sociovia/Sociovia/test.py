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
from Sociovia.Sociovia.models import db, User, Admin,SocialAccount,Workspace # make sure models.py exports User, Admin
from Sociovia.Sociovia.mailer import send_mail
from Sociovia.Sociovia.tokens import make_action_token, load_action_token
from Sociovia.Sociovia.utils import log_action, valid_password, generate_code, load_email_template      
#from config import Config



from datetime import timedelta

class Config:
    # Security
    # NOTE: For quick local testing you can hardcode, but DO NOT commit this file to any repo.
    SECRET_KEY = "change_me_super_secret_production_key"

    # Database (hardcoded sqlite file)
    SQLALCHEMY_DATABASE_URI = "sqlite:///sociovia.db"
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

# ---------------- Session + CORS ----------------
FRONTEND_ORIGINS = [
     "https://sociovia-c9473.web.app",
    "https://sociovia.com",
    "www.sociovia.com",
    "https://www.sociovia.com",
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
"""
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
    __tablename__ = "workspaces"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    business_name = db.Column(db.String(255))
    business_type = db.Column(db.String(100))
    registered_address = db.Column(db.String(255))
    b2b_b2c = db.Column(db.String(50))
    industry = db.Column(db.String(100))
    describe_business = db.Column(db.Text)
    describe_audience = db.Column(db.Text)
    website = db.Column(db.String(255))
    direct_competitors = db.Column(db.Text)
    indirect_competitors = db.Column(db.Text)
    social_links = db.Column(db.Text)
    usp = db.Column(db.String(255))
    logo_path = db.Column(db.String(255))
    creatives_paths = db.Column(db.Text)
    additional_remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())  # this is missing in DB




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
      1) session['user_id'] (backwards compatible)
      2) X-User-Id header (int)
      3) user_id query param or form field
      4) X-User-Email header
      5) email query param or form field

    Returns User instance or None if not found.
    """
    # 1) session (compatible with older flow)
    user_id = session.get("user_id")
    if user_id:
        u = User.query.get(user_id)
        if u:
            return u

    # 2) X-User-Id header
    uid = request.headers.get("X-User-Id")
    if uid:
        try:
            u = User.query.get(int(uid))
            if u:
                return u
        except Exception:
            pass

    # 3) user_id in query string or form (works for GET, POST multipart)
    uid = request.args.get("user_id") or (request.form.get("user_id") if request.form else None)
    if uid:
        try:
            u = User.query.get(int(uid))
            if u:
                return u
        except Exception:
            pass

    # 4) X-User-Email header
    email = request.headers.get("X-User-Email")
    if email:
        u = User.query.filter_by(email=str(email).strip().lower()).first()
        if u:
            return u

    # 5) email query string or form
    email = request.args.get("email") or (request.form.get("email") if request.form else None)
    if email:
        u = User.query.filter_by(email=str(email).strip().lower()).first()
        if u:
            return u

    if require:
        return None
    return None

@app.route("/api/workspace/setup", methods=["POST"])
def api_workspace_setup():
    """
    Workspace setup (multipart/form-data).
    Prototype mode: identifies user via session, headers, or form fields.
    """
    try:
        # ---- User resolution ----
        user = get_user_from_request(require=True)
        if not user:
            return jsonify({"success": False, "error": "not_authenticated"}), 401
        user_id = user.id

        # ---- Content type check ----
        if not request.content_type or "multipart/form-data" not in request.content_type:
            return jsonify({"success": False, "error": "content_type_must_be_multipart"}), 415

        # ---- Extract form fields ----
        form = request.form
        business_name = (form.get("business_name") or "").strip()
        business_type = (form.get("business_type") or "").strip()
        registered_address = (form.get("registered_address") or "").strip()
        b2b_b2c = (form.get("b2b_b2c") or "").strip().upper()
        industry = (form.get("industry") or "").strip()
        describe_business = (form.get("describe_business") or "").strip()
        describe_audience = (form.get("describe_audience") or "").strip()
        website = (form.get("website") or "").strip()
        direct_competitors_raw = (form.get("direct_competitors") or "").strip()
        indirect_competitors_raw = (form.get("indirect_competitors") or "").strip()
        social_links_raw = (form.get("social_links") or "").strip()
        usp = (form.get("usp") or "").strip()
        additional_remarks = (form.get("additional_remarks") or "").strip()

        # ---- Files ----
        logo_file = request.files.get("logo")
        creatives_files = request.files.getlist("creatives")

        # ---- Validation ----
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
        if len(describe_business) < 100:
            errors.append("describe_business_min_100")
        if len(describe_audience) < 100:
            errors.append("describe_audience_min_100")
        if not usp:
            errors.append("usp_required")
        if not logo_file:
            errors.append("logo_required")
        elif not allowed_file(logo_file.filename):
            errors.append("logo_invalid_file_type")

        # Parse JSON/string lists
        import json
        def split_to_list(raw: str):
            raw = raw.strip()
            if not raw:
                return []
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    return [str(x).strip() for x in parsed if str(x).strip()]
            except Exception:
                pass
            return [part.strip() for part in raw.split(",") if part.strip()]

        direct_competitors = split_to_list(direct_competitors_raw)
        indirect_competitors = split_to_list(indirect_competitors_raw)
        social_links = split_to_list(social_links_raw) if social_links_raw else []

        if len(direct_competitors) < 2:
            errors.append("direct_competitors_min_2")
        if len(indirect_competitors) < 2:
            errors.append("indirect_competitors_min_2")

        if errors:
            return jsonify({"success": False, "errors": errors}), 400

        # ---- File persistence ----
        user_upload_dir = os.path.join(UPLOAD_BASE, str(user_id))
        os.makedirs(user_upload_dir, exist_ok=True)

        # Save logo
        logo_filename = secure_filename(logo_file.filename)
        logo_abs_name = "logo_" + logo_filename
        logo_abs_path = os.path.join(user_upload_dir, logo_abs_name)
        logo_file.save(logo_abs_path)
        logo_path_rel = os.path.join(str(user_id), logo_abs_name)

        # Save creatives
        creatives_paths = []
        for idx, f in enumerate(creatives_files or []):
            if not f or f.filename == "":
                continue
            if not allowed_file(f.filename):
                continue
            safe = secure_filename(f.filename)
            abs_name = f"creative_{idx}_{safe}"
            abs_path = os.path.join(user_upload_dir, abs_name)
            f.save(abs_path)
            creatives_paths.append(os.path.join(str(user_id), abs_name))

        # ---- DB save/update ----
        import json as _json
        workspace = Workspace.query.filter_by(user_id=user_id).first()
        if not workspace:
            workspace = Workspace(user_id=user_id)

        workspace.business_name = business_name
        workspace.business_type = business_type
        workspace.registered_address = registered_address
        workspace.b2b_b2c = b2b_b2c
        workspace.industry = industry
        workspace.describe_business = describe_business
        workspace.describe_audience = describe_audience
        workspace.website = website or None
        workspace.direct_competitors = _json.dumps(direct_competitors)
        workspace.indirect_competitors = _json.dumps(indirect_competitors)
        workspace.social_links = _json.dumps(social_links)
        workspace.usp = usp
        workspace.logo_path = logo_path_rel.replace(os.path.sep, "/")
        workspace.creatives_paths = _json.dumps([p.replace(os.path.sep, "/") for p in creatives_paths])
        workspace.additional_remarks = additional_remarks or None

        db.session.add(workspace)
        db.session.commit()

        # ---- URLs for frontend ----
        logo_url = f"{APP_BASE_URL.rstrip('/')}/uploads/workspaces/{workspace.user_id}/{os.path.basename(logo_abs_path)}"
        creative_urls = [
            f"{APP_BASE_URL.rstrip('/')}/uploads/workspaces/{workspace.user_id}/{os.path.basename(p)}"
            for p in creatives_paths
        ]

        log_action(user.email or "system", "workspace_setup", user.id, {"workspace_id": workspace.id})

        return jsonify({
            "success": True,
            "message": "workspace_saved",
            "workspace": {
                "id": workspace.id,
                "user_id": workspace.user_id,
                "business_name": workspace.business_name,
                "website": workspace.website,
                "logo_url": logo_url,
                "creative_urls": creative_urls,
            }
        }), 201

    except Exception as e:
        # Always log + return JSON
        logger.exception("Workspace setup failed")
        return jsonify({
            "success": False,
            "error": "internal_server_error",
            "details": str(e)  # ⚠️ safe to expose only in dev
        }), 500



@app.route("/api/workspace", methods=["GET"])
def api_workspace_get():
    """Return workspace for current user (if any)."""
    user_id = get_user_from_request("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "not_authenticated"}), 401
    workspace = Workspace.query.filter_by(user_id=user_id).first()
    if not workspace:
        return jsonify({"success": True, "workspace": None}), 200

    import json as _json
    logo = workspace.logo_path
    logo_url = f"{APP_BASE_URL.rstrip('/')}/uploads/workspaces/{workspace.user_id}/{os.path.basename(logo)}" if logo else None
    creatives = _json.loads(workspace.creatives_paths or "[]")
    creative_urls = [
        f"{APP_BASE_URL.rstrip('/')}/uploads/workspaces/{workspace.user_id}/{os.path.basename(p)}"
        for p in creatives
    ]

    return jsonify({
        "success": True,
        "workspace": {
            "id": workspace.id,
            "business_name": workspace.business_name,
            "business_type": workspace.business_type,
            "registered_address": workspace.registered_address,
            "b2b_b2c": workspace.b2b_b2c,
            "industry": workspace.industry,
            "describe_business": workspace.describe_business,
            "describe_audience": workspace.describe_audience,
            "website": workspace.website,
            "direct_competitors": _json.loads(workspace.direct_competitors or "[]"),
            "indirect_competitors": _json.loads(workspace.indirect_competitors or "[]"),
            "social_links": _json.loads(workspace.social_links or "[]"),
            "usp": workspace.usp,
            "logo_url": logo_url,
            "creative_urls": creative_urls,
            "additional_remarks": workspace.additional_remarks,
            "created_at": workspace.created_at.isoformat() if workspace.created_at else None,
            "updated_at": workspace.updated_at.isoformat() if workspace.updated_at else None,
        }
    }), 200

@app.route("/api/me", methods=["GET"])
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
 # adjust import if needed
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
    state = request.args.get('state') or ''
    logger.info('Starting Facebook connect (state=%s)', state)
    auth_url = _build_fb_oauth_url(state=state)
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

# String version to pass to OAuth URLs
OAUTH_SCOPES_STR = ",".join(OAUTH_SCOPES)

@app.route('/api/oauth/facebook/callback', methods=['GET'])
@app.route('/api/oauth/instagram/callback', methods=['GET'])
def oauth_facebook_callback():
    code = request.args.get('code')
    state = request.args.get('state') or ''
    error = request.args.get('error')
    frontend = FRONTEND_BASE_URL.rstrip('/')

    # Helper to render response
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

    # 1️⃣ Handle error / missing code
    if error or not code:
        payload = {"type": "sociovia_oauth_complete", "success": False, "state": state,
                   "fb_error": {"message": error or "no_code"}}
        return render_response(payload)

    # 2️⃣ Exchange code → short-lived token
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

    # 3️⃣ Exchange short-lived → long-lived token
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
        long_token = short_token  # fallback

    # 4️⃣ Fetch pages + IG business accounts
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

    # 5️⃣ Save/update social accounts
    saved = []
    db_error = None
    try:
        user = get_user_from_request(require=False)
        user_id = getattr(user, "id", None)
        for p in pages:
            page_id = str(p.get('id'))
            page_name = p.get('name')
            page_token = p.get('access_token') or long_token
            ig = p.get('instagram_business_account')
            ig_id = str(ig.get('id')) if ig else None

            try:
                existing = SocialAccount.query.filter_by(provider='facebook', provider_user_id=page_id).first()
                if not existing:
                    sa = SocialAccount(
                        provider='facebook',
                        provider_user_id=page_id,
                        account_name=page_name,
                        access_token=page_token,
                        user_id=user_id,
                        scopes=OAUTH_SCOPES,
                        instagram_business_id=ig_id
                    )
                    db.session.add(sa)
                    db.session.commit()
                    saved.append(sa.serialize())
                else:
                    existing.access_token = page_token
                    existing.scopes = OAUTH_SCOPES
                    existing.instagram_business_id = ig_id
                    if user_id:
                        existing.user_id = user_id
                    db.session.add(existing)
                    db.session.commit()
                    saved.append(existing.serialize())
            except Exception as e:
                db.session.rollback()
                db_error = str(e)
    except Exception as e:
        db_error = str(e)

    # 6️⃣ Respond to frontend
    resp_payload = {
        "type": "sociovia_oauth_complete",
        "success": (len(saved) > 0 and db_error is None),
        "state": state,
        "saved": saved,
        "fb_pages_count": len(pages)
    }
    if db_error:
        resp_payload["db_error"] = db_error

    return render_response(resp_payload)


@app.route('/api/oauth/facebook/save-selection', methods=['POST'])
@cross_origin(origins=["https://sociovia.com","https://6136l5dn-5000.inc1.devtunnels.ms"], supports_credentials=True)
def oauth_save_selection():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({'success': False, 'error': 'invalid_json'}), 400

    # Use user_id from frontend if present
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'error': 'missing_user_id'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'error': 'user_not_found'}), 404

    accounts = data.get('accounts', [])
    features = data.get('features', {})
    saved = []

    for a in accounts:
        provider = a.get('provider') or 'facebook'
        pid = str(a.get('provider_user_id'))
        sa = SocialAccount.query.filter_by(provider=provider, provider_user_id=pid, user_id=user.id).first()
        enabled_scopes = [k for k, v in (features or {}).items() if v]

        if sa:
            sa.scopes = ",".join(enabled_scopes) if enabled_scopes else sa.scopes
        else:
            sa = SocialAccount(
                user_id=user.id,
                provider=provider,
                provider_user_id=pid,
                account_name=a.get('name', ''),
                scopes=",".join(enabled_scopes)
            )
            db.session.add(sa)
        saved.append(sa.serialize())

    db.session.commit()
    return jsonify({'success': True, 'connected': saved}), 200



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
    # your existing implementation, for example:
    DEFAULT_USER_ID = 1
    user = get_user_from_request(require=True)
    print(user,flush=True)
    accounts = SocialAccount.query.order_by(SocialAccount.id.desc()).all()
    rows = []
    active = None

    for a in accounts:
        item = {"db": a.serialize(), "fb_raw": None, "error": None}

        # Fallback token: account token first, else default user token
        token = a.access_token or get_facebook_token_for_user(getattr(user, "id", DEFAULT_USER_ID))

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

        # If you want to default active to first account when no user, set:
        try:
            if getattr(user, "active_social_account_id", None) == a.id:
                active = a.serialize()
        except Exception:
            pass

    # If no active and there are accounts, set first as active (optional)
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
    """Update social account permissions (always under user ID 1)"""
    user_id = 1  # fixed user

    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "invalid_request"}), 400

    provider = data.get("provider")
    provider_user_id = str(data.get("provider_user_id") or "")
    scopes = data.get("scopes", [])

    if not provider or not provider_user_id:
        return jsonify({"success": False, "error": "missing_required_fields"}), 400

    account = SocialAccount.query.filter_by(
        provider=provider,
        provider_user_id=provider_user_id
    ).first()

    if not account:
        return jsonify({"success": False, "error": "account_not_found"}), 404

    try:
        account.scopes = ",".join(scopes)
        account.user_id = user_id  # always set user to 1
        db.session.add(account)
        db.session.commit()

        return jsonify({
            "success": True,
            "account": account.serialize()
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "success": False,
            "error": "db_error",
            "message": str(e)
        }), 500

# Fix unlink endpoint
@app.route("/api/social/unlink", methods=["POST"]) 
def api_social_unlink():
    """Unlink social account"""
    user = get_user_from_request(require=True)
    if not user:
        return jsonify({"success": False, "error": "unauthorized"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "invalid_request"}), 400

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
                logger.warning(f"Failed to revoke FB token: {e}")

        db.session.delete(account)
        db.session.commit()

        return jsonify({"success": True})

    except Exception as e:
        db.session.rollback()
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



# ---------------- Run (dev) ----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        debug_flag = os.getenv("FLASK_ENV", "development") != "production"
        app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=debug_flag)








