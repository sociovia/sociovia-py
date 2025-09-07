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
from flask_cors import CORS

#from config import Config
from Sociovia.Sociovia.config import Config

from Sociovia.Sociovia.models import db, User, Admin,SocialAccount  # make sure models.py exports User, Admin
from Sociovia.Sociovia.mailer import send_mail
from Sociovia.Sociovia.tokens import make_action_token, load_action_token
from Sociovia.Sociovia.utils import log_action, valid_password, generate_code, load_email_template

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

from urllib.parse import unquote
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
    user_id = session.get("user_id")
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
from Sociovia.Sociovia.models import Workspace  # adjust import if needed
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

# ---------------- Run (dev) ----------------
if __name__ == "__main__":
    debug_flag = os.getenv("FLASK_ENV", "development") != "production"
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=debug_flag)













