import smtplib
import ssl
from email.message import EmailMessage
from flask import current_app

def send_mail(to_addrs, subject, body):
    """
    Send email using SMTP configuration from Flask config.
    Falls back to logging if SMTP is unavailable.
    """
    if isinstance(to_addrs, str):
        to_addrs = [to_addrs]

    smtp_user = current_app.config.get("SMTP_USER")
    smtp_pass = current_app.config.get("SMTP_PASS")
    smtp_host = current_app.config.get("SMTP_HOST")
    smtp_port = current_app.config.get("SMTP_PORT", 587)
    mail_from = current_app.config.get("MAIL_FROM", smtp_user or "no-reply@sociovia.com")

    # Fallback if no SMTP config
    if not smtp_user or not smtp_pass or not smtp_host:
        current_app.logger.warning(
            f"[MAIL-FAKE] Would send to={to_addrs}, subject='{subject}'\n{body}"
        )
        return

    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = mail_from
        msg["To"] = ", ".join(to_addrs)
        msg.set_content(body)

        context = ssl.create_default_context()

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls(context=context)
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)

        current_app.logger.info(f"Email sent successfully to {to_addrs}")

    except Exception as e:
        current_app.logger.error(
            f"[MAIL-FAIL] Could not send to={to_addrs}, subject='{subject}', error={e}"
        )
        # Fallback: don’t crash, just log the email
        current_app.logger.warning(
            f"[MAIL-BACKUP] Would send to={to_addrs}, subject='{subject}'\n{body}"
        )
