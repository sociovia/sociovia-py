import smtplib
import ssl
from email.message import EmailMessage
from flask import current_app

def send_mail(to_addrs, subject, body):
    if isinstance(to_addrs, str):
        to_addrs = [to_addrs]

    smtp_host = current_app.config.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port_tls = 587
    smtp_port_ssl = 465
    smtp_user = current_app.config.get("SMTP_USER")
    smtp_pass = current_app.config.get("SMTP_PASS")
    mail_from = current_app.config.get("MAIL_FROM", smtp_user)

    if not smtp_host or not smtp_user or not smtp_pass:
        current_app.logger.warning(f"[MAIL-FAKE] Would send to {to_addrs}, subject='{subject}'")
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = mail_from
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(body)

    context = ssl.create_default_context()

    # Try TLS (port 587) first
    try:
        with smtplib.SMTP(smtp_host, smtp_port_tls, timeout=10) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        current_app.logger.info(f"[MAIL-SUCCESS] Email sent to {to_addrs} via TLS 587")
        return
    except Exception as e_tls:
        current_app.logger.warning(f"[MAIL-TLS-FAIL] TLS 587 failed: {e_tls}, trying SSL 465...")

    # Fallback to SSL (port 465)
    try:
        with smtplib.SMTP_SSL(smtp_host, smtp_port_ssl, context=context, timeout=10) as server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        current_app.logger.info(f"[MAIL-SUCCESS] Email sent to {to_addrs} via SSL 465")
        return
    except Exception as e_ssl:
        current_app.logger.error(f"[MAIL-FAIL] Could not send to {to_addrs}, TLS error: {e_tls}, SSL error: {e_ssl}")
        current_app.logger.warning(f"[MAIL-BACKUP] Would send to {to_addrs}, subject='{subject}'\n{body}")
