import smtplib
import ssl
import socket
import time
from email.message import EmailMessage
from flask import current_app

def can_connect(host, port, timeout=5):
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        current_app.logger.debug("[MAIL-TEST] DNS resolution failed for %s: %s", host, e)
        return False, f"dns:{e}"
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, None
    except Exception as e:
        return False, str(e)

def send_mail(to_addrs, subject, body, max_retries=2):
    if isinstance(to_addrs, str):
        to_addrs = [to_addrs]

    smtp_host = current_app.config.get("SMTP_HOST", "smtp.gmail.com")
    smtp_user = current_app.config.get("SMTP_USER")
    smtp_pass = current_app.config.get("SMTP_PASS")
    mail_from = current_app.config.get("MAIL_FROM", smtp_user)
    smtp_port_tls = current_app.config.get("SMTP_PORT_TLS", 587)
    smtp_port_ssl = current_app.config.get("SMTP_PORT_SSL", 465)

    if not smtp_host or not smtp_user or not smtp_pass:
        current_app.logger.warning(f"[MAIL-FAKE] Would send to {to_addrs}, subject='{subject}'\n{body}")
        return

    # connectivity quick check
    ok, why = can_connect(smtp_host, smtp_port_tls)
    if not ok:
        ok_ssl, why_ssl = can_connect(smtp_host, smtp_port_ssl)
        current_app.logger.warning("[MAIL-TEST] connectivity check TLS=%s(%s), SSL=%s(%s)",
                                   ok, why, ok_ssl, why_ssl)
        # if both fail, bail early (network issue)
        if not ok and not ok_ssl:
            current_app.logger.error("[MAIL-FAIL] network unreachable for SMTP host: %s (tls:%s ssl:%s)", smtp_host, why, why_ssl)
            current_app.logger.warning(f"[MAIL-BACKUP] Would send to {to_addrs}, subject='{subject}'\n{body}")
            return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = mail_from
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(body)

    context = ssl.create_default_context()

    # attempt send with retries
    attempt = 0
    last_exc = None
    while attempt <= max_retries:
        attempt += 1
        try:
            # prefer TLS (starttls)
            with smtplib.SMTP(smtp_host, smtp_port_tls, timeout=10) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            current_app.logger.info(f"[MAIL-SUCCESS] Email sent to {to_addrs} via TLS 587 (attempt {attempt})")
            return
        except Exception as e:
            last_exc = e
            current_app.logger.warning("[MAIL-TLS-FAIL] attempt %d: %s", attempt, e)
            time.sleep(1.5 ** attempt)

        try:
            with smtplib.SMTP_SSL(smtp_host, smtp_port_ssl, context=context, timeout=10) as server:
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            current_app.logger.info(f"[MAIL-SUCCESS] Email sent to {to_addrs} via SSL 465 (attempt {attempt})")
            return
        except Exception as e:
            last_exc = e
            current_app.logger.warning("[MAIL-SSL-FAIL] attempt %d: %s", attempt, e)
            time.sleep(1.5 ** attempt)

    current_app.logger.error("[MAIL-FAIL] final failure sending email: %s", last_exc)
    current_app.logger.warning(f"[MAIL-BACKUP] Would send to {to_addrs}, subject='{subject}'\n{body}")
