# mailer.py (quick fix)
import smtplib
import traceback
from flask import current_app
from concurrent.futures import ThreadPoolExecutor

# single global pool (module-level)
THREAD_POOL = ThreadPoolExecutor(max_workers=4)

def _send_smtp(recipient, subject, body):
    try:
        smtp_host = current_app.config.get("SMTP_HOST")
        smtp_port = int(current_app.config.get("SMTP_PORT", 25))
        smtp_user = current_app.config.get("SMTP_USER")
        smtp_pass = "hrgm qfdi ehky uyyz"

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            if server.has_extn("starttls"):
                server.starttls()
                server.ehlo()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            msg = f"From: {smtp_user or 'no-reply@yourdomain.com'}\r\nTo: {recipient}\r\nSubject: {subject}\r\n\r\n{body}"
            server.sendmail(smtp_user or "no-reply@yourdomain.com", [recipient], msg)
    except Exception:
        # ensure we only log errors; never bubble up to request
        current_app.logger.exception("Failed to send email")

def send_mail(recipient, subject, body, async_send=True):
    """
    Public helper — by default sends async in thread pool
    """
    if async_send:
        try:
            THREAD_POOL.submit(_send_smtp, recipient, subject, body)
        except Exception:
            current_app.logger.exception("Failed to schedule email send")
    else:
        _send_smtp(recipient, subject, body)
