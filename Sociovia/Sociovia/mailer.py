import smtplib
import ssl
from email.message import EmailMessage
"""
def send_mail(to_addrs, subject, body):
    """
    Quick hardcoded SMTP sender for testing.
    """
    if isinstance(to_addrs, str):
        to_addrs = [to_addrs]

    # ===== HARDCODED SMTP SETTINGS =====
    smtp_host = "smtp.gmail.com"       # Replace with your SMTP server if different
    smtp_port_tls = 25
    smtp_port_ssl = 465
    smtp_user = "sociovia.ai@gmail.com"  # Replace with your email
    smtp_pass = "dinm hrwm igpd sjyy"    # Replace with your App Password / SMTP password
    mail_from = smtp_user
    # ==================================

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = mail_from
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(body)

    context = ssl.create_default_context()
    e_tls, e_ssl = None, None

    # Try TLS first
    try:
        with smtplib.SMTP(smtp_host, smtp_port_tls, timeout=10) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        print(f"[MAIL-SUCCESS] Email sent to {to_addrs} via TLS 587")
        return
    except Exception as ex_tls:
        e_tls = ex_tls
        print(f"[MAIL-TLS-FAIL] TLS 587 failed: {e_tls}, trying SSL 465...")

    # Try SSL
    try:
        with smtplib.SMTP_SSL(smtp_host, smtp_port_ssl, context=context, timeout=10) as server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        print(f"[MAIL-SUCCESS] Email sent to {to_addrs} via SSL 465")
        return
    except Exception as ex_ssl:
        e_ssl = ex_ssl
        print(f"[MAIL-FAIL] Could not send to {to_addrs}, TLS error: {e_tls}, SSL error: {e_ssl}")

    # Final fallback logging
    print(f"[MAIL-BACKUP] Would send to {to_addrs}, subject='{subject}'\n{body}")
    """

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from flask import current_app

def send_mail(to_addrs, subject, body):
    """
    Send email using SendGrid API
    """
    # Handle single email or list of emails
    if isinstance(to_addrs, str):
        to_addrs = [to_addrs]
    
    # Skip if no SendGrid API key
    if not current_app.config.get("SENDGRID_API_KEY"):
        print(f"Email would be sent to {to_addrs}: {subject}")
        print(f"Body: {body}")
        return
    
    try:
        # Create the email
        message = Mail(
            from_email="sociovia.ai@gmail.com",
            to_emails=to_addrs,
            subject=subject,
            html_content=body
        )

        # Send email
        sg = SendGridAPIClient(current_app.config["SENDGRID_API_KEY"])
        response = sg.send(message)

        print(f"Email sent successfully to {to_addrs}, Status Code: {response.status_code}")

    except Exception as e:
        print(f"Failed to send email to {to_addrs}: {e}")
        raise

