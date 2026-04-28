"""
Email Notification Service - Handles all email notifications for the app.
In production, replace with SMTP, SendGrid, AWS SES, etc.
"""
import os
import logging
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Email configuration
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "noreply@eta.local")
FROM_NAME = os.environ.get("FROM_NAME", "ETA Security")


class EmailService:
    """Email notification service."""

    def __init__(self):
        self.enabled = bool(SMTP_HOST)

    def send_email(
        self,
        to: str,
        subject: str,
        body: str,
        html: Optional[str] = None,
    ) -> bool:
        """Send an email."""
        if not self.enabled:
            # Log instead of sending in development
            logger.info(f"[EMAIL] To: {to}")
            logger.info(f"[EMAIL] Subject: {subject}")
            logger.info(f"[EMAIL] Body: {body}")
            return True

        # In production, implement actual email sending
        # Example with SMTP:
        # import smtplib
        # from email.mime.text import MIMEText
        # from email.mime.multipart import MIMEMultipart

        # msg = MIMEMultipart()
        # msg["From"] = f"{FROM_NAME} <{FROM_EMAIL}>"
        # msg["To"] = to
        # msg["Subject"] = subject
        # msg.attach(MIMEText(body, "plain"))
        # if html:
        #     msg.attach(MIMEText(html, "html"))

        # with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        #     server.starttls()
        #     server.login(SMTP_USER, SMTP_PASSWORD)
        #     server.send_message(msg)

        return True

    def send_account_approved(self, email: str, username: str) -> bool:
        """Send account approval notification."""
        subject = "Your ETA Account Has Been Approved"
        body = f"""Hello {username},

Your ETA account has been approved! You can now log in to start analyzing emails for threats.

Log in at: https://eta.example.com/login

If you have any questions, please contact your administrator.

Best regards,
ETA Security Team
"""
        return self.send_email(email, subject, body)

    def send_account_created(self, email: str, username: str) -> bool:
        """Send account created notification."""
        subject = "Welcome to ETA - Account Pending Approval"
        body = f"""Hello {username},

Your ETA account has been created successfully!

Your account is now pending approval from an administrator. You'll receive another email once your account has been approved.

In the meantime, you can prepare the email files you'd like to analyze.

Best regards,
ETA Security Team
"""
        return self.send_email(email, subject, body)

    def send_password_reset(self, email: str, username: str, reset_url: str) -> bool:
        """Send password reset email."""
        subject = "Reset Your ETA Password"
        body = f"""Hello {username},

We received a request to reset your password. Click the link below to create a new password:

{reset_url}

This link will expire in 1 hour.

If you didn't request this password reset, please ignore this email or contact support if you have concerns.

Best regards,
ETA Security Team
"""
        return self.send_email(email, subject, body)

    def send_new_login_alert(
        self,
        email: str,
        username: str,
        ip_address: str,
        user_agent: str,
    ) -> bool:
        """Alert user of new login from unknown device."""
        subject = "New Login to Your ETA Account"
        body = f"""Hello {username},

A new login was detected on your ETA account:

- IP Address: {ip_address}
- Device: {user_agent[:100] if user_agent else 'Unknown'}
- Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

If this was you, no action needed.
If you don't recognize this login, please reset your password immediately and contact support.

Best regards,
ETA Security Team
"""
        return self.send_email(email, subject, body)

    def send_failed_login_alert(
        self,
        email: str,
        username: str,
        ip_address: str,
        attempts: int,
    ) -> bool:
        """Alert user of failed login attempts."""
        subject = "Failed Login Attempts on Your ETA Account"
        body = f"""Hello {username},

We detected {attempts} failed login attempt(s) on your account:

- IP Address: {ip_address}
- Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

If this was you, you can safely ignore this message.
If you don't recognize these attempts, please consider resetting your password to secure your account.

Best regards,
ETA Security Team
"""
        return self.send_email(email, subject, body)

    def send_account_disabled(self, email: str, username: str) -> bool:
        """Notify user their account has been disabled."""
        subject = "Your ETA Account Has Been Disabled"
        body = f"""Hello {username},

Your ETA account has been disabled by an administrator.

If you believe this was done in error, please contact your administrator to request reactivation.

Best regards,
ETA Security Team
"""
        return self.send_email(email, subject, body)


# Singleton instance
email_service = EmailService()