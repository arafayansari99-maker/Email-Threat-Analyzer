"""
Admin setup utility - Run this script ONCE to create the initial admin account.
Usage: python setup_admin.py

This replaces the insecure hardcoded admin credentials.
"""
import os
import sys
from datetime import datetime
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database import get_db, User
from routers.auth import get_password_hash

ADMIN_EMAIL = os.environ.get("ETA_ADMIN_EMAIL", "admin@eta.local")
ADMIN_USERNAME = os.environ.get("ETA_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ETA_ADMIN_PASSWORD", "Eta@2026!SecureAdmin")


def setup_admin():
    """Create or update the admin account."""
    db = next(get_db())

    # Check if admin exists
    admin = db.query(User).filter(User.email == ADMIN_EMAIL).first()

    if admin:
        print(f"Admin already exists: {admin.email}")
        # Update password if requested
        if os.environ.get("ETA_RESET_ADMIN_PASSWORD"):
            admin.hashed_pw = get_password_hash(ADMIN_PASSWORD)
            db.commit()
            print(f"Admin password updated")
        return admin

    # Create new admin
    admin = User(
        username=ADMIN_USERNAME,
        email=ADMIN_EMAIL,
        hashed_pw=get_password_hash(ADMIN_PASSWORD),
        role="superadmin",
        is_active=True,
        is_approved=True,
        created_at=datetime.utcnow(),
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)

    print(f"Admin created successfully!")
    print(f"  Email: {admin.email}")
    print(f"  Username: {admin.username}")
    print(f"  Role: {admin.role}")
    print(f"\nIMPORTANT: Change the default password in production!")
    print(f"  Set ETA_ADMIN_EMAIL and ETA_ADMIN_PASSWORD environment variables")

    return admin


if __name__ == "__main__":
    setup_admin()