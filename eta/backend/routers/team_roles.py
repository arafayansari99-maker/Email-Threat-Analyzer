"""
Team Roles Router - Manages team roles and granular permissions.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database import get_db, User
from routers.auth import get_current_user

router = APIRouter(prefix="/team", tags=["team"])

# Role definitions with permissions
ROLE_PERMISSIONS = {
    "superadmin": {
        "manage_users": True,
        "manage_settings": True,
        "view_audit_logs": True,
        "approve_users": True,
        "delete_scans": True,
        "export_data": True,
        "manage_api_keys": True,
        "view_all_scans": True,
    },
    "admin": {
        "manage_users": True,
        "manage_settings": False,
        "view_audit_logs": True,
        "approve_users": True,
        "delete_scans": True,
        "export_data": True,
        "manage_api_keys": True,
        "view_all_scans": True,
    },
    "soc_analyst": {
        "manage_users": False,
        "manage_settings": False,
        "view_audit_logs": True,
        "approve_users": False,
        "delete_scans": True,
        "export_data": True,
        "manage_api_keys": False,
        "view_all_scans": True,
    },
    "analyst": {
        "manage_users": False,
        "manage_settings": False,
        "view_audit_logs": False,
        "approve_users": False,
        "delete_scans": False,
        "export_data": True,
        "manage_api_keys": False,
        "view_all_scans": False,
    },
    "viewer": {
        "manage_users": False,
        "manage_settings": False,
        "view_audit_logs": False,
        "approve_users": False,
        "delete_scans": False,
        "export_data": False,
        "manage_api_keys": False,
        "view_all_scans": False,
    },
    "user": {
        "manage_users": False,
        "manage_settings": False,
        "view_audit_logs": False,
        "approve_users": False,
        "delete_scans": False,
        "export_data": False,
        "manage_api_keys": False,
        "view_all_scans": False,
    },
}


class RoleCheckResponse(BaseModel):
    role: str
    permissions: dict
    can: dict  # Convenience: boolean permissions for frontend


class UpdateRoleRequest(BaseModel):
    role: str


@router.get("/role", response_model=RoleCheckResponse)
def get_my_role(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):

    permissions = ROLE_PERMISSIONS.get(current_user.role, ROLE_PERMISSIONS["user"])

    return RoleCheckResponse(
        role=current_user.role,
        permissions=permissions,
        can=permissions,
    )


@router.get("/roles")
def list_roles():
    """List all available roles and their permissions."""
    return {
        role: {
            "description": _get_role_description(role),
            "permissions": perms,
        }
        for role, perms in ROLE_PERMISSIONS.items()
    }


def _get_role_description(role: str) -> str:
    descriptions = {
        "superadmin": "Full system access, can manage all settings and users",
        "admin": "Manage users, approve accounts, view audit logs",
        "soc_analyst": "View all scans, analyze threats, export data",
        "analyst": "Analyze emails, create reports",
        "viewer": "View own scans only, read-only access",
        "user": "Basic user, analyze own emails",
    }
    return descriptions.get(role, "Basic user access")


def check_permission(user: User, permission: str) -> bool:
    """Check if a user has a specific permission."""
    perms = ROLE_PERMISSIONS.get(user.role, ROLE_PERMISSIONS["user"])
    return perms.get(permission, False)


def require_permission(user: User, permission: str):
    """Dependency to require a specific permission."""
    if not check_permission(user, permission):
        raise HTTPException(403, f"Permission denied: {permission}")