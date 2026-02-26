"""
SentinelSQL — Auth Layer
mock_users.py — 6 Apollo Hospital user personas for development/demo.

In production, replace this with a PostgreSQL-backed user store
querying the apollo_hospitals_db `staff` / `doctors` / `hr_employees` tables.

Password for all mock users: Apollo@123
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Optional

from layer01_identity.models import ClearanceLevel, UserProfile


# ─── SIMPLE PASSWORD HASHING (no bcrypt dependency) ──────────────────────────
# Uses PBKDF2-HMAC-SHA256 from Python stdlib — production-grade, no extra deps.
# In production: use passlib[bcrypt] or argon2-cffi instead.

def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"{salt}${key.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    try:
        salt, key_hex = hashed.split("$")
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
        return hmac.compare_digest(key.hex(), key_hex)
    except Exception:
        return False


# ─── MOCK USER RECORD ─────────────────────────────────────────────────────────

@dataclass
class MockUser:
    username:     str
    display_name: str
    password_hash: str
    role:         str          # Single IdP role — hierarchy resolver expands it
    profile:      UserProfile
    avatar_initials: str
    avatar_color: str          # CSS color for avatar bubble
    department_label: str      # Human-readable for UI
    is_active:    bool = True


# ─── THE 6 APOLLO PERSONAS ────────────────────────────────────────────────────

_PASSWORD = "Apollo@123"
_HASHED_PASSWORD = hash_password(_PASSWORD)

MOCK_USERS: dict[str, MockUser] = {

    "dr.arjun": MockUser(
        username="dr.arjun",
        display_name="Dr. Arjun Mehta",
        password_hash=_HASHED_PASSWORD,
        role="ATTENDING_PHYSICIAN",
        avatar_initials="AM",
        avatar_color="#0EA5E9",
        department_label="Cardiology · Apollo Hospitals Delhi",
        profile=UserProfile(
            user_id="dr.arjun",
            department="Cardiology",
            unit="Cardiac ICU",
            facility="Apollo Hospitals Delhi",
            provider_id="MCI-DL-2891",
            clearance_level=ClearanceLevel.CONFIDENTIAL,
            is_active=True,
        ),
    ),

    "nurse.priya": MockUser(
        username="nurse.priya",
        display_name="Priya Radhakrishnan",
        password_hash=_HASHED_PASSWORD,
        role="NURSE",
        avatar_initials="PR",
        avatar_color="#10B981",
        department_label="ICU Nursing · Apollo Hospitals Chennai",
        profile=UserProfile(
            user_id="nurse.priya",
            department="Nursing",
            unit="Surgical ICU",
            facility="Apollo Hospitals Chennai",
            provider_id=None,
            clearance_level=ClearanceLevel.INTERNAL,
            is_active=True,
        ),
    ),

    "admin.suresh": MockUser(
        username="admin.suresh",
        display_name="Suresh Krishnamurthy",
        password_hash=_HASHED_PASSWORD,
        role="ADMIN",
        avatar_initials="SK",
        avatar_color="#F59E0B",
        department_label="Hospital Administration · Apollo Hospitals Hyderabad",
        profile=UserProfile(
            user_id="admin.suresh",
            department="Administration",
            unit="Operations",
            facility="Apollo Hospitals Hyderabad",
            provider_id=None,
            clearance_level=ClearanceLevel.SECRET,
            is_active=True,
        ),
    ),

    "analyst.deepa": MockUser(
        username="analyst.deepa",
        display_name="Deepa Sundaram",
        password_hash=_HASHED_PASSWORD,
        role="DATA_ANALYST",
        avatar_initials="DS",
        avatar_color="#8B5CF6",
        department_label="Business Intelligence · Apollo Health Analytics",
        profile=UserProfile(
            user_id="analyst.deepa",
            department="Data Analytics",
            unit="Revenue Intelligence",
            facility="Apollo Corporate HQ",
            provider_id=None,
            clearance_level=ClearanceLevel.CONFIDENTIAL,
            is_active=True,
        ),
    ),

    "pharma.ravi": MockUser(
        username="pharma.ravi",
        display_name="Ravi Thandapani",
        password_hash=_HASHED_PASSWORD,
        role="PHARMACIST",
        avatar_initials="RT",
        avatar_color="#EC4899",
        department_label="Pharmacy · Apollo Hospitals Bangalore",
        profile=UserProfile(
            user_id="pharma.ravi",
            department="Pharmacy",
            unit="Inpatient Dispensary",
            facility="Apollo Hospitals Bangalore",
            provider_id="PCI-KA-4412",
            clearance_level=ClearanceLevel.INTERNAL,
            is_active=True,
        ),
    ),

    "superadmin": MockUser(
        username="superadmin",
        display_name="Platform Super Admin",
        password_hash=_HASHED_PASSWORD,
        role="SUPER_ADMIN",
        avatar_initials="SA",
        avatar_color="#EF4444",
        department_label="SentinelSQL Platform · All Facilities",
        profile=UserProfile(
            user_id="superadmin",
            department="Platform Engineering",
            unit="Security",
            facility="ALL",
            provider_id=None,
            clearance_level=ClearanceLevel.TOP_SECRET,
            is_active=True,
        ),
    ),
}


# ─── LOOKUP HELPERS ───────────────────────────────────────────────────────────

def get_user(username: str) -> Optional[MockUser]:
    return MOCK_USERS.get(username.lower())


def authenticate(username: str, password: str) -> Optional[MockUser]:
    """Returns the MockUser if credentials are valid, else None."""
    user = get_user(username)
    if user is None:
        return None
    if not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


# ─── ROLE → UI METADATA ───────────────────────────────────────────────────────
# Used by the dashboard to render role-specific permission cards.

ROLE_UI_META: dict[str, dict] = {
    "SUPER_ADMIN": {
        "badge_color": "#EF4444",
        "clearance_color": "#EF4444",
        "permissions": [
            {"icon": "🏥", "label": "All Facilities", "desc": "Full access across all Apollo locations"},
            {"icon": "👥", "label": "Staff Management", "desc": "HR, payroll, credentials"},
            {"icon": "📊", "label": "All Analytics", "desc": "Revenue, clinical, operational BI"},
            {"icon": "🔐", "label": "Audit Logs", "desc": "Full HIPAA audit trail access"},
            {"icon": "⚙️", "label": "System Config", "desc": "Roles, policies, schema access"},
            {"icon": "🚨", "label": "Break-the-Glass", "desc": "Emergency override access"},
        ],
    },
    "ADMIN": {
        "badge_color": "#F59E0B",
        "clearance_color": "#F59E0B",
        "permissions": [
            {"icon": "📋", "label": "Billing & Revenue", "desc": "Insurance claims, invoices, revenue cycle"},
            {"icon": "👥", "label": "Staff Records", "desc": "Employee profiles, attendance, payroll"},
            {"icon": "📊", "label": "Operational Reports", "desc": "Occupancy, performance dashboards"},
            {"icon": "🏥", "label": "Facility Management", "desc": "Bed management, department ops"},
            {"icon": "📦", "label": "Inventory", "desc": "Medical supplies, pharmacy stock"},
        ],
    },
    "ATTENDING_PHYSICIAN": {
        "badge_color": "#0EA5E9",
        "clearance_color": "#0EA5E9",
        "permissions": [
            {"icon": "🩺", "label": "Patient Records", "desc": "Full clinical history for your patients"},
            {"icon": "💊", "label": "Prescriptions", "desc": "Write and review medication orders"},
            {"icon": "🧪", "label": "Lab Results", "desc": "Diagnostics, pathology, LOINC data"},
            {"icon": "📝", "label": "SOAP Notes", "desc": "Clinical documentation"},
            {"icon": "📅", "label": "Appointments", "desc": "Your schedule and patient bookings"},
        ],
    },
    "NURSE": {
        "badge_color": "#10B981",
        "clearance_color": "#10B981",
        "permissions": [
            {"icon": "💓", "label": "Vital Signs", "desc": "Record and view patient vitals"},
            {"icon": "🛏️", "label": "Bed Management", "desc": "Ward assignments, transfers"},
            {"icon": "📋", "label": "Care Notes", "desc": "Nursing documentation"},
            {"icon": "💊", "label": "Medication Admin", "desc": "Administer prescriptions"},
        ],
    },
    "DATA_ANALYST": {
        "badge_color": "#8B5CF6",
        "clearance_color": "#8B5CF6",
        "permissions": [
            {"icon": "📊", "label": "Revenue Analytics", "desc": "Billing trends, payer mix, collections"},
            {"icon": "🏥", "label": "Occupancy Reports", "desc": "Bed utilization, department load"},
            {"icon": "👨⚕️", "label": "Doctor Performance", "desc": "Consultation metrics, outcomes"},
            {"icon": "💊", "label": "Pharmacy Analytics", "desc": "Drug sales, formulary performance"},
        ],
    },
    "PHARMACIST": {
        "badge_color": "#EC4899",
        "clearance_color": "#EC4899",
        "permissions": [
            {"icon": "💊", "label": "Drug Inventory", "desc": "Stock levels, batch tracking, expiry"},
            {"icon": "📋", "label": "Prescriptions", "desc": "Inpatient & outpatient dispensing"},
            {"icon": "🏭", "label": "Purchase Orders", "desc": "Supplier management, procurement"},
            {"icon": "⚠️", "label": "Expiry Alerts", "desc": "Near-expiry and recall notifications"},
        ],
    },
}
