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
    department:   str          # Added department
    is_active:    bool = True


# ─── THE 6 APOLLO PERSONAS ────────────────────────────────────────────────────

_PASSWORD = "Apollo@123"
_HASHED_PASSWORD = hash_password(_PASSWORD)

MOCK_USERS: dict[str, MockUser] = {
    "dr-patel-4521": MockUser(
        username="dr-patel-4521",
        display_name="Dr. Rajesh Patel",
        password_hash=_HASHED_PASSWORD,
        role="Attending_Physician",
        department="Cardiology",
    ),
    "dr-sharma-1102": MockUser(
        username="dr-sharma-1102",
        display_name="Dr. Priya Sharma",
        password_hash=_HASHED_PASSWORD,
        role="Consulting_Physician",
        department="Oncology",
    ),
    "dr-reddy-2233": MockUser(
        username="dr-reddy-2233",
        display_name="Dr. Aditya Reddy",
        password_hash=_HASHED_PASSWORD,
        role="Emergency_Physician",
        department="Emergency Medicine",
    ),
    "dr-iyer-3301": MockUser(
        username="dr-iyer-3301",
        display_name="Dr. Meera Iyer",
        password_hash=_HASHED_PASSWORD,
        role="Psychiatrist",
        department="Psychiatry",
    ),
    "nurse-kumar-2847": MockUser(
        username="nurse-kumar-2847",
        display_name="Anita Kumar",
        password_hash=_HASHED_PASSWORD,
        role="Registered_Nurse",
        department="Cardiology",
    ),
    "nurse-nair-3102": MockUser(
        username="nurse-nair-3102",
        display_name="Deepa Nair",
        password_hash=_HASHED_PASSWORD,
        role="ICU_Nurse",
        department="Emergency Medicine",
    ),
    "nurse-singh-4455": MockUser(
        username="nurse-singh-4455",
        display_name="Rajesh Singh",
        password_hash=_HASHED_PASSWORD,
        role="Head_Nurse",
        department="Neurology",
    ),
    "bill-maria-5521": MockUser(
        username="bill-maria-5521",
        display_name="Maria Fernandes",
        password_hash=_HASHED_PASSWORD,
        role="Billing_Clerk",
        department="Billing & Revenue Cycle",
    ),
    "bill-suresh-5530": MockUser(
        username="bill-suresh-5530",
        display_name="Suresh Gupta",
        password_hash=_HASHED_PASSWORD,
        role="Revenue_Cycle_Analyst",
        department="Billing & Revenue Cycle",
    ),
    "rev-james-6601": MockUser(
        username="rev-james-6601",
        display_name="James Thomas",
        password_hash=_HASHED_PASSWORD,
        role="Revenue_Cycle_Manager",
        department="Billing & Revenue Cycle",
    ),
    "hr-priya-7701": MockUser(
        username="hr-priya-7701",
        display_name="Priya Mehta",
        password_hash=_HASHED_PASSWORD,
        role="HR_Manager",
        department="Human Resources",
    ),
    "hr-dir-kapoor": MockUser(
        username="hr-dir-kapoor",
        display_name="Rohit Kapoor",
        password_hash=_HASHED_PASSWORD,
        role="HR_Director",
        department="Human Resources",
    ),
    "it-admin-7801": MockUser(
        username="it-admin-7801",
        display_name="Vikram Joshi",
        password_hash=_HASHED_PASSWORD,
        role="IT_Administrator",
        department="Information Technology",
    ),
    "hipaa-officer": MockUser(
        username="hipaa-officer",
        display_name="Dr. Sunita Verma",
        password_hash=_HASHED_PASSWORD,
        role="HIPAA_Privacy_Officer",
        department="Compliance & Legal",
    ),
    "researcher-das": MockUser(
        username="researcher-das",
        display_name="Dr. Anirban Das",
        password_hash=_HASHED_PASSWORD,
        role="Clinical_Researcher",
        department="Quality Assurance",
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
