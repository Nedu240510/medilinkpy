# medilink.py
# MediLink – Health Access App (offline-first, no API keys)
# Multi-profile + local per-user encryption (optional) and Sign Up / Login (no global master password)
# Full country dialing codes included
# Login / Sign up stores per-user salted password hashes and per-user enc-salt for optional encryption

import streamlit as st
import datetime as dt
import json
import os
import random
import re
import urllib.parse
import hashlib
import hmac
import binascii
from typing import List, Dict, Any, Tuple

# Try to import cryptography for optional per-user encryption
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet, InvalidToken
    import base64
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

# Optional PDF export
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

# ---------------------------
# App metadata
# ---------------------------
CREATOR_NAME = "Ejiofor Chinedu Francis"
APP_COPYRIGHT_YEAR = dt.datetime.now().year

# ---------------------------
# Config / Paths
# ---------------------------
st.set_page_config(page_title="MediLink – Health Access App", layout="wide")
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, "medilink_data")
os.makedirs(DATA_DIR, exist_ok=True)

USERS_FILE = os.path.join(DATA_DIR, "users.json")

# Legacy global file paths (used to migrate existing data into per-user files on first login)
PROFILES_FILE = os.path.join(DATA_DIR, "profiles.json")
CONTACTS_FILE = os.path.join(DATA_DIR, "contacts.json")
REMINDERS_FILE = os.path.join(DATA_DIR, "reminders.json")
LIBRARY_FILE = os.path.join(DATA_DIR, "library.json")

# ---------------------------
# Default data (used when new)
# ---------------------------
DEFAULT_CONTACTS = [
    {"name": "National Emergency (Nigeria)", "type": "Ambulance/Police/Fire", "phone": "+112", "whatsapp": "", "address": "Nationwide", "country": "Nigeria"},
]

DEFAULT_PROFILES = [
    {
        "id": "profile_default",
        "name": "Default",
        "age": None,
        "weight_kg": None,
        "blood_type": "",
        "allergies": "",
        "medications": [],
        "symptom_history": [],
    }
]

# Full default Health Library (kept from original)
DEFAULT_HEALTH_LIBRARY: Dict[str, Dict[str, Any]] = {
    "First Aid": {
        "Bleeding": {
            "summary": "Apply direct pressure, clean with water, cover with a dressing.",
            "symptoms": ["Bleeding", "Visible wound"],
            "causes": ["Cut, trauma, puncture"],
            "treatment": [
                "Wash hands or wear gloves.",
                "Apply firm direct pressure with clean cloth.",
                "Elevate the area if possible.",
                "Seek emergency care if bleeding is heavy or doesn't stop."
            ],
            "prevention": ["Use protective gloves", "Keep a first-aid kit accessible"],
            "tips": ["If an object is stuck, don't remove it — stabilize and seek care."],
            "is_custom": False
        },
        "Burns": {
            "summary": "Cool under running water for 10–20 minutes; cover with a clean dressing.",
            "symptoms": ["Redness", "Pain", "Blisters"],
            "causes": ["Heat, chemicals, electricity"],
            "treatment": ["Remove heat source", "Cool with running water (not ice)", "Cover with non-stick dressing"],
            "prevention": ["Keep hot liquids away from children", "Use protective gear"],
            "tips": ["Seek care for large, deep, or facial burns."],
            "is_custom": False
        }
    },
    "Infectious Diseases": {
        "Malaria": {
            "summary": "Parasitic infection transmitted by mosquitoes causing fever, chills and fatigue.",
            "symptoms": ["Fever", "Chills", "Headache", "Sweating", "Fatigue"],
            "causes": ["Plasmodium parasites via Anopheles mosquito bite"],
            "treatment": ["Seek testing (rapid test) and antimalarial medications as prescribed", "Hydration and rest"],
            "prevention": ["Use insecticide-treated bed nets", "Eliminate standing water", "Repellents"],
            "tips": ["If high fever + confusion or difficulty breathing, seek emergency care."],
            "is_custom": False
        },
        "Typhoid": {
            "summary": "Bacterial infection causing prolonged fever and abdominal pain.",
            "symptoms": ["Fever", "Abdominal pain", "Headache", "Diarrhea or constipation", "Loss of appetite"],
            "causes": ["Salmonella Typhi via contaminated food/water"],
            "treatment": ["See doctor for antibiotic therapy", "Hydration"],
            "prevention": ["Safe water, hand hygiene, cooked food"],
            "tips": ["Vaccination available in some settings."],
            "is_custom": False
        },
        "Dengue": {
            "summary": "Viral infection transmitted by Aedes mosquitoes causing fever and body pains.",
            "symptoms": ["Fever", "Severe headache", "Joint/muscle pain", "Rash", "Bleeding gums (in severe cases)"],
            "causes": ["Dengue virus via mosquito bite"],
            "treatment": ["Rest, fluids; seek medical care if warning signs (severe abdominal pain, vomiting, bleeding)"],
            "prevention": ["Avoid mosquito bites", "Remove standing water"],
            "tips": ["Avoid NSAIDs (e.g., ibuprofen) if dengue is suspected."],
            "is_custom": False
        },
        "COVID-19 (Respiratory infection)": {
            "summary": "Respiratory infection caused by SARS-CoV-2 with a range from mild to severe disease.",
            "symptoms": ["Fever", "Cough", "Sore throat", "Loss of smell/taste", "Difficulty breathing"],
            "causes": ["SARS-CoV-2 virus"],
            "treatment": ["Isolate, rest, fluids; seek testing and medical care if severe symptoms or high risk"],
            "prevention": ["Vaccination, mask in crowded spaces, hand hygiene"],
            "tips": ["Follow local public health guidance for testing and isolation."],
            "is_custom": False
        }
    },
    "Chronic Diseases": {
        "Diabetes": {
            "summary": "A condition where blood sugar is too high due to insulin problems.",
            "symptoms": ["Excessive thirst", "Frequent urination", "Fatigue", "Weight loss"],
            "causes": ["Type 1: autoimmune; Type 2: insulin resistance, lifestyle & genetic factors"],
            "treatment": ["Blood sugar monitoring, medications or insulin, healthy diet, exercise"],
            "prevention": ["Healthy weight, balanced diet, regular activity"],
            "tips": ["See a clinician for blood tests (fasting glucose, HbA1c)."],
            "is_custom": False
        },
        "Hypertension (High blood pressure)": {
            "summary": "Persistent elevation of blood pressure that increases heart disease risk.",
            "symptoms": ["Often none", "Headache (occasionally)"],
            "causes": ["Age, genetics, diet high in salt, obesity, inactivity"],
            "treatment": ["Lifestyle changes, antihypertensive medications as prescribed"],
            "prevention": ["Healthy diet, exercise, limit salt & alcohol"],
            "tips": ["Regular checks are important; silent condition for many."],
            "is_custom": False
        },
        "Asthma": {
            "summary": "Chronic lung condition causing wheeze, cough and breathing difficulty.",
            "symptoms": ["Wheeze", "Cough", "Shortness of breath", "Chest tightness"],
            "causes": ["Allergens, infections, exercise, irritants"],
            "treatment": ["Inhalers (relievers & preventers), avoid triggers, action plan"],
            "prevention": ["Avoid triggers, take preventer inhaler if prescribed"],
            "tips": ["Seek urgent help for severe breathing difficulties."],
            "is_custom": False
        }
    },
    "Mental Health": {
        "Stress": {
            "summary": "A normal response to pressure but may become harmful if persistent.",
            "symptoms": ["Irritability", "Sleep problems", "Difficulty concentrating", "Muscle tension"],
            "causes": ["Work, relationships, financial pressure"],
            "treatment": ["Routine, breaks, breathing exercises, talk therapy if needed"],
            "prevention": ["Healthy sleep, exercise, social support"],
            "tips": ["If thoughts of self-harm occur, seek immediate help."],
            "is_custom": False
        },
        "Anxiety (Mild to moderate)": {
            "summary": "Excessive worry that affects daily life.",
            "symptoms": ["Worry", "Restlessness", "Palpitations", "Sleep problems"],
            "causes": ["Stress, genetics, life changes"],
            "treatment": ["CBT, relaxation techniques, medication when needed"],
            "prevention": ["Mindfulness, structured routine"],
            "tips": ["See a mental health professional for persistent symptoms."],
            "is_custom": False
        }
    },
    "Nutrition & Wellness": {
        "Hydration & ORS": {
            "summary": "Keeping well-hydrated is essential; ORS prevents dehydration in diarrhoea.",
            "symptoms": ["Thirst", "Reduced urine", "Dizziness when dehydrated"],
            "causes": ["Heat, fever, diarrhoea, vomiting"],
            "treatment": ["Drink clean water, ORS for fluid losses", "Seek care for severe dehydration"],
            "prevention": ["Regular fluids, salt & sugar balance in heavy losses"],
            "tips": ["Give ORS to children with diarrhoea as per guidance."],
            "is_custom": False
        },
        "Healthy Plate": {
            "summary": "A simple way to portion meals: half vegetables, quarter protein, quarter whole grains.",
            "symptoms": [],
            "causes": [],
            "treatment": [],
            "prevention": ["Balanced diet prevents many chronic diseases"],
            "tips": ["Include pulses and fish; limit added sugars."],
            "is_custom": False
        }
    }
}

DEFAULT_REMINDERS: List[Dict[str,Any]] = []

# ---------------------------
# Country dialing codes (E.164-like) - FULL global list
# ---------------------------
COUNTRY_DIAL_CODES = {
    "Afghanistan": "+93",
    "Albania": "+355",
    "Algeria": "+213",
    "Andorra": "+376",
    "Angola": "+244",
    "Antigua and Barbuda": "+1268",
    "Argentina": "+54",
    "Armenia": "+374",
    "Aruba": "+297",
    "Australia": "+61",
    "Austria": "+43",
    "Azerbaijan": "+994",
    "Bahamas": "+1242",
    "Bahrain": "+973",
    "Bangladesh": "+880",
    "Barbados": "+1246",
    "Belarus": "+375",
    "Belgium": "+32",
    "Belize": "+501",
    "Benin": "+229",
    "Bhutan": "+975",
    "Bolivia": "+591",
    "Bosnia and Herzegovina": "+387",
    "Botswana": "+267",
    "Brazil": "+55",
    "Brunei": "+673",
    "Bulgaria": "+359",
    "Burkina Faso": "+226",
    "Burundi": "+257",
    "Cabo Verde": "+238",
    "Cambodia": "+855",
    "Cameroon": "+237",
    "Canada": "+1",
    "Central African Republic": "+236",
    "Chad": "+235",
    "Chile": "+56",
    "China": "+86",
    "Colombia": "+57",
    "Comoros": "+269",
    "Congo (Republic)": "+242",
    "Congo (Democratic Republic)": "+243",
    "Costa Rica": "+506",
    "Côte d'Ivoire": "+225",
    "Croatia": "+385",
    "Cuba": "+53",
    "Curaçao": "+599",
    "Cyprus": "+357",
    "Czechia": "+420",
    "Denmark": "+45",
    "Djibouti": "+253",
    "Dominica": "+1767",
    "Dominican Republic": "+1809",
    "Ecuador": "+593",
    "Egypt": "+20",
    "El Salvador": "+503",
    "Equatorial Guinea": "+240",
    "Eritrea": "+291",
    "Estonia": "+372",
    "Eswatini": "+268",
    "Ethiopia": "+251",
    "Fiji": "+679",
    "Finland": "+358",
    "France": "+33",
    "Gabon": "+241",
    "Gambia": "+220",
    "Georgia": "+995",
    "Germany": "+49",
    "Ghana": "+233",
    "Gibraltar": "+350",
    "Greece": "+30",
    "Greenland": "+299",
    "Grenada": "+1473",
    "Guatemala": "+502",
    "Guernsey": "+44",
    "Guinea": "+224",
    "Guinea-Bissau": "+245",
    "Guyana": "+592",
    "Haiti": "+509",
    "Honduras": "+504",
    "Hong Kong": "+852",
    "Hungary": "+36",
    "Iceland": "+354",
    "India": "+91",
    "Indonesia": "+62",
    "Iran": "+98",
    "Iraq": "+964",
    "Ireland": "+353",
    "Isle of Man": "+44",
    "Israel": "+972",
    "Italy": "+39",
    "Jamaica": "+1876",
    "Japan": "+81",
    "Jersey": "+44",
    "Jordan": "+962",
    "Kazakhstan": "+7",
    "Kenya": "+254",
    "Kiribati": "+686",
    "Kosovo": "+383",
    "Kuwait": "+965",
    "Kyrgyzstan": "+996",
    "Laos": "+856",
    "Latvia": "+371",
    "Lebanon": "+961",
    "Lesotho": "+266",
    "Liberia": "+231",
    "Libya": "+218",
    "Liechtenstein": "+423",
    "Lithuania": "+370",
    "Luxembourg": "+352",
    "Macau": "+853",
    "Madagascar": "+261",
    "Malawi": "+265",
    "Malaysia": "+60",
    "Maldives": "+960",
    "Mali": "+223",
    "Malta": "+356",
    "Marshall Islands": "+692",
    "Mauritania": "+222",
    "Mauritius": "+230",
    "Mexico": "+52",
    "Micronesia": "+691",
    "Moldova": "+373",
    "Monaco": "+377",
    "Mongolia": "+976",
    "Montenegro": "+382",
    "Morocco": "+212",
    "Mozambique": "+258",
    "Myanmar": "+95",
    "Namibia": "+264",
    "Nauru": "+674",
    "Nepal": "+977",
    "Netherlands": "+31",
    "New Caledonia": "+687",
    "New Zealand": "+64",
    "Nicaragua": "+505",
    "Niger": "+227",
    "Nigeria": "+234",
    "North Korea": "+850",
    "North Macedonia": "+389",
    "Norway": "+47",
    "Oman": "+968",
    "Pakistan": "+92",
    "Palau": "+680",
    "Panama": "+507",
    "Papua New Guinea": "+675",
    "Paraguay": "+595",
    "Peru": "+51",
    "Philippines": "+63",
    "Poland": "+48",
    "Portugal": "+351",
    "Puerto Rico": "+1",
    "Qatar": "+974",
    "Réunion": "+262",
    "Romania": "+40",
    "Russia": "+7",
    "Rwanda": "+250",
    "Saint Kitts and Nevis": "+1869",
    "Saint Lucia": "+1758",
    "Saint Vincent and the Grenadines": "+1784",
    "Samoa": "+685",
    "San Marino": "+378",
    "Sao Tome and Principe": "+239",
    "Saudi Arabia": "+966",
    "Senegal": "+221",
    "Serbia": "+381",
    "Seychelles": "+248",
    "Sierra Leone": "+232",
    "Singapore": "+65",
    "Sint Maarten": "+1721",
    "Slovakia": "+421",
    "Slovenia": "+386",
    "Solomon Islands": "+677",
    "Somalia": "+252",
    "South Africa": "+27",
    "South Korea": "+82",
    "South Sudan": "+211",
    "Spain": "+34",
    "Sri Lanka": "+94",
    "Sudan": "+249",
    "Suriname": "+597",
    "Sweden": "+46",
    "Switzerland": "+41",
    "Syria": "+963",
    "Taiwan": "+886",
    "Tajikistan": "+992",
    "Tanzania": "+255",
    "Thailand": "+66",
    "Timor-Leste": "+670",
    "Togo": "+228",
    "Tonga": "+676",
    "Trinidad and Tobago": "+1868",
    "Tunisia": "+216",
    "Turkey": "+90",
    "Turkmenistan": "+993",
    "Tuvalu": "+688",
    "Uganda": "+256",
    "Ukraine": "+380",
    "United Arab Emirates": "+971",
    "United Kingdom": "+44",
    "United States": "+1",
    "Uruguay": "+598",
    "Uzbekistan": "+998",
    "Vanuatu": "+678",
    "Vatican City": "+379",
    "Venezuela": "+58",
    "Vietnam": "+84",
    "Virgin Islands (U.S.)": "+1340",
    "Wallis and Futuna": "+681",
    "Yemen": "+967",
    "Zambia": "+260",
    "Zimbabwe": "+263"
}

# Build country list sorted. If Nigeria present, keep it default selection later.
COUNTRY_LIST = sorted(list(COUNTRY_DIAL_CODES.keys()))

# ---------------------------
# Crypto helpers (use for per-user Fernet if available)
# ---------------------------
def _b64_from_key(key_bytes: bytes) -> bytes:
    """Return URL-safe base64 key bytes for Fernet"""
    return base64.urlsafe_b64encode(key_bytes)

def derive_key_from_password(password: str, salt: bytes, iterations: int = 390000) -> bytes:
    """Derive a 32-byte key from password+salt using PBKDF2-HMAC-SHA256"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password.encode("utf-8"))
    return _b64_from_key(key)

def make_fernet(password: str, salt: bytes):
    key = derive_key_from_password(password, salt)
    return Fernet(key)

# ---------------------------
# Password hashing for login (PBKDF2-HMAC-SHA256)
# ---------------------------
PWD_ITERATIONS = 200_000
PWD_SALT_BYTES = 16
PWD_HASH_BYTES = 32

def hash_password_pbkdf2(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PWD_ITERATIONS, dklen=PWD_HASH_BYTES)
    return binascii.hexlify(dk).decode("ascii")

def verify_password_pbkdf2(password: str, salt_hex: str, hash_hex: str) -> bool:
    try:
        salt = binascii.unhexlify(salt_hex)
        expected = binascii.unhexlify(hash_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PWD_ITERATIONS, dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

# ---------------------------
# User store (users.json)
# ---------------------------
def load_users() -> Dict[str, Any]:
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_users(users: Dict[str, Any]):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)

# ---------------------------
# Per-user file helpers
# ---------------------------
def safe_username(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", name)

def user_file(name: str, username: str = None) -> str:
    user = username if username else st.session_state.get("user", "guest")
    safe_user = safe_username(user or "guest")
    return os.path.join(DATA_DIR, f"{safe_user}_{name}.json")

def read_json(path: str, fallback):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return fallback
    return fallback

def write_json(path: str, data: Any):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        st.error(f"Could not save file {os.path.basename(path)}: {e}")
        return False

# ---------------------------
# Secure read/write JSON (use per-user Fernet when available)
# ---------------------------
def secure_write_json(path: str, data: Any):
    """
    If encryption enabled and a per-user fernet is set in session, write encrypted bytes (path + '.enc').
    Otherwise write plain JSON to path.
    """
    fernet = st.session_state.get("fernet")
    if CRYPTO_AVAILABLE and fernet:
        try:
            raw = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
            token = fernet.encrypt(raw)
            with open(path + ".enc", "wb") as f:
                f.write(token)
            # remove plain file if exists
            if os.path.exists(path):
                try:
                    os.remove(path)
                except:
                    pass
            return True
        except Exception as e:
            st.error(f"Could not encrypt & save {os.path.basename(path)}: {e}")
            return False
    else:
        # Fallback - write plain JSON
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            # remove .enc if exists (to avoid confusion)
            if os.path.exists(path + ".enc"):
                try:
                    os.remove(path + ".enc")
                except:
                    pass
            return True
        except Exception as e:
            st.error(f"Could not save file {os.path.basename(path)}: {e}")
            return False

def secure_read_json(path: str, fallback):
    """
    If encrypted file exists (path + '.enc') and a per-user fernet is present, decrypt and return JSON.
    Else read plaintext JSON if present. If neither, return fallback.
    """
    enc_path = path + ".enc"
    # prefer encrypted file if available
    if os.path.exists(enc_path):
        if not CRYPTO_AVAILABLE:
            st.warning(f"Encrypted data found for {os.path.basename(path)} but 'cryptography' is not installed. Install it to decrypt.")
            return fallback
        fernet = st.session_state.get("fernet")
        if not fernet:
            # user hasn't unlocked their encryption (shouldn't happen after login)
            st.warning("Encrypted data found but no encryption key available for this session.")
            return fallback
        try:
            with open(enc_path, "rb") as f:
                token = f.read()
            raw = fernet.decrypt(token)
            return json.loads(raw.decode("utf-8"))
        except InvalidToken:
            st.warning("Could not decrypt stored data with the current session key (InvalidToken).")
            return fallback
        except Exception as e:
            st.error(f"Could not read encrypted data {os.path.basename(enc_path)}: {e}")
            return fallback
    else:
        # fallback to plaintext JSON if exists
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return fallback
        else:
            return fallback

# ---------------------------
# App data loaders/savers (per-user)
# ---------------------------
def load_profiles(username: str = None) -> List[Dict[str,Any]]:
    return secure_read_json(user_file("profiles", username), DEFAULT_PROFILES)

def save_profiles(profiles: List[Dict[str,Any]], username: str = None):
    return secure_write_json(user_file("profiles", username), profiles)

def load_contacts(username: str = None) -> List[Dict[str,str]]:
    return secure_read_json(user_file("contacts", username), DEFAULT_CONTACTS)

def save_contacts(contacts: List[Dict[str,str]], username: str = None):
    return secure_write_json(user_file("contacts", username), contacts)

def load_reminders(username: str = None) -> List[Dict[str,Any]]:
    return secure_read_json(user_file("reminders", username), DEFAULT_REMINDERS)

def save_reminders(rem: List[Dict[str,Any]], username: str = None):
    return secure_write_json(user_file("reminders", username), rem)

def load_library(username: str = None) -> Dict[str, Dict[str, Any]]:
    return secure_read_json(user_file("library", username), DEFAULT_HEALTH_LIBRARY)

def save_library(lib: Dict[str, Dict[str, Any]], username: str = None):
    return secure_write_json(user_file("library", username), lib)

# ---------------------------
# Migrate global files into per-user files (run on first login)
# ---------------------------
def migrate_global_to_user(username: str):
    try:
        # profiles
        dest = user_file("profiles", username)
        if not os.path.exists(dest) and os.path.exists(PROFILES_FILE):
            try:
                with open(PROFILES_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                write_json(dest, data)
            except Exception:
                pass
        # contacts
        dest = user_file("contacts", username)
        if not os.path.exists(dest) and os.path.exists(CONTACTS_FILE):
            try:
                with open(CONTACTS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                write_json(dest, data)
            except Exception:
                pass
        # reminders
        dest = user_file("reminders", username)
        if not os.path.exists(dest) and os.path.exists(REMINDERS_FILE):
            try:
                with open(REMINDERS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                write_json(dest, data)
            except Exception:
                pass
        # library
        dest = user_file("library", username)
        if not os.path.exists(dest) and os.path.exists(LIBRARY_FILE):
            try:
                with open(LIBRARY_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                write_json(dest, data)
            except Exception:
                pass
    except Exception:
        pass

# ---------------------------
# Phone / Message helpers
# ---------------------------
def normalize_phone_for_tel(num: str) -> str:
    num = (num or "").strip()
    if not num:
        return ""
    cleaned = re.sub(r"[^\d+]", "", num)
    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]
    return cleaned

def normalize_phone_for_whatsapp(num: str) -> str:
    digits = "".join(ch for ch in (num or "") if ch.isdigit())
    return digits

def add_country_code_if_missing(number: str, country: str) -> str:
    if not number:
        return ""
    s = number.strip()
    if s.startswith("+"):
        return s
    s_clean = re.sub(r"[^\d]", "", s)
    if s_clean.startswith("0"):
        s_clean = s_clean.lstrip("0")
    code = COUNTRY_DIAL_CODES.get(country)
    if not code:
        return "+" + s_clean
    code_digits = re.sub(r"[^\d\+]", "", code)
    return f"{code_digits}{s_clean}"

def google_maps_link(lat: str, lon: str) -> str:
    lat = (lat or "").strip()
    lon = (lon or "").strip()
    if not lat or not lon:
        return ""
    return f"https://maps.google.com/?q={urllib.parse.quote(lat)},{urllib.parse.quote(lon)}"

def build_message(user_msg: str, lat: str, lon: str) -> str:
    base = (user_msg or "").strip() or "Emergency! Please help."
    maps = google_maps_link(lat, lon)
    if maps:
        base += f"\nMy location: {maps}"
    return base

def whatsapp_link(phone: str, message: str) -> str:
    num = normalize_phone_for_whatsapp(phone)
    text = urllib.parse.quote(message or "")
    if not num:
        return ""
    return f"https://wa.me/{num}?text={text}"

def sms_link(phone: str, message: str) -> str:
    tel = normalize_phone_for_tel(phone)
    body = urllib.parse.quote(message or "")
    if not tel:
        return ""
    return f"sms:{tel}?&body={body}"

# ---------------------------
# Symptom Checker data & helpers (kept compact)
# ---------------------------
SYMPTOMS = [
    "fever", "headache", "chills", "vomiting", "diarrhea", "abdominal pain",
    "cough", "sore throat", "runny nose", "difficulty breathing",
    "chest pain", "fatigue", "loss of appetite", "joint pain",
    "rash", "dizziness", "high temperature (≥38°C)", "bloody stool",
    "shortness of breath", "sweating", "nausea", "weight loss", "night sweats",
    "persistent cough", "frequent urination", "excessive thirst", "stiffness", "swelling"
]

# Example CONDITIONS (you can reuse full mapping from earlier versions)
CONDITIONS = {
    "Malaria": {"weights": {"fever":3,"chills":2,"headache":2}, "advice":"See clinic","threshold":4},
    "Common Cold / Flu": {"weights": {"cough":1,"sore throat":2}, "advice":"Rest & fluids","threshold":2},
    "Heart Attack (EMERGENCY)": {"weights": {"chest pain":4,"shortness of breath":4}, "advice":"Call emergency services", "threshold":6}
}

def score_conditions_ranked(selected: List[str], top_n: int = 3) -> List[Dict[str,Any]]:
    sel = set(s.strip().lower() for s in selected if s)
    results = []
    for cond, spec in CONDITIONS.items():
        weights = spec.get("weights", {})
        max_possible = sum(weights.values()) if weights else 0
        score = 0
        for symptom, w in weights.items():
            if symptom.lower() in sel:
                score += w
            else:
                if symptom.lower() == "shortness of breath" and "difficulty breathing" in sel:
                    score += w
        percent = int((score / max_possible * 100)) if max_possible else 0
        results.append({"condition": cond, "score": score, "percent": percent, "advice": spec.get("advice",""), "threshold": spec.get("threshold",0)})
    results.sort(key=lambda x: (x["score"], x["percent"]), reverse=True)
    return results[:top_n]

# ---------------------------
# Health Library search helpers
# ---------------------------
def search_library(lib: Dict[str, Dict[str, Any]], query: str = "", category: str = "All") -> List[Tuple[str,str,Dict[str,Any]]]:
    """
    Return list of (category, title, content) matching query and category filter.
    Search across title, summary, symptoms, causes, treatment, prevention, tips.
    """
    results = []
    q = (query or "").strip().lower()
    for cat, topics in lib.items():
        if category != "All" and cat != category:
            continue
        for title, content in topics.items():
            # combine searchable text
            blob = " ".join([
                title,
                content.get("summary",""),
                " ".join(content.get("symptoms",[])),
                " ".join(content.get("causes",[])),
                " ".join(content.get("treatment",[])),
                " ".join(content.get("prevention",[])),
                " ".join(content.get("tips",[]))
            ]).lower()
            if not q or q in blob:
                results.append((cat, title, content))
    # Sort custom entries to bottom and built-ins first, and alphabetically
    results.sort(key=lambda x: (x[2].get("is_custom", False), x[0].lower(), x[1].lower()))
    return results

def add_library_entry(lib: Dict[str, Dict[str, Any]], category: str, title: str, summary: str,
                      symptoms: List[str], causes: List[str], treatment: List[str],
                      prevention: List[str], tips: List[str]) -> Dict[str, Dict[str, Any]]:
    lib.setdefault(category, {})
    lib[category][title] = {
        "summary": summary,
        "symptoms": [s.strip() for s in symptoms if s.strip()],
        "causes": [c.strip() for c in causes if c.strip()],
        "treatment": [t.strip() for t in treatment if t.strip()],
        "prevention": [p.strip() for p in prevention if p.strip()],
        "tips": [t.strip() for t in tips if t.strip()],
        "is_custom": True
    }
    save_library(lib, st.session_state.get("user"))
    return lib

# ---------------------------
# UI & App State - Authentication (Sign Up / Login)
# ---------------------------
if "user" not in st.session_state:
    st.session_state.user = None
if "fernet" not in st.session_state:
    st.session_state.fernet = None

# Small helper to clear sensitive in-memory data
def logout_user():
    st.session_state.user = None
    st.session_state.fernet = None

# Helper safe rerun
def safe_rerun():
    try:
        rerun = getattr(st, "experimental_rerun", None)
        if callable(rerun):
            rerun()
        else:
            raise AttributeError
    except Exception:
        st.session_state._needs_refresh = True
        st.info("Please refresh the page (browser reload) to continue — automatic rerun is not available in this Streamlit version.")
        st.stop()

# If not logged in, show login/sign-up
if not st.session_state.user:
    st.title("🏥 MediLink — Login / Sign Up")
    st.write("Create an account to keep your MediLink data separate and optionally encrypted locally.")
    if CRYPTO_AVAILABLE:
        st.info("Optional local encryption is available (cryptography installed).")
    else:
        st.warning("Cryptography package is not installed. Data will be stored unencrypted unless you install 'cryptography'.")

    users = load_users()
    option = st.radio("Choose action", ["Login", "Sign Up"])

    if option == "Login":
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pw")
        if st.button("Login"):
            if not username or not password:
                st.error("Please enter username and password.")
            elif username not in users:
                st.error("User not found. Sign up first.")
            else:
                rec = users[username]
                if verify_password_pbkdf2(password, rec.get("salt",""), rec.get("password_hash","")):
                    # successful login
                    st.session_state.user = username
                    # initialize per-user fernet if possible
                    if CRYPTO_AVAILABLE:
                        try:
                            enc_salt_hex = rec.get("enc_salt")
                            if not enc_salt_hex:
                                # if user record missing enc_salt (older users), create one and save back
                                enc_salt = os.urandom(16)
                                rec["enc_salt"] = binascii.hexlify(enc_salt).decode("ascii")
                                save_users(users)
                            else:
                                enc_salt = binascii.unhexlify(enc_salt_hex)
                            st.session_state.fernet = make_fernet(password, enc_salt)
                        except Exception:
                            st.session_state.fernet = None
                            st.warning("Could not initialize encryption for your account.")
                    else:
                        st.session_state.fernet = None
                    # migrate global files to user-level if present
                    migrate_global_to_user(username)
                    st.success(f"Welcome back, {username}!")
                    safe_rerun()
                else:
                    st.error("Invalid username or password")

    elif option == "Sign Up":
        new_user = st.text_input("Choose a username", key="signup_user")
        new_pw = st.text_input("Choose a password", type="password", key="signup_pw")
        new_pw_confirm = st.text_input("Confirm password", type="password", key="signup_confirm")
        if st.button("Create Account"):
            if not new_user or not new_pw:
                st.error("Username and password required")
            elif new_user in users:
                st.error("Username already exists")
            elif new_pw != new_pw_confirm:
                st.error("Passwords do not match")
            else:
                # create user record
                pwd_salt = os.urandom(PWD_SALT_BYTES)
                pwd_hash = hash_password_pbkdf2(new_pw, pwd_salt)
                enc_salt = os.urandom(16)
                users[new_user] = {
                    "salt": binascii.hexlify(pwd_salt).decode("ascii"),
                    "password_hash": pwd_hash,
                    "enc_salt": binascii.hexlify(enc_salt).decode("ascii"),
                    "created_at": dt.datetime.utcnow().isoformat()
                }
                save_users(users)
                st.success("Account created! Now login using your new credentials.")
    st.stop()  # stop the rest of app until user logs in

# If we reach here, user is logged in
st.sidebar.markdown("### Account")
st.sidebar.markdown(f"**{st.session_state.user}**")
if st.sidebar.button("🔓 Logout"):
    logout_user()
    st.sidebar.success("Logged out. Reloading...")
    safe_rerun()

st.sidebar.markdown("---")
if REPORTLAB_AVAILABLE:
    st.sidebar.write("PDF export available")
else:
    st.sidebar.write("Install 'reportlab' for PDF export")

# If per-user fernet is present we will use it when saving/loading (secure_read_json / secure_write_json use st.session_state['fernet'])

# ---------------------------
# Navigation (include Health Library)
# ---------------------------
menu = st.sidebar.radio("Navigation", ["Home", "Profiles", "Health Library", "Symptom Checker", "Medication", "Emergency", "About"])

# Keep a small session-state slot to pre-fill symptom checker from library
if "symptom_prefill" not in st.session_state:
    st.session_state.symptom_prefill = []

st.title("🏥 MediLink (Full Health Library & Features)")

# ---------------- Home ----------------
if menu == "Home":
    st.subheader("Welcome 👋")
    today = dt.datetime.now()
    st.write(f"**Date:** {today.strftime('%A, %B %d, %Y')}")
    tip = random.choice([
        "Drink clean water", "Sleep 7–9 hours", "Wash hands regularly", "Exercise 30 minutes"
    ])
    st.info(tip)
    st.markdown("---")
    profiles = load_profiles(st.session_state.user)
    st.write("Profiles available:")
    for p in profiles:
        st.write(f"- {p['name']} (id: {p['id']})")
    st.caption("Use the Profiles page to manage family members. Health Library contains detailed, actionable entries.")

# ---------------- Profiles ----------------
elif menu == "Profiles":
    st.subheader("👨‍👩‍👧 Manage Profiles")
    profiles = load_profiles(st.session_state.user)
    with st.expander("➕ Create new profile"):
        new_name = st.text_input("Name for profile", key="new_profile_name")
        if st.button("Create profile"):
            if not new_name.strip():
                st.error("Give the profile a name.")
            else:
                new_id = f"profile_{int(dt.datetime.now().timestamp())}"
                profiles.append({
                    "id": new_id, "name": new_name.strip(), "age": None, "weight_kg": None,
                    "blood_type": "", "allergies": "", "medications": [], "symptom_history": []
                })
                save_profiles(profiles, st.session_state.user)
                st.success(f"Created profile {new_name.strip()}")
                safe_rerun()
    if profiles:
        names = [p["name"] for p in profiles]
        sel = st.selectbox("Select profile to view/edit", names)
        active = next((p for p in profiles if p["name"] == sel), profiles[0])
        st.markdown(f"### {active['name']}")
        col1, col2, col3 = st.columns(3)
        with col1:
            active["age"] = st.number_input("Age", min_value=0, max_value=150, value=active.get("age") or 0)
        with col2:
            active["weight_kg"] = st.number_input("Weight (kg)", min_value=0.0, max_value=500.0, value=active.get("weight_kg") or 0.0)
        with col3:
            active["blood_type"] = st.text_input("Blood type", value=active.get("blood_type",""))
        active["allergies"] = st.text_input("Allergies (comma separated)", value=active.get("allergies",""))
        if st.button("Save profile changes"):
            save_profiles(profiles, st.session_state.user)
            st.success("Saved.")
        if st.button("Delete this profile"):
            if len(profiles) <= 1:
                st.error("Cannot delete the last profile.")
            else:
                profiles = [p for p in profiles if p["id"] != active["id"]]
                save_profiles(profiles, st.session_state.user)
                st.success("Profile deleted.")
                safe_rerun()
        st.markdown("Recent symptom checks:")
        for entry in reversed(active.get("symptom_history", [])[-10:]):
            ts = entry.get("timestamp","")
            try:
                ts = dt.datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M")
            except:
                pass
            st.write(f"- {ts}: {', '.join(entry.get('symptoms',[]))} → {entry.get('results_summary','')}")
    else:
        st.info("No profiles exist. Create one above.")

# ---------------- Health Library ----------------
elif menu == "Health Library":
    st.subheader("📚 Health Library")
    st.caption("Comprehensive, searchable, categorized health content. Built-in entries are read-only; you can add custom entries below.")

    library = load_library(st.session_state.user)
    categories = ["All"] + sorted(library.keys())
    q = st.text_input("Search library (keywords match title, symptoms, causes, treatment, prevention, tips)", value="", key="lib_search")
    cat_choice = st.selectbox("Category", categories, index=0)
    matches = search_library(library, q, cat_choice)

    colL, colR = st.columns([2,1])
    with colL:
        if not matches:
            st.info("No matches. Try a different term or check categories.")
        else:
            st.markdown(f"### {len(matches)} results")
            for (cat, title, content) in matches:
                with st.expander(f"{title} — *{cat}*"):
                    st.markdown(f"**Summary:** {content.get('summary','')}")
                    if content.get("symptoms"):
                        st.markdown("**Common Symptoms:**")
                        st.write(", ".join(content.get("symptoms",[])))
                    if content.get("causes"):
                        st.markdown("**Causes:**")
                        for c in content.get("causes", []):
                            st.write(f"- {c}")
                    if content.get("treatment"):
                        st.markdown("**Treatment / What to do:**")
                        for t in content.get("treatment", []):
                            st.write(f"- {t}")
                    if content.get("prevention"):
                        st.markdown("**Prevention:**")
                        for p in content.get("prevention", []):
                            st.write(f"- {p}")
                    if content.get("tips"):
                        st.markdown("**Tips:**")
                        for t in content.get("tips", []):
                            st.write(f"- {t}")
                    st.write("")
                    # buttons: prefill symptom checker with symptoms, edit/delete if custom
                    btn_col1, btn_col2, btn_col3 = st.columns(3)
                    with btn_col1:
                        if st.button("Use symptoms in Checker", key=f"use_{cat}_{title}"):
                            st.session_state.symptom_prefill = [s.lower() for s in content.get("symptoms",[])]
                            st.success("Prefilled symptom checker with this entry's symptoms. Go to Symptom Checker page and click Analyze.")
                    with btn_col2:
                        if content.get("is_custom", False):
                            if st.button("Edit entry", key=f"edit_{cat}_{title}"):
                                st.session_state._edit_entry = {"category": cat, "title": title}
                                safe_rerun()
                    with btn_col3:
                        if content.get("is_custom", False):
                            # simple confirmation using checkbox approach
                            key_del = f"del_confirm_{cat}_{title}"
                            if key_del not in st.session_state:
                                st.session_state[key_del] = False
                            if st.button("Delete entry", key=f"del_{cat}_{title}"):
                                st.session_state[key_del] = True
                            if st.session_state.get(key_del):
                                # perform delete
                                del library[cat][title]
                                if not library[cat]:
                                    del library[cat]
                                save_library(library, st.session_state.user)
                                st.success("Deleted custom entry.")
                                safe_rerun()

    with colR:
        st.markdown("### Add custom entry")
        with st.form("add_entry_form"):
            a_cat = st.text_input("Category (e.g., 'Infectious Diseases')", value="", help="Choose an existing category or create a new one")
            a_title = st.text_input("Title (e.g., 'Cholera')", value="")
            a_summary = st.text_area("Short summary", value="", height=80)
            a_symptoms = st.text_area("Symptoms (comma separated)", value="")
            a_causes = st.text_area("Causes (comma separated)", value="")
            a_treatment = st.text_area("Treatment steps (one per line)", value="")
            a_prevention = st.text_area("Prevention steps (one per line)", value="")
            a_tips = st.text_area("Short tips (one per line)", value="")
            submitted = st.form_submit_button("Add custom entry")
            if submitted:
                if not a_cat.strip() or not a_title.strip():
                    st.error("Category and Title are required.")
                else:
                    symptoms_list = [s.strip() for s in a_symptoms.split(",") if s.strip()]
                    causes_list = [c.strip() for c in a_causes.split(",") if c.strip()]
                    treatment_list = [t.strip() for t in a_treatment.splitlines() if t.strip()]
                    prevention_list = [p.strip() for p in a_prevention.splitlines() if p.strip()]
                    tips_list = [t.strip() for t in a_tips.splitlines() if t.strip()]
                    library = add_library_entry(library, a_cat.strip(), a_title.strip(), a_summary.strip(),
                                                symptoms_list, causes_list, treatment_list, prevention_list, tips_list)
                    save_library(library, st.session_state.user)
                    st.success("Custom entry added.")
                    safe_rerun()

    # If user clicked edit earlier, show edit form
    if st.session_state.get("_edit_entry"):
        e = st.session_state["_edit_entry"]
        ccat = e["category"]
        ctitle = e["title"]
        content = library.get(ccat, {}).get(ctitle)
        if content:
            st.markdown("---")
            st.subheader(f"Edit custom entry: {ctitle} ({ccat})")
            with st.form("edit_entry_form"):
                e_summary = st.text_area("Summary", value=content.get("summary",""))
                e_symptoms = st.text_area("Symptoms (comma separated)", value=", ".join(content.get("symptoms",[])))
                e_causes = st.text_area("Causes (comma separated)", value=", ".join(content.get("causes",[])))
                e_treatment = st.text_area("Treatment (one per line)", value="\n".join(content.get("treatment",[])))
                e_prevention = st.text_area("Prevention (one per line)", value="\n".join(content.get("prevention",[])))
                e_tips = st.text_area("Tips (one per line)", value="\n".join(content.get("tips",[])))
                if st.form_submit_button("Save changes"):
                    library[ccat][ctitle] = {
                        "summary": e_summary.strip(),
                        "symptoms": [s.strip() for s in e_symptoms.split(",") if s.strip()],
                        "causes": [c.strip() for c in e_causes.split(",") if c.strip()],
                        "treatment": [t.strip() for t in e_treatment.splitlines() if t.strip()],
                        "prevention": [p.strip() for p in e_prevention.splitlines() if p.strip()],
                        "tips": [t.strip() for t in e_tips.splitlines() if t.strip()],
                        "is_custom": True
                    }
                    save_library(library, st.session_state.user)
                    st.success("Saved changes.")
                    del st.session_state["_edit_entry"]
                    safe_rerun()
            if st.button("Cancel edit"):
                del st.session_state["_edit_entry"]
                safe_rerun()

# ---------------- Symptom Checker ----------------
elif menu == "Symptom Checker":
    st.subheader("🩺 Symptom Checker")
    st.caption("Type symptoms comma-separated or pick from list (not a diagnosis).")
    # pre-fill from library if available
    prefill = st.session_state.get("symptom_prefill", [])
    selected = st.multiselect("Pick symptoms", SYMPTOMS, default=prefill)
    typed = st.text_input("Or type symptoms (comma separated)")
    if typed:
        selected = [s.strip().lower() for s in typed.split(",") if s.strip()]
    if st.button("Analyze"):
        if not selected:
            st.warning("Please provide symptoms.")
        else:
            results = score_conditions_ranked(selected, top_n=5)
            # attach to selected profile's history (choose profile)
            profiles = load_profiles(st.session_state.user)
            if profiles:
                # show selection UI to choose which profile to save into
                names = [p["name"] for p in profiles]
                profile_choice = st.selectbox("Save this check under which profile?", names)
                active = next((p for p in profiles if p["name"] == profile_choice), profiles[0])
                active.setdefault("symptom_history",[]).append({
                    "timestamp": dt.datetime.now().isoformat(),
                    "symptoms": selected,
                    "results_summary": "; ".join([f"{r['condition']}({r['percent']}%)" for r in results]),
                    "full_results": results
                })
                save_profiles(profiles, st.session_state.user)
            # show red flags (simple checks)
            selset = set(s.lower() for s in selected)
            if "chest pain" in selset and ("difficulty breathing" in selset or "shortness of breath" in selset):
                st.error("🚨 Chest pain + breathing difficulty — seek emergency care now.")
            st.markdown("### Top matches")
            for r in results:
                with st.expander(f"{r['condition']} — {r['percent']}%"):
                    st.write(r.get("advice",""))

# ---------------- Medication ----------------
elif menu == "Medication":
    st.subheader("💊 Medication Management")
    profiles = load_profiles(st.session_state.user)
    if not profiles:
        st.error("Create a profile first.")
    else:
        names = [p["name"] for p in profiles]
        sel = st.selectbox("Select profile", names)
        active = next((p for p in profiles if p["name"] == sel), profiles[0])
        st.markdown(f"Medications for **{active['name']}**")
        with st.expander("➕ Add medication"):
            med_name = st.text_input("Medicine name", key="add_med_name")
            med_dose = st.text_input("Dosage instructions", key="add_med_dose")
            med_time = st.time_input("Default time (optional)", key="add_med_time")
            pills = st.number_input("Total pills in stock", min_value=0, step=1, key="add_med_pills")
            refill_thresh = st.number_input("Refill threshold", min_value=0, step=1, value=3, key="add_med_refill")
            if st.button("Add medication"):
                if not med_name.strip():
                    st.error("Name required")
                else:
                    med_entry = {"id": f"m{int(dt.datetime.now().timestamp())}", "name": med_name.strip(), "dosage": med_dose.strip(), "time": med_time.strftime("%H:%M"), "pills_left": int(pills), "refill_threshold": int(refill_thresh), "history": []}
                    active.setdefault("medications", []).append(med_entry)
                    save_profiles(profiles, st.session_state.user)
                    st.success("Added medication")
                    safe_rerun()
        meds = active.get("medications", [])
        if meds:
            for m in meds:
                st.markdown(f"**{m['name']}** — {m.get('dosage','')}")
                st.write(f"Pills left: {m.get('pills_left',0)} | Refill at: {m.get('refill_threshold',0)}")
                c1, c2, c3 = st.columns([1,1,2])
                with c1:
                    if st.button("Mark Taken", key=f"take_{m['id']}"):
                        m.setdefault("history",[]).append(dt.datetime.now().isoformat())
                        if isinstance(m.get("pills_left"), int) and m["pills_left"]>0:
                            m["pills_left"] -= 1
                        save_profiles(profiles, st.session_state.user)
                        st.success("Marked as taken")
                        safe_rerun()
                with c2:
                    if st.button("Refill +5", key=f"refill_{m['id']}"):
                        m["pills_left"] = int(m.get("pills_left",0)) + 5
                        save_profiles(profiles, st.session_state.user)
                        st.success("Refilled 5 pills")
                        safe_rerun()
                with c3:
                    if st.button("Show history", key=f"hist_{m['id']}"):
                        if m.get("history"):
                            for hh in reversed(m["history"][-10:]):
                                try:
                                    ts = dt.datetime.fromisoformat(hh).strftime("%Y-%m-%d %H:%M")
                                except:
                                    ts = hh
                                st.write(f"- {ts}")
                        else:
                            st.info("No history yet.")
                if isinstance(m.get("pills_left"), int) and m["pills_left"] <= m.get("refill_threshold",0):
                    st.warning("🔔 Low pills — consider refill soon.")
            if st.button("Export meds to PDF"):
                if not REPORTLAB_AVAILABLE:
                    st.error("Install reportlab to enable PDF export.")
                else:
                    try:
                        pdf_path = os.path.join(DATA_DIR, f"{st.session_state.user}_meds_{active['id']}.pdf")
                        c = canvas.Canvas(pdf_path, pagesize=A4)
                        c.setFont("Helvetica-Bold", 12)
                        c.drawString(40, 800, f"MediLink Medication Report for {active['name']}")
                        y = 780
                        c.setFont("Helvetica", 10)
                        for m in meds:
                            if y < 60:
                                c.showPage()
                                y = 800
                            c.drawString(40, y, f"- {m['name']}: {m.get('dosage','')} | Pills left: {m.get('pills_left',0)}")
                            y -= 18
                        c.save()
                        st.success(f"Saved PDF: {pdf_path}")
                        st.markdown(f"[Download PDF]({pdf_path})")
                    except Exception as e:
                        st.error(f"PDF export failed: {e}")
        else:
            st.info("No medications yet.")

# ---------------- Emergency ----------------
elif menu == "Emergency":
    st.subheader("🚨 Emergency Contacts")
    contacts = load_contacts(st.session_state.user)
    with st.expander("➕ Add Contact"):
        name = st.text_input("Name", key="e_name")
        ctype = st.selectbox("Type", ["Hospital","Police","Ambulance/EMS","Fire Service","Other"], key="e_type")
        country_index = COUNTRY_LIST.index("Nigeria") if "Nigeria" in COUNTRY_LIST else 0
        country = st.selectbox("Country (for dialing code)", COUNTRY_LIST, index=country_index)
        phone = st.text_input("Phone (local or international). If local, country code will be prefixed.", placeholder="e.g., 8012345678 or +2348012345678", key="e_phone")
        whatsapp = st.text_input("WhatsApp (local or international). If local, country code will be prefixed.", placeholder="e.g., 8012345678 or +2348012345678", key="e_wa")
        address = st.text_input("Address", key="e_addr")
        if st.button("Save contact"):
            if not name.strip() or not phone.strip():
                st.error("Name and phone required.")
            else:
                phone_full = add_country_code_if_missing(phone, country)
                wa_full = add_country_code_if_missing(whatsapp, country) if whatsapp.strip() else ""
                phone_norm = normalize_phone_for_tel(phone_full)
                wa_norm = normalize_phone_for_whatsapp(wa_full)
                contacts.append({"name": name.strip(), "type": ctype, "phone": phone_norm, "whatsapp": wa_norm, "address": address.strip(), "country": country})
                save_contacts(contacts, st.session_state.user)
                st.success("Saved contact")
                safe_rerun()
    if contacts:
        for i,c in enumerate(contacts):
            st.markdown(f"**{c['name']}** — {c['type']}")
            if c.get("address"):
                st.caption(c["address"])
            tel = normalize_phone_for_tel(c.get("phone",""))
            display_phone = c.get("phone","")
            st.markdown(f"[📞 Call](tel:{tel})  |  `{display_phone}`")
            if c.get("whatsapp"):
                wa = normalize_phone_for_whatsapp(c.get("whatsapp",""))
                st.markdown(f"[🟢 WhatsApp](https://wa.me/{wa})")
            if st.button("Remove", key=f"rmc_{i}"):
                del contacts[i]
                save_contacts(contacts, st.session_state.user)
                safe_rerun()
    else:
        st.info("No emergency contacts yet.")

# ---------------- About ----------------
elif menu == "About":
    st.subheader("About MediLink")
    st.write("MediLink is an offline-first health assistant MVP. Profiles, contacts, reminders and the Health Library can be stored per-user and optionally encrypted locally when 'cryptography' is installed.")
    st.write("Health Library entries are searchable. Built-in content is educational and not a substitute for professional medical advice.")
    st.markdown("---")
    st.write(f"**Created by:** {CREATOR_NAME}")
    st.write(f"© {APP_COPYRIGHT_YEAR} {CREATOR_NAME}")

else:
    st.info("Select a page from the sidebar.")
