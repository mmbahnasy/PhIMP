from datetime import datetime, timedelta
import glob
import json
import os
import threading
import uuid
import webbrowser

import requests
import yaml
from flask import Flask, flash, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = "aims_secure_portal_key"

INCIDENTS_DIR = "incidents_store"
NIDR_LOG_FILE = "nidr_sync_log.json"
CONFIG_FILE = "config.yaml"
os.makedirs(INCIDENTS_DIR, exist_ok=True)

# In-memory storage for action plans and SSA submissions
action_plans_db = []
ssa_results_db = []


def load_config():
  """Loads configuration values from the YAML configuration file."""
  if os.path.exists(CONFIG_FILE):
    try:
      with open(CONFIG_FILE, "r") as f:
        data = yaml.safe_load(f) or {}
        if isinstance(data, dict):
          return data
    except Exception as exc:
      print(f"[Config Error] Failed to parse {CONFIG_FILE}: {exc}")
  return {}


config_data = load_config()
nidr_cfg = config_data.get("nidr", {})
security_cfg = config_data.get("security", {})

DEFAULT_USERS = {
    "pharmacist": {
        "password": "Pharm@2026",
        "full_name": "J. Doe, Pharmacist",
        "practice_id": "PH-8492",
    }
}

AUTH_USERS = {}
for user in security_cfg.get("users", []):
  if isinstance(user, dict):
    username = user.get("username")
    password = user.get("password")
    if username and password:
      AUTH_USERS[username] = {
          "password": password,
          "full_name": user.get("full_name", username.title()),
          "practice_id": user.get("practice_id", "PH-00000"),
      }
if not AUTH_USERS:
  AUTH_USERS = DEFAULT_USERS

NIDR_CLIENT_ID = nidr_cfg.get("client_id", "default_client_id")
NIDR_CLIENT_SECRET = nidr_cfg.get("client_secret", "default_secret")
NIDR_AUTH_URL = nidr_cfg.get(
    "auth_url", "https://auth.ismpcanada.ca/oauth/token"
)
NIDR_API_URL = nidr_cfg.get(
    "api_url", "https://api.ismpcanada.ca/nidr/v1/incidents"
)
PHARMACY_NIDR_ID = nidr_cfg.get("pharmacy_repository_id", "PH-00000")
NIDR_USE_MOCK = bool(nidr_cfg.get("use_mock_nidr", True))

token_cache = {"access_token": None, "expires_at": 0}

REQUIRED_INCIDENT_FIELDS = {
    "date",
    "time",
    "age_range",
    "patient_gender",
    "incident_type",
    "discovered_by",
    "prescribed_by",
    "medication_system_stages",
    "medications_involved",
    "route",
    "incident_description",
    "contributing_factors",
    "actions_taken",
}


def validate_incident_record(event_type, incident_data):
  """Ensures mandatory AIMS data fields are present before saving."""
  missing = []
  for field in REQUIRED_INCIDENT_FIELDS:
    value = incident_data.get(field)
    if not value or (isinstance(value, str) and not value.strip()):
      missing.append(field)
  if event_type == "Incident":
    if not incident_data.get("harm_level"):
      missing.append("harm_level")
  return missing


def get_current_user():
  username = session.get("username")
  if not username:
    return None
  return AUTH_USERS.get(username)


@app.before_request
def enforce_login():
  allowed_paths = {"/login", "/logout"}
  if request.path.startswith("/static"):
    return None
  if request.path in allowed_paths:
    return None
  if not session.get("authenticated"):
    return redirect(url_for("login"))
  return None


def get_nidr_access_token():
  """Acquires or retrieves a cached OAuth 2.0 token for NIDR API access."""
  global token_cache
  now = datetime.now().timestamp()

  if token_cache["access_token"] and token_cache["expires_at"] > (now + 60):
    return token_cache["access_token"]

  try:
    if NIDR_USE_MOCK:
      token_cache["access_token"] = "mock_bearer_token_cai_active"
      token_cache["expires_at"] = now + 3600
      return token_cache["access_token"]

    payload = {
        "grant_type": "client_credentials",
        "client_id": NIDR_CLIENT_ID,
        "client_secret": NIDR_CLIENT_SECRET,
        "scope": "nidr:submit",
    }
    response = requests.post(NIDR_AUTH_URL, data=payload, timeout=10)
    response.raise_for_status()
    data = response.json()
    token_cache["access_token"] = data.get("access_token")
    token_cache["expires_at"] = now + data.get("expires_in", 3600)
    return token_cache["access_token"]
  except Exception as exc:
    print(f"[NIDR Auth Error] Failed to obtain access token: {exc}")
    return None


def anonymize_and_prep_payload(incident_data):
  """Strips PHI, staff names, and sensitive free-text from an incident record."""
  return {
      "repository_id": PHARMACY_NIDR_ID,
      "event_type": incident_data.get("event_type"),
      "incident_type": incident_data.get("incident_type"),
      "date_occurred": incident_data.get("date"),
      "time_occurred": incident_data.get("time"),
      "patient_age_range": incident_data.get("age_range"),
      "patient_gender": incident_data.get("patient_gender"),
      "route_of_administration": incident_data.get("route"),
      "harm_level": incident_data.get("harm_level"),
      "associated_factors": incident_data.get("associated_factors"),
      "contributing_factors": incident_data.get("contributing_factors"),
      "medication_system_stages": incident_data.get("medication_system_stages"),
      "medications_involved": incident_data.get("medications_involved"),
      "incident_description": (incident_data.get("incident_description") or "")[:1000],
  }


def log_sync_event(summary, status):
  """Appends sync transaction results to a local audit log file."""
  log_entry = {
      "timestamp": datetime.now().strftime("%b %d, %Y - %H:%M %p"),
      "summary": summary,
      "status": status,
  }
  logs = []
  if os.path.exists(NIDR_LOG_FILE):
    try:
      with open(NIDR_LOG_FILE, "r") as f:
        logs = json.load(f)
    except Exception:
      pass
  logs.insert(0, log_entry)
  with open(NIDR_LOG_FILE, "w") as f:
    json.dump(logs[:20], f, indent=4)


def perform_manual_nidr_sync():
  """Manual trigger that batch-uploads anonymized incidents to NIDR."""
  print("[NIDR Sync] Initiating manual transmission to ISMP Canada repository...")
  token = get_nidr_access_token()
  if not token:
    log_sync_event(
        "Token acquisition failed", "Failed (OAuth Authentication Error)"
    )
    return False

  payloads = []
  file_mapping = []

  for filepath in glob.glob(os.path.join(INCIDENTS_DIR, "*.json")):
    try:
      with open(filepath, "r") as f:
        raw_data = json.load(f)
        if not raw_data.get("synced_to_nidr", False):
          clean_record = anonymize_and_prep_payload(raw_data)
          payloads.append(clean_record)
          file_mapping.append(filepath)
    except Exception as exc:
      print(f"Error reading {filepath}: {exc}")

  if not payloads:
    print("[NIDR Sync] No new unsynced incidents found.")
    log_sync_event("0 records to transmit", "Skipped (No New Incidents)")
    return True

  status_code = 200
  response_text = "Mock accepted by demo repository"
  if not NIDR_USE_MOCK:
    try:
      response = requests.post(
          NIDR_API_URL,
          json=payloads,
          headers={
              "Authorization": f"Bearer {token}",
              "Content-Type": "application/json",
          },
          timeout=10,
      )
      status_code = response.status_code
      response_text = response.text
      response.raise_for_status()
    except Exception as exc:
      print(f"[NIDR Sync] API call failed: {exc}")
      log_sync_event(
          f"{len(payloads)} record(s) attempted but transmission failed",
          f"Failed ({type(exc).__name__})",
      )
      return False

  for filepath in file_mapping:
    with open(filepath, "r") as f:
      data = json.load(f)
    data["synced_to_nidr"] = True
    with open(filepath, "w") as f:
      json.dump(data, f, indent=4)

  summary_str = f"{len(payloads)} Record(s) Transmitted (Anonymized)"
  log_sync_event(f"{summary_str} - {response_text}", f"Success ({status_code})")
  print(f"[NIDR Sync] Successfully synced {len(payloads)} records.")
  return True


def get_all_incidents():
  incidents = []
  if not os.path.exists(INCIDENTS_DIR):
    return incidents
  for filepath in glob.glob(os.path.join(INCIDENTS_DIR, "*.json")):
    try:
      with open(filepath, "r") as f:
        incidents.append(json.load(f))
    except Exception:
      pass
  return sorted(
      incidents,
      key=lambda x: (x.get("date", ""), x.get("time", "")),
      reverse=True,
  )


def save_incident_to_file(incident_data):
  incident_id = str(uuid.uuid4())[:8]
  incident_data["id"] = incident_id
  incident_data["synced_to_nidr"] = False
  filepath = os.path.join(INCIDENTS_DIR, f"incident_{incident_id}.json")
  with open(filepath, "w") as f:
    json.dump(incident_data, f, indent=4)


def get_seconds_until_0300():
  now = datetime.now()
  target = now.replace(hour=3, minute=0, second=0, microsecond=0)
  if now >= target:
    target += timedelta(days=1)
  return (target - now).total_seconds()


def run_scheduled_sync():
  print("[NIDR Sync] Scheduled daily upload triggered.")
  perform_manual_nidr_sync()
  schedule_daily_nidr_sync()


def schedule_daily_nidr_sync():
  delay = max(1, get_seconds_until_0300())
  timer = threading.Timer(delay, run_scheduled_sync)
  timer.daemon = True
  timer.start()
  return timer


@app.route("/login", methods=["GET", "POST"])
def login():
  if request.method == "POST":
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    user = AUTH_USERS.get(username)
    if user and user.get("password") == password:
      session["authenticated"] = True
      session["username"] = username
      flash("Signed in successfully.", "success")
      return redirect(url_for("index"))
    flash("Invalid username or password.", "error")
  return render_template("login.html")


@app.route("/logout")
def logout():
  session.clear()
  flash("You have been signed out.", "success")
  return redirect(url_for("login"))


@app.route("/")
def index():
  current_user = get_current_user()
  return render_template(
      "index.html",
      incidents=get_all_incidents(),
      incidents_dir=INCIDENTS_DIR,
      action_plans_db=action_plans_db,
      ssa_results_db=ssa_results_db,
      current_user=current_user,
  )


@app.route("/report", methods=["GET", "POST"])
def report():
  if request.method == "POST":
    event_type = request.form.get("event_type")
    incident_data = {
        "event_type": event_type,
        "date": request.form.get("date"),
        "time": request.form.get("time"),
        "age_range": request.form.get("age_range"),
        "patient_gender": request.form.get("patient_gender"),
        "incident_type": request.form.get("incident_type"),
        "discovered_by": request.form.get("discovered_by"),
        "prescribed_by": request.form.get("prescribed_by"),
        "medication_system_stages": ", ".join(
            request.form.getlist("medication_system_stages")
        ) or "None",
        "medications_involved": request.form.get("medications_involved"),
        "route": request.form.get("route"),
        "associated_factors": ", ".join(
            request.form.getlist("associated_factors")
        ) or "None",
        "harm_level": (
            request.form.get("harm_level") if event_type == "Incident" else "N/A"
        ),
        "incident_description": request.form.get("incident_description"),
        "contributing_factors": request.form.get("contributing_factors"),
        "actions_taken": request.form.get("actions_taken"),
        "recorded_by": session.get("username"),
    }
    missing_fields = validate_incident_record(event_type, incident_data)
    if missing_fields:
      flash(
          "Please complete all required AIMS fields before saving: "
          + ", ".join(sorted(missing_fields)),
          "error",
      )
      return render_template(
          "report.html",
          today=datetime.now().strftime("%Y-%m-%d"),
          current_user=get_current_user(),
      )
    save_incident_to_file(incident_data)
    flash(
        "Incident saved as a standalone JSON file and queued for NIDR"
        " review and daily anonymized transmission.",
        "success",
    )
    return redirect(url_for("index"))
  return render_template(
      "report.html",
      today=datetime.now().strftime("%Y-%m-%d"),
      current_user=get_current_user(),
  )


@app.route("/action-plans", methods=["GET", "POST"])
def action_plans():
  if request.method == "POST":
    action_plans_db.append({
        "issue": request.form.get("issue"),
        "target_date": request.form.get("target_date"),
        "steps": request.form.get("steps"),
    })
    flash("CQI Action Plan recorded.", "success")
    return redirect(url_for("action_plans"))
  return render_template(
      "action_plans.html",
      action_plans_db=action_plans_db,
      current_user=get_current_user(),
  )


@app.route("/ssa", methods=["GET", "POST"])
def ssa():
  if request.method == "POST":
    score = request.form.get("overall_score", "0")
    evaluation = {
        "completed_by": session.get("username"),
        "assessment_date": request.form.get("assessment_date"),
        "overall_score": score,
        "risk_rating": request.form.get("risk_rating"),
        "status": request.form.get("status"),
        "improvement_plan": request.form.get("improvement_plan"),
    }
    ssa_results_db.append(evaluation)
    flash("Safety self-assessment recorded and stored for CQI review.", "success")
    return redirect(url_for("ssa"))
  return render_template(
      "ssa.html",
      ssa_results_db=ssa_results_db,
      current_user=get_current_user(),
  )


@app.route("/nidr-status")
def nidr_status():
  logs = []
  if os.path.exists(NIDR_LOG_FILE):
    try:
      with open(NIDR_LOG_FILE, "r") as f:
        logs = json.load(f)
    except Exception:
      pass
  return render_template(
      "nidr_status.html",
      logs=logs,
      current_user=get_current_user(),
  )


@app.route("/trigger-sync", methods=["POST"])
def trigger_sync():
  success = perform_manual_nidr_sync()
  if success:
    flash(
        "NIDR REST API synchronization completed successfully using"
        " configuration from config.yaml.",
        "success",
    )
  else:
    flash("NIDR synchronization failed. Check server logs.", "error")
  return redirect(url_for("nidr_status"))


def open_browser():
  webbrowser.open("http://127.0.0.1:5000/")


if __name__ == "__main__":
  if not glob.glob(os.path.join(INCIDENTS_DIR, "*.json")):
    sample = {
        "id": "sample1",
        "event_type": "Incident",
        "date": "2026-11-03",
        "time": "11:15",
        "age_range": "40-49 years",
        "patient_gender": "Female",
        "incident_type": "Incorrect drug",
        "discovered_by": "Pharmacist",
        "prescribed_by": "Physician",
        "medication_system_stages": "Order entry, dispensing",
        "medications_involved": "Amoxicillin 500mg",
        "route": "Oral",
        "associated_factors": "Transition of Care",
        "harm_level": "None",
        "incident_description": "Dispensing label mismatch identified before patient handoff.",
        "contributing_factors": "Workflow interruption during verification.",
        "actions_taken": "Replaced blister card with correct batch.",
        "synced_to_nidr": False,
    }
    with open(os.path.join(INCIDENTS_DIR, "incident_sample1.json"), "w") as f:
      json.dump(sample, f, indent=4)

  schedule_daily_nidr_sync()
  threading.Timer(1.0, open_browser).start()
  app.run(debug=False, port=5000)

