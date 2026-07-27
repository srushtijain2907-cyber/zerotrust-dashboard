

import os, json, threading, time
from datetime import datetime, timezone
from flask import Flask, render_template, jsonify, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

# Add project root to path
import sys
sys.path.insert(0, os.path.dirname(__file__))

from modules.aws_collector import collect_aws_logs
from modules.azure_collector import collect_azure_logs
from modules.gcp_collector import collect_gcp_logs
from modules.ml_engine import EnsembleDetector
from config import *

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ── Simple auth ────────────────────────────────────────────────────────────
USERS = {
    "admin":    generate_password_hash("ZeroTrust@2026"),
    "srushti":  generate_password_hash("srushti123"),
    "ridam":    generate_password_hash("ridam123"),
    "vishwajeet": generate_password_hash("vishwajeet123"),
}

# ── Global state ───────────────────────────────────────────────────────────
detector = EnsembleDetector()
processed_events = []
last_refresh = None
refresh_lock = threading.Lock()


def collect_and_process():
    """Collect from all clouds, run ML, store results."""
    global processed_events, last_refresh
    with refresh_lock:
        all_events = []
        all_events += collect_aws_logs()
        all_events += collect_azure_logs()
        all_events += collect_gcp_logs()

        if len(all_events) >= 10 and not detector.is_trained:
            detector.train(all_events)

        if all_events:
            results = detector.predict(all_events)
            processed_events = sorted(
                results, key=lambda x: x.get("severity", 0), reverse=True
            )
        last_refresh = datetime.now(timezone.utc).isoformat()
        print(f"[App] Processed {len(processed_events)} events at {last_refresh}")


def background_refresh():
    """Background thread: refresh logs every 30 seconds."""
    while True:
        try:
            collect_and_process()
        except Exception as e:
            print(f"[Background] Error: {e}")
        time.sleep(LOG_REFRESH_SECONDS)


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ── Auth routes ────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        stored = USERS.get(username)
        if stored and check_password_hash(stored, password):
            session["user"] = username
            return redirect(url_for("dashboard"))
        error = "Invalid username or password"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


# ── Dashboard ──────────────────────────────────────────────────────────────
@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", user=session.get("user"))


# ── API routes ─────────────────────────────────────────────────────────────
@app.route("/api/summary")
@login_required
def api_summary():
    events = processed_events
    total = len(events)
    anomalies = sum(1 for e in events if e.get("is_anomaly"))
    by_cloud = {"AWS": 0, "Azure": 0, "GCP": 0}
    by_decision = {"ALLOW": 0, "MFA REQUIRED": 0, "BLOCK": 0, "CRITICAL BLOCK": 0}
    critical = []

    for e in events:
        c = e.get("cloud", "AWS")
        if c in by_cloud:
            by_cloud[c] += 1
        d = e.get("decision", "ALLOW")
        if d in by_decision:
            by_decision[d] += 1
        if e.get("severity", 0) >= 2:
            critical.append({
                "user":       e.get("user", "unknown"),
                "action":     e.get("action", ""),
                "cloud":      e.get("cloud", ""),
                "trust_score": e.get("trust_score", 0),
                "decision":   e.get("decision", ""),
                "timestamp":  e.get("timestamp", ""),
                "ip_address": e.get("ip_address", ""),
                "country":    e.get("country", ""),
            })

    avg_trust = (
        round(sum(e.get("trust_score", 0) for e in events) / total, 3)
        if total > 0 else 0
    )

    return jsonify({
        "total_events":    total,
        "anomalies":       anomalies,
        "by_cloud":        by_cloud,
        "by_decision":     by_decision,
        "avg_trust_score": avg_trust,
        "critical_events": critical[:20],
        "last_refresh":    last_refresh,
        "model_trained":   detector.is_trained,
    })


@app.route("/api/events")
@login_required
def api_events():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    cloud_filter = request.args.get("cloud", "all")
    decision_filter = request.args.get("decision", "all")

    events = processed_events
    if cloud_filter != "all":
        events = [e for e in events if e.get("cloud") == cloud_filter]
    if decision_filter != "all":
        events = [e for e in events if e.get("decision") == decision_filter]

    total = len(events)
    start = (page - 1) * per_page
    end = start + per_page
    page_events = events[start:end]

    # Remove raw field for response size
    clean = []
    for e in page_events:
        clean.append({k: v for k, v in e.items() if k != "raw"})

    return jsonify({"events": clean, "total": total, "page": page, "per_page": per_page})


@app.route("/api/refresh", methods=["POST"])
@login_required
def api_refresh():
    thread = threading.Thread(target=collect_and_process, daemon=True)
    thread.start()
    return jsonify({"status": "refresh_started"})


@app.route("/api/trust_score_chart")
@login_required
def api_trust_chart():
    """Return last 50 trust scores for chart rendering."""
    events = processed_events[-50:]
    return jsonify([{
        "timestamp": e.get("timestamp", ""),
        "trust_score": e.get("trust_score", 0),
        "decision": e.get("decision", "ALLOW"),
        "user": e.get("user", ""),
        "cloud": e.get("cloud", ""),
    } for e in events])


@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "events": len(processed_events)})


if __name__ == "__main__":
    os.makedirs("models", exist_ok=True)
    # Initial load in background
    t = threading.Thread(target=collect_and_process, daemon=True)
    t.start()
    # Start background refresh
    bg = threading.Thread(target=background_refresh, daemon=True)
    bg.start()
    print(f"\n{'='*60}")
    print("  Zero Trust Multi-Cloud Security Dashboard")
    print(f"  Running at: http://localhost:{DASHBOARD_PORT}")
    print(f"  Login: admin / ZeroTrust@2026")
    print(f"{'='*60}\n")
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False)
