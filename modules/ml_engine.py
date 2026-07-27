"""
modules/ml_engine.py

Ensemble ML anomaly detection engine.
Three models as per Al-Shehari et al. (2023) IEEE Access methodology:
  1. Random Forest  — supervised baseline (Figure 1, Section III-B-1)
  2. XGBoost        — supervised baseline (Section III-B-1, Eq. 2)
  3. Isolation Forest — unsupervised anomaly detection (Section III-B-2, Eq. 5,6)

Isolation Forest contamination = 0.02 (Table 6: best accuracy=98%, F-score=99%)
"""

import numpy as np
import pandas as pd
import pickle
import os
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier
from config import (
    IF_CONTAMINATION, IF_N_ESTIMATORS, IF_RANDOM_STATE,
    ODD_HOUR_START, ODD_HOUR_END, HIGH_RISK_COUNTRIES,
    WEIGHT_USER_BEHAVIOR, WEIGHT_NETWORK, WEIGHT_DEVICE, WEIGHT_THREAT_HISTORY,
    THRESHOLD_ALLOW, THRESHOLD_MFA, THRESHOLD_BLOCK
)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models")


def extract_features(events: list[dict]) -> pd.DataFrame:
    """
    Convert raw log events into ML feature vectors.
    Feature engineering based on CERT r4.2 dataset attributes used in
    Al-Shehari et al. (2023): Vectors (logon, logoff, device, http),
    Timestamps, User IDs, Events, Targets.
    """
    rows = []
    for e in events:
        try:
            # Parse timestamp
            ts_str = e.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
            except Exception:
                ts = datetime.now()

            hour = ts.hour
            day_of_week = ts.weekday()  # 0=Mon, 6=Sun

            # Feature: is_odd_hour
            # Source: Jeong & Yang (2025), Table 2 Row ③, Page 8
            # "02:00–05:00 → very high risk time logins (score=0)"
            is_odd_hour = int(ODD_HOUR_START <= hour < ODD_HOUR_END)

            # Feature: is_weekend
            is_weekend = int(day_of_week >= 5)

            # Feature: is_high_risk_country
            # Source: Jeong & Yang (2025), Table 3 Row ④
            # "New country login (medium/high risk)" & threat intelligence feeds
            country = e.get("country", "Unknown")
            is_high_risk_country = int(country in HIGH_RISK_COUNTRIES)

            # Feature: action_risk score (0–9)
            action_risk = int(e.get("action_risk", 3))

            # Feature: is_denied (error_code present = access denied)
            error_code = e.get("error_code", "")
            is_denied = int(bool(error_code and error_code not in ["", "None"]))

            # Feature: cloud_encoded
            cloud_map = {"AWS": 0, "Azure": 1, "GCP": 2}
            cloud_encoded = cloud_map.get(e.get("cloud", "AWS"), 0)

            # Feature: is_privileged_action (action_risk >= 8)
            is_privileged_action = int(action_risk >= 8)

            rows.append({
                "hour":                 hour,
                "day_of_week":          day_of_week,
                "is_odd_hour":          is_odd_hour,
                "is_weekend":           is_weekend,
                "action_risk":          action_risk,
                "is_denied":            is_denied,
                "is_high_risk_country": is_high_risk_country,
                "cloud_encoded":        cloud_encoded,
                "is_privileged_action": is_privileged_action,
            })
        except Exception:
            rows.append({
                "hour": 12, "day_of_week": 0, "is_odd_hour": 0,
                "is_weekend": 0, "action_risk": 3, "is_denied": 0,
                "is_high_risk_country": 0, "cloud_encoded": 0,
                "is_privileged_action": 0,
            })

    return pd.DataFrame(rows)


def compute_trust_score(event: dict) -> float:
    """
    Compute normalized Trust Score (0.0–1.0).

    Formula: TS = wB·B + wN·N + wD·D + wT·T
    Source: Jeong & Yang (2025), Equation 1, Section 3.2.1, Page 10

    Weights: wB=0.4, wN=0.3, wD=0.2, wT=0.1
    Source: Section 3.2.2, Page 10–11

    Each factor scored 0–100, then normalized to 0–1.
    """
    try:
        ts_str = event.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        except Exception:
            ts = datetime.now()

        hour = ts.hour
        action_risk = int(event.get("action_risk", 3))
        country = event.get("country", "Unknown")
        error_code = event.get("error_code", "")
        is_denied = bool(error_code and error_code not in ["", "None"])

        # ── B: User Behavior Score (0–100) ────────────────────────────────
        # Source: Jeong & Yang (2025), Table 2, Page 8
        # Row ①: Login Frequency (action_risk as proxy)
        # Row ③: Off-Hours Login
        b_time_score = (
            20 if 9 <= hour < 18       # Normal business hours → 20pts
            else 15 if 18 <= hour < 22  # Acceptable overtime → 15pts
            else 10 if 22 <= hour or hour < 2   # Unusual hours → 10pts
            else 5 if 2 <= hour < 4    # Weekend/odd hours → 5pts
            else 0                     # 02:00–05:00 → 0pts (very high risk)
        )
        b_action_score = max(0, 20 - (action_risk * 2))  # higher risk = lower score
        b_denied_score = 0 if is_denied else 20
        B = min(100, b_time_score + b_action_score + b_denied_score + 20)

        # ── N: Network Environment Score (0–100) ──────────────────────────
        # Source: Jeong & Yang (2025), Table 3, Page 8
        # Row ①: IP Reputation, Row ④: Access Location Reliability
        if country in HIGH_RISK_COUNTRIES:
            N = 15   # Accessing high-risk countries → 0pts location + low IP score
        elif country == "Unknown":
            N = 50
        else:
            N = 80   # Known safe location

        # ── D: Device Status Score (0–100) ────────────────────────────────
        # Source: Jeong & Yang (2025), Table 4, Page 9
        # We don't have device data from cloud logs, so we use a baseline
        # of 70 (moderate — known device but no full security posture data)
        D = 70

        # ── T: Threat History Score (0–100) ───────────────────────────────
        # Source: Jeong & Yang (2025), Table 5, Page 9-10
        # Proxied by action_risk and denied status
        T = 80 if not is_denied else 40
        if action_risk >= 8:
            T = max(0, T - 30)

        # ── Weighted Trust Score ───────────────────────────────────────────
        # Formula: TS = (wB·B + wN·N + wD·D + wT·T)
        # Normalize to 0.0–1.0 (divide by 100)
        raw_ts = (
            WEIGHT_USER_BEHAVIOR   * B +
            WEIGHT_NETWORK         * N +
            WEIGHT_DEVICE          * D +
            WEIGHT_THREAT_HISTORY  * T
        )
        return round(raw_ts / 100.0, 4)

    except Exception:
        return 0.5


def get_decision(trust_score: float) -> dict:
    """
    Map trust score to Zero Trust decision.
    Source: Jeong & Yang (2025), Section 4.1, Page 14
    Extended with CRITICAL BLOCK tier per NIST SP 800-207 §3.3.1
    """
    if trust_score >= THRESHOLD_ALLOW:
        return {
            "decision": "ALLOW",
            "color": "#2ecc71",
            "action": "Access granted. Continue monitoring.",
            "severity": 0
        }
    elif trust_score >= THRESHOLD_MFA:
        return {
            "decision": "MFA REQUIRED",
            "color": "#f1c40f",
            "action": "Additional verification required before access.",
            "severity": 1
        }
    elif trust_score >= THRESHOLD_BLOCK:
        return {
            "decision": "BLOCK",
            "color": "#e67e22",
            "action": "Access denied. High risk detected.",
            "severity": 2
        }
    else:
        return {
            "decision": "CRITICAL BLOCK",
            "color": "#e74c3c",
            "action": "Session terminated. Admin alerted. IP flagged.",
            "severity": 3
        }


class EnsembleDetector:
    """
    Combines Random Forest, XGBoost, and Isolation Forest.
    Architecture follows Al-Shehari et al. (2023) Figure 1, Page 118173:
    Left box: ML-Based Supervised Learning (RF, XGBoost)
    Right box: ML-Based Anomaly Detection (Isolation Forest)
    """

    def __init__(self):
        self.rf = RandomForestClassifier(
            n_estimators=100, random_state=IF_RANDOM_STATE
        )
        self.xgb = XGBClassifier(
            n_estimators=100, random_state=IF_RANDOM_STATE,
            eval_metric="logloss", verbosity=0
        )
        self.iso = IsolationForest(
            contamination=IF_CONTAMINATION,    # 0.02 — Table 6 best result
            n_estimators=IF_N_ESTIMATORS,
            random_state=IF_RANDOM_STATE
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self._try_load_models()

    def _try_load_models(self):
        model_file = os.path.join(MODEL_PATH, "ensemble.pkl")
        if os.path.exists(model_file):
            try:
                with open(model_file, "rb") as f:
                    data = pickle.load(f)
                self.rf = data["rf"]
                self.xgb = data["xgb"]
                self.iso = data["iso"]
                self.scaler = data["scaler"]
                self.is_trained = True
                print("[ML Engine] Loaded saved models.")
            except Exception:
                pass

    def _save_models(self):
        os.makedirs(MODEL_PATH, exist_ok=True)
        model_file = os.path.join(MODEL_PATH, "ensemble.pkl")
        with open(model_file, "wb") as f:
            pickle.dump({
                "rf": self.rf, "xgb": self.xgb,
                "iso": self.iso, "scaler": self.scaler
            }, f)

    def train(self, events: list[dict]):
        """
        Train all three models on collected log events.
        Labels: events with action_risk >= 7 OR is_odd_hour OR is_denied = anomaly (1)
        Normal events = 0. This is consistent with CERT r4.2 dataset labeling approach.
        """
        if len(events) < 10:
            print("[ML Engine] Not enough events to train. Need at least 10.")
            return

        df = extract_features(events)

        # Synthetic labels for supervised models
        # Anomaly if: high action risk, odd hour, or denied access
        labels = (
            (df["action_risk"] >= 7) |
            (df["is_odd_hour"] == 1) |
            (df["is_denied"] == 1) |
            (df["is_high_risk_country"] == 1)
        ).astype(int)

        X = df.values
        X_scaled = self.scaler.fit_transform(X)

        self.rf.fit(X_scaled, labels)
        self.xgb.fit(X_scaled, labels)
        self.iso.fit(X_scaled)

        self.is_trained = True
        self._save_models()
        print(f"[ML Engine] Trained on {len(events)} events. "
              f"Anomaly rate: {labels.mean()*100:.1f}%")

    def predict(self, events: list[dict]) -> list[dict]:
        """
        Run ensemble prediction on events.
        Returns events enriched with:
        - trust_score (float 0.0–1.0)
        - rf_score, xgb_score, iso_score (individual model outputs)
        - ensemble_score (weighted average)
        - decision (ALLOW/MFA/BLOCK/CRITICAL BLOCK)
        - is_anomaly (bool)
        """
        df = extract_features(events)
        X = df.values

        results = []
        for i, event in enumerate(events):
            row = X[i].reshape(1, -1)

            # Compute trust score (IEEE formula, always available)
            trust_score = compute_trust_score(event)

            # ML model predictions (if trained)
            rf_anomaly = 0
            xgb_anomaly = 0
            iso_anomaly = 0

            if self.is_trained:
                try:
                    row_scaled = self.scaler.transform(row)
                    rf_anomaly = int(self.rf.predict(row_scaled)[0])
                    xgb_anomaly = int(self.xgb.predict(row_scaled)[0])
                    # Isolation Forest: -1 = anomaly, 1 = normal
                    iso_pred = self.iso.predict(row_scaled)[0]
                    iso_anomaly = int(iso_pred == -1)
                except Exception:
                    pass

            # Ensemble vote (majority)
            ensemble_votes = rf_anomaly + xgb_anomaly + iso_anomaly
            is_anomaly = ensemble_votes >= 2

            # Adjust trust score if ML flags anomaly
            if is_anomaly:
                trust_score = min(trust_score, 0.55)

            decision = get_decision(trust_score)

            results.append({
                **event,
                "trust_score":    trust_score,
                "rf_anomaly":     rf_anomaly,
                "xgb_anomaly":    xgb_anomaly,
                "iso_anomaly":    iso_anomaly,
                "ensemble_votes": ensemble_votes,
                "is_anomaly":     is_anomaly,
                "decision":       decision["decision"],
                "decision_color": decision["color"],
                "decision_action": decision["action"],
                "severity":       decision["severity"],
            })

        return results
