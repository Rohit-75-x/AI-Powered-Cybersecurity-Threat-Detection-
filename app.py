"""
Production-Ready Flask REST API for AI Cybersecurity Threat Detection.
Provides real-time packet inference, batch evaluation, and threat simulation endpoints.
"""

import json
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS

from src.config import OUTPUTS_DIR
from src.preprocessor import ThreatPreprocessor
from src.models import DualEngineThreatDetector
from src.alert_system import SOCAlertSystem
from src.simulator import CyberThreatSimulator

# Initialize Flask application
app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing for SOC dashboards

# Global model references
PREPROCESSOR = None
DETECTOR = None
SOC_SYSTEM = None
CLASS_NAMES = []


def initialize_system():
    """Initializes and caches models and preprocessors."""
    global PREPROCESSOR, DETECTOR, SOC_SYSTEM, CLASS_NAMES
    try:
        PREPROCESSOR = ThreatPreprocessor.load()
        DETECTOR = DualEngineThreatDetector.load()
        SOC_SYSTEM = SOCAlertSystem()
        CLASS_NAMES = list(PREPROCESSOR.target_encoder.classes_)
        print("[INFO] AI Threat Detection Engine initialized successfully.")
    except Exception as e:
        print(f"[WARN] Models not loaded on startup: {e}. Please run training pipeline.")


# Run initialization
initialize_system()


@app.route("/", methods=["GET"])
def index():
    """Root endpoint detailing system status and available API contracts."""
    return jsonify({
        "system": "AI-Powered Cybersecurity Threat Detection System",
        "version": "1.0.0",
        "status": "OPERATIONAL" if DETECTOR is not None else "NEEDS_TRAINING",
        "supported_threat_classes": CLASS_NAMES,
        "endpoints": {
            "GET /health": "Engine health and model status",
            "POST /api/v1/detect": "Single network flow threat classification & risk scoring",
            "POST /api/v1/batch-detect": "Bulk network telemetry batch processing",
            "GET /api/v1/simulate": "Trigger live 5-scenario cyber warfare simulation",
            "GET /api/v1/metrics": "Retrieve model validation benchmarks",
        },
    }), 200


@app.route("/health", methods=["GET"])
def health():
    """Healthcheck endpoint."""
    return jsonify({
        "status": "healthy" if DETECTOR is not None else "uninitialized",
        "models_loaded": {
            "random_forest_classifier": DETECTOR.is_rf_trained if DETECTOR else False,
            "isolation_forest_anomaly": DETECTOR.is_if_trained if DETECTOR else False,
            "preprocessor": PREPROCESSOR.is_fitted if PREPROCESSOR else False,
        },
    }), 200


@app.route("/api/v1/detect", methods=["POST"])
def detect_single_packet():
    """
    Evaluates a single network packet or connection flow.
    Expects JSON body containing flow metrics.
    """
    if DETECTOR is None or PREPROCESSOR is None:
        return jsonify({"error": "Models not initialized. Please run training pipeline first."}), 503

    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "Invalid request. JSON payload required."}), 400

    # Ensure required default fields if omitted
    defaults = {
        "duration": 0.0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 100,
        "dst_bytes": 100,
        "failed_logins": 0,
        "logged_in": 1,
        "count": 1,
        "srv_count": 1,
        "serror_rate": 0.0,
        "rerror_rate": 0.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "dst_host_count": 10,
        "dst_host_srv_count": 10,
        "source_ip": "192.168.1.50",
        "dest_ip": "10.0.0.1",
    }
    for k, v in defaults.items():
        if k not in payload:
            payload[k] = v

    try:
        # Preprocess features
        X_flow = PREPROCESSOR.transform_single_dict(payload)

        # Dual-engine inference
        inference = DETECTOR.predict_packet(X_flow)
        pred_idx = inference["predicted_class_index"]
        pred_threat = str(CLASS_NAMES[pred_idx])
        confidence = inference["confidence"]
        is_anomaly = inference["is_anomaly"]
        anomaly_score = inference["anomaly_score"]

        # Generate SOC incident alert
        alert = SOC_SYSTEM.generate_incident_alert(
            threat_type=pred_threat,
            confidence=confidence,
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            source_ip=payload.get("source_ip", "192.168.1.50"),
            dest_ip=payload.get("dest_ip", "10.0.0.1"),
            network_telemetry=payload,
        )

        return jsonify({
            "success": True,
            "threat_detected": (pred_threat != "Normal") or is_anomaly,
            "alert": alert,
        }), 200

    except Exception as ex:
        return jsonify({"error": f"Inference failure: {str(ex)}"}), 500


@app.route("/api/v1/batch-detect", methods=["POST"])
def detect_batch():
    """
    Evaluates a batch array of network flows.
    """
    if DETECTOR is None or PREPROCESSOR is None:
        return jsonify({"error": "Models not initialized."}), 503

    payload = request.get_json(silent=True)
    if not payload or not isinstance(payload.get("flows"), list):
        return jsonify({"error": "Payload must contain a 'flows' list of connection records."}), 400

    flows = payload["flows"]
    results = []
    threat_count = 0

    import pandas as pd
    df_flows = pd.DataFrame(flows)
    X_batch, _, _ = PREPROCESSOR.transform(df_flows)
    rf_preds, rf_probs, if_preds, if_scores = DETECTOR.predict_batch(X_batch)

    for i, flow in enumerate(flows):
        pred_threat = str(CLASS_NAMES[rf_preds[i]])
        conf = float(rf_probs[i])
        is_anom = bool(if_preds[i])
        a_score = float(if_scores[i])

        alert = SOC_SYSTEM.generate_incident_alert(
            threat_type=pred_threat,
            confidence=conf,
            is_anomaly=is_anom,
            anomaly_score=a_score,
            source_ip=flow.get("source_ip", "192.168.1.100"),
            dest_ip=flow.get("dest_ip", "10.0.0.1"),
            network_telemetry=flow,
        )

        is_threat = (pred_threat != "Normal") or is_anom
        if is_threat:
            threat_count += 1

        results.append({
            "flow_index": i,
            "threat_detected": is_threat,
            "threat_type": pred_threat,
            "severity": alert["severity"],
            "risk_score": alert["risk_score"],
            "action": alert["soc_recommended_action"],
        })

    return jsonify({
        "success": True,
        "total_analyzed": len(flows),
        "threats_flagged": threat_count,
        "clean_flows": len(flows) - threat_count,
        "results": results,
    }), 200


@app.route("/api/v1/simulate", methods=["GET"])
def trigger_simulation():
    """Triggers virtual attack simulation and returns results."""
    try:
        sim = CyberThreatSimulator()
        sim_results = sim.run_simulation(delay=0.0)
        return jsonify({
            "success": True,
            "message": "Cyber threat scenario simulation executed successfully.",
            "scenarios_tested": len(sim_results),
            "telemetry": sim_results,
        }), 200
    except Exception as ex:
        return jsonify({"error": f"Simulation failure: {str(ex)}"}), 500


@app.route("/api/v1/metrics", methods=["GET"])
def get_metrics():
    """Returns serialized model benchmarks."""
    metrics_path = OUTPUTS_DIR / "evaluation_metrics.json"
    if not metrics_path.exists():
        return jsonify({"error": "Metrics file not found. Train the model first."}), 404

    with open(metrics_path, "r") as f:
        data = json.load(f)
    return jsonify(data), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
