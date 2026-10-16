"""
Master Execution Pipeline for AI Cybersecurity Threat Detection System.
Executes data generation, preprocessing, model training, evaluation,
visual analytics generation, and virtual threat simulation in a single automated run.
"""

import sys
import time
from pathlib import Path

from src.train import train_and_evaluate
from src.visualizer import generate_all_visualizations
from src.simulator import CyberThreatSimulator


def main():
    start_time = time.time()
    print("=" * 75)
    print("      AI-POWERED CYBERSECURITY THREAT DETECTION SYSTEM       ")
    print("        SOC End-to-End Autonomous Pipeline Execution         ")
    print("=" * 75)

    # Step 1 & 2: Train models & evaluate
    print("\n[STEP 1/3] Running Data Pipeline, Preprocessing & Dual-Engine Training...")
    metrics = train_and_evaluate()

    # Step 3: Visual Analytics
    print("\n[STEP 2/3] Generating High-Resolution SOC Analytics & Charts...")
    generate_all_visualizations()

    # Step 4: Virtual Cyber Warfare Simulation
    print("\n[STEP 3/3] Launching Real-World Cyber Attack Stream Simulation...")
    sim = CyberThreatSimulator()
    sim.run_simulation(delay=0.1)

    elapsed = time.time() - start_time
    print("\n" + "=" * 75)
    print(f"[PIPELINE COMPLETE] All tasks succeeded in {elapsed:.2f} seconds!")
    print(f"[*] Accuracy:              {metrics['multi_class_accuracy'] * 100:.2f}%")
    print(f"[*] Attack Recall:         {metrics['binary_threat_recall'] * 100:.2f}%")
    print(f"[*] Generated Charts:      outputs/ and images/")
    print(f"[*] SOC Alert Logs:        outputs/soc_alerts.json & outputs/soc_alerts.csv")
    print("[*] To launch the REST API: python app.py")
    print("=" * 75)


if __name__ == "__main__":
    main()
