#!/usr/bin/env python3
"""
report_metrics.py
Generates thesis-ready analysis from verification_logs, including:
- Summary stats (CSV)
- Latency histogram (PNG)
- Confusion matrices (PNG) for:
    * Duplicate detection
    * Tampering detection (AES-GCM)
    * Signature verification (RSA-PSS)
- Processed verification logs export
"""

import os
import sqlite3
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(ROOT, "docutrack.db")
OUTDIR = os.path.join(ROOT, "reports")

os.makedirs(OUTDIR, exist_ok=True)

print("Reading DB:", DB)

# -------------------------------------------------------------
# Load verification logs
# -------------------------------------------------------------
conn = sqlite3.connect(DB)
df = pd.read_sql_query("SELECT * FROM verification_logs", conn)
conn.close()

if df.empty:
    print("ERROR: verification_logs is empty. Run test_harness.py --verify first.")
    exit(1)

print(f"Loaded {len(df)} verification records.")

# -------------------------------------------------------------
# Clean and preprocess (robust to NULL/NaN)
# -------------------------------------------------------------
# Convert numeric-like columns robustly to nullable ints/floats
df["signature_valid"] = pd.to_numeric(df.get("signature_valid"), errors="coerce").astype("Int64")
df["gcm_auth_valid"] = pd.to_numeric(df.get("gcm_auth_valid"), errors="coerce").astype("Int64")
df["duplicate_flag"]   = pd.to_numeric(df.get("duplicate_flag"), errors="coerce").astype("Int64")
df["latency_ms"]       = pd.to_numeric(df.get("latency_ms"), errors="coerce").astype(float)

# combined validity (both crypto checks passed)
df["is_valid"] = (df["signature_valid"] == 1) & (df["gcm_auth_valid"] == 1)

# normalize ground_truth to lowercase string for substring checks
df["ground_truth_norm"] = df["ground_truth"].fillna("").astype(str).str.lower()

# -------------------------------------------------------------
# Latency Metrics (ignore NaNs)
# -------------------------------------------------------------
lat_mean = float(df["latency_ms"].mean()) if not df["latency_ms"].dropna().empty else float("nan")
lat_median = float(df["latency_ms"].median()) if not df["latency_ms"].dropna().empty else float("nan")
lat_p95 = float(df["latency_ms"].quantile(0.95)) if not df["latency_ms"].dropna().empty else float("nan")
lat_max = float(df["latency_ms"].max()) if not df["latency_ms"].dropna().empty else float("nan")

# -------------------------------------------------------------
# Signature / GCM Accuracy
# -------------------------------------------------------------
# Where signature_valid is NaN, it will be ignored by .mean()
sig_acc = float(df["signature_valid"].dropna().mean() * 100) if not df["signature_valid"].dropna().empty else float("nan")
gcm_acc = float(df["gcm_auth_valid"].dropna().mean() * 100) if not df["gcm_auth_valid"].dropna().empty else float("nan")
overall_valid_rate = float(df["is_valid"].dropna().mean() * 100) if not df["is_valid"].dropna().empty else float("nan")

# -------------------------------------------------------------
# Helper: confusion matrix computation & plotting
# -------------------------------------------------------------
def compute_confusion(gt_mask, pred_mask):
    """
    gt_mask: boolean Series indicating ground-truth positive (True for positive)
    pred_mask: boolean Series indicating predicted positive (True for positive)
    Both must be aligned and have no missing values for selected rows.
    Returns (TP, FN, FP, TN)
    """
    TP = int(((gt_mask == True) & (pred_mask == True)).sum())
    FN = int(((gt_mask == True) & (pred_mask == False)).sum())
    FP = int(((gt_mask == False) & (pred_mask == True)).sum())
    TN = int(((gt_mask == False) & (pred_mask == False)).sum())
    return TP, FN, FP, TN

def plot_confusion_matrix(cm, title, xticks, yticks, outpath):
    plt.figure(figsize=(5,4))
    plt.imshow(cm, cmap="Blues", interpolation="nearest")
    plt.colorbar()
    plt.title(title)
    plt.xticks([0,1], xticks)
    plt.yticks([0,1], yticks)
    for i in range(2):
        for j in range(2):
            plt.text(j, i, int(cm[i,j]), ha="center", va="center", fontsize=14)
    plt.xlabel("Predicted")
    plt.ylabel("Ground Truth")
    plt.tight_layout()
    plt.savefig(outpath, dpi=150, bbox_inches="tight")
    plt.close()

# timestamp suffix for files
ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

# -------------------------------------------------------------
# Confusion Matrix 1: Duplicate Detection
# ground_truth contains 'dup' vs duplicate_flag column
# -------------------------------------------------------------
df_dup = df[~df["ground_truth_norm"].isna()].copy()
# Only consider rows where duplicate_flag is not null for predictions
df_dup_eval = df_dup[df_dup["duplicate_flag"].notna()].copy()

if not df_dup_eval.empty:
    gt_dup = df_dup_eval["ground_truth_norm"].str.contains("dup", na=False)
    pred_dup = (df_dup_eval["duplicate_flag"] == 1)
    TP, FN, FP, TN = compute_confusion(gt_dup, pred_dup)
    cm_dup = np.array([[TP, FN],
                       [FP, TN]])
    dup_cm_path = os.path.join(OUTDIR, f"confusion_matrix_duplicate_{ts}.png")
    plot_confusion_matrix(cm_dup, "Duplicate Detection Confusion Matrix",
                          ["Pred Dup", "Pred Unique"], ["GT Dup", "GT Unique"], dup_cm_path)
else:
    TP = FN = FP = TN = 0
    cm_dup = np.array([[0,0],[0,0]])
    dup_cm_path = None

# -------------------------------------------------------------
# Confusion Matrix 2: Tampering Detection (AES-GCM)
# ground_truth contains 'tamper' or 'tampered' -> positive
# prediction: gcm_auth_valid == 0 -> tampered (positive)
# -------------------------------------------------------------
df_tam = df[~df["ground_truth_norm"].isna()].copy()
# consider rows where gcm_auth_valid is not null
df_tam_eval = df_tam[df_tam["gcm_auth_valid"].notna()].copy()

if not df_tam_eval.empty:
    gt_tam = df_tam_eval["ground_truth_norm"].str.contains("tamper", na=False)
    pred_tam = (df_tam_eval["gcm_auth_valid"] == 0)  # gcm_auth_valid == 0 indicates tampered
    TP_t, FN_t, FP_t, TN_t = compute_confusion(gt_tam, pred_tam)
    cm_tam = np.array([[TP_t, FN_t],
                       [FP_t, TN_t]])
    tam_cm_path = os.path.join(OUTDIR, f"confusion_matrix_tampering_{ts}.png")
    plot_confusion_matrix(cm_tam, "Tampering Detection Confusion Matrix",
                          ["Pred Tampered", "Pred Clean"], ["GT Tampered", "GT Clean"], tam_cm_path)
else:
    TP_t = FN_t = FP_t = TN_t = 0
    cm_tam = np.array([[0,0],[0,0]])
    tam_cm_path = None

# -------------------------------------------------------------
# Confusion Matrix 3: Signature Verification (RSA-PSS)
# ground_truth contains 'sig' or 'sig_corrupt' -> positive (corrupted)
# prediction: signature_valid == 0 -> invalid signature -> positive
# -------------------------------------------------------------
df_sig = df[~df["ground_truth_norm"].isna()].copy()
df_sig_eval = df_sig[df_sig["signature_valid"].notna()].copy()

if not df_sig_eval.empty:
    gt_sig = df_sig_eval["ground_truth_norm"].str.contains("sig", na=False)
    pred_sig_invalid = (df_sig_eval["signature_valid"] == 0)  # 0 => invalid signature -> positive
    TP_s, FN_s, FP_s, TN_s = compute_confusion(gt_sig, pred_sig_invalid)
    cm_sig = np.array([[TP_s, FN_s],
                       [FP_s, TN_s]])
    sig_cm_path = os.path.join(OUTDIR, f"confusion_matrix_signature_{ts}.png")
    plot_confusion_matrix(cm_sig, "Signature Integrity Confusion Matrix",
                          ["Pred Invalid Sig", "Pred Valid Sig"], ["GT Sig-Corrupted", "GT Clean"], sig_cm_path)
else:
    TP_s = FN_s = FP_s = TN_s = 0
    cm_sig = np.array([[0,0],[0,0]])
    sig_cm_path = None

# -------------------------------------------------------------
# Save Latency Histogram
# -------------------------------------------------------------
plt.figure(figsize=(8,4))
plt.hist(df["latency_ms"].dropna(), bins=20)
plt.title("File Verification Latency (ms)")
plt.xlabel("Latency (ms)")
plt.ylabel("Frequency")

hist_path = os.path.join(OUTDIR, f"latency_histogram_{ts}.png")
plt.savefig(hist_path, dpi=150, bbox_inches='tight')
plt.close()

# -------------------------------------------------------------
# Save Summary CSV
# -------------------------------------------------------------
summary = {
    "records_processed": len(df),
    "latency_mean_ms": lat_mean,
    "latency_median_ms": lat_median,
    "latency_p95_ms": lat_p95,
    "latency_max_ms": lat_max,
    "signature_accuracy_pct": sig_acc,
    "gcm_accuracy_pct": gcm_acc,
    "overall_validity_pct": overall_valid_rate,
    # duplicate metrics
    "dup_TP": TP, "dup_FN": FN, "dup_FP": FP, "dup_TN": TN,
    # tampering metrics
    "tam_TP": TP_t, "tam_FN": FN_t, "tam_FP": FP_t, "tam_TN": TN_t,
    # signature metrics (using invalid-as-positive)
    "sig_TP": TP_s, "sig_FN": FN_s, "sig_FP": FP_s, "sig_TN": TN_s
}

summary_df = pd.DataFrame([summary])
summary_path = os.path.join(OUTDIR, f"report_metrics_summary_{ts}.csv")
summary_df.to_csv(summary_path, index=False)

# -------------------------------------------------------------
# Save processed logs
# -------------------------------------------------------------
processed_path = os.path.join(OUTDIR, f"verification_logs_processed_{ts}.csv")
df.to_csv(processed_path, index=False)

# -------------------------------------------------------------
# Print summary to console
# -------------------------------------------------------------
print("\n===== REPORT SUMMARY =====")
print(f"Records processed: {len(df)}")
if not np.isnan(lat_mean):
    print(f"Mean latency: {lat_mean:.2f} ms")
    print(f"Median latency: {lat_median:.2f} ms")
    print(f"95th percentile latency: {lat_p95:.2f} ms")
    print(f"Max latency: {lat_max:.2f} ms\n")
else:
    print("Latency metrics: no valid latency records.\n")

if not np.isnan(sig_acc):
    print(f"Signature verification accuracy: {sig_acc:.2f}%")
else:
    print("Signature verification accuracy: N/A (no signature_valid data)")

if not np.isnan(gcm_acc):
    print(f"GCM authentication accuracy: {gcm_acc:.2f}%")
else:
    print("GCM authentication accuracy: N/A (no gcm_auth_valid data)")

if not np.isnan(overall_valid_rate):
    print(f"Overall cryptographic validity: {overall_valid_rate:.2f}%\n")
else:
    print("Overall cryptographic validity: N/A\n")

print("Duplicate detection (confusion):")
print(f"  TP: {TP}  FN: {FN}  FP: {FP}  TN: {TN}")
print("Tampering detection (confusion):")
print(f"  TP: {TP_t}  FN: {FN_t}  FP: {FP_t}  TN: {TN_t}")
print("Signature detection (confusion, invalid-as-positive):")
print(f"  TP: {TP_s}  FN: {FN_s}  FP: {FP_s}  TN: {TN_s}")

print("\nGenerated files:")
print(" -", hist_path)
if dup_cm_path: print(" -", dup_cm_path)
if tam_cm_path: print(" -", tam_cm_path)
if sig_cm_path: print(" -", sig_cm_path)
print(" -", summary_path)
print(" -", processed_path)
print("==========================\n")
