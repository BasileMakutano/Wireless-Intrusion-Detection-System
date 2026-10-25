"""Train the classifier from AWID3 CSV file(s).
Usage: python train.py awid3_deauth.csv [more.csv] [--max-rows 2000000]
Column names follow the AWID3 CSV (Wireshark field names); edit COLS if yours differ."""
import argparse, json, joblib, pandas as pd, numpy as np
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from features import window_features, FEATS

COLS = {"t": ["frame.time_epoch"], "ta": ["wlan.ta", "wlan.sa"], "ra": ["wlan.ra", "wlan.da"],
        "rssi": ["radiotap.dbm_antsignal"], "len": ["frame.len"], "type": ["wlan.fc.type"],
        "subtype": ["wlan.fc.subtype"], "label": ["Label", "label"]}

ap = argparse.ArgumentParser()
ap.add_argument("csv", nargs="+"); ap.add_argument("--max-rows", type=int, default=None)
a = ap.parse_args()

frames = []
for path in a.csv:
    head = pd.read_csv(path, nrows=0).columns
    pick = {k: next(c for c in v if c in head) for k, v in COLS.items()}
    d = pd.read_csv(path, usecols=list(pick.values()), nrows=a.max_rows, low_memory=False)
    d = d.rename(columns={v: k for k, v in pick.items()})
    for c in ["t", "rssi", "len", "type", "subtype"]:
        d[c] = pd.to_numeric(d[c], errors="coerce")   # AWID3 uses '?' for missing
    d["y"] = (d["label"].astype(str).str.strip().str.lower() != "normal").astype(int)
    frames.append(d.dropna(subset=["t", "type", "subtype"]))
df = pd.concat(frames)
print("frames:", len(df), "attack frames:", int(df.y.sum()))

W = window_features(df)
print("windows:", len(W), "attack windows:", int(W.y.sum()))
Xtr, Xte, ytr, yte = train_test_split(W[FEATS], W["y"], test_size=0.3, stratify=W["y"], random_state=42)
clf = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42).fit(Xtr, ytr)
pred = clf.predict(Xte)
acc = accuracy_score(yte, pred); cm = confusion_matrix(yte, pred, labels=[0, 1])
print("accuracy:", acc); print(cm); print(classification_report(yte, pred, target_names=["normal", "malicious"]))

joblib.dump(clf, "model.joblib")
json.dump({"accuracy": acc, "confusion_matrix": cm.tolist(), "n_train": len(Xtr), "n_test": len(Xte),
           "importances": dict(zip(FEATS, map(float, clf.feature_importances_)))},
          open("metrics.json", "w"), indent=2)
fig, ax = plt.subplots(figsize=(4, 4)); ax.imshow(cm, cmap="Blues")
for i in range(2):
    for j in range(2): ax.text(j, i, cm[i, j], ha="center", va="center", fontsize=14)
ax.set_xticks([0, 1], ["normal", "malicious"]); ax.set_yticks([0, 1], ["normal", "malicious"])
ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(f"Accuracy {acc:.3f}")
plt.tight_layout(); plt.savefig("confusion_matrix.png", dpi=200)
