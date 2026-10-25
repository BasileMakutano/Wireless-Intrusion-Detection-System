"""Train on the association/disassociation dataset.
Usage: python train.py Aassociation-Disassociation_Dataset.csv"""
import argparse, json, joblib, pandas as pd, numpy as np
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from features import window_features, FEATS

ap = argparse.ArgumentParser(); ap.add_argument("csv"); a = ap.parse_args()
d = pd.read_csv(a.csv)
ts = pd.to_datetime(d["@timestamp"].str.replace(" @ ", " "), format="%b %d, %Y %H:%M:%S.%f")
ev = pd.DataFrame({"t": (ts - pd.Timestamp("1970-01-01")) / pd.Timedelta(seconds=1),
                   "dev": d["mac_address"], "dis": (d["association"] == "disassociated").astype(int),
                   "y": (d["dataType"] == "attack").astype(int), "stream": d["dataType"]})
print("events:", len(ev), "| attack events:", int(ev.y.sum()))

W = window_features(ev)
print("windows:", len(W), "| attack windows:", int(W.y.sum()))
# Split by 1-hour blocks (not random rows) so neighbouring seconds of one burst never land in both sets
groups = W["stream"].astype(str) + "_" + (W["w"] // 3600).astype(str)
tr, te = next(GroupShuffleSplit(test_size=0.3, random_state=42).split(W, W["y"], groups))
Xtr, Xte, ytr, yte = W.iloc[tr][FEATS], W.iloc[te][FEATS], W.iloc[tr]["y"], W.iloc[te]["y"]
clf = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42).fit(Xtr, ytr)
pred = clf.predict(Xte)
acc = accuracy_score(yte, pred); cm = confusion_matrix(yte, pred, labels=[0, 1])
print("accuracy:", acc); print(cm); print(classification_report(yte, pred, target_names=["normal", "malicious"]))

joblib.dump(clf, "model.joblib")
json.dump({"accuracy": acc, "confusion_matrix": cm.tolist(), "n_train": len(Xtr), "n_test": len(Xte),
           "importances": dict(zip(FEATS, map(float, clf.feature_importances_)))}, open("metrics.json", "w"), indent=2)
fig, ax = plt.subplots(figsize=(4, 4)); ax.imshow(cm, cmap="Blues")
for i in range(2):
    for j in range(2): ax.text(j, i, cm[i, j], ha="center", va="center", fontsize=14)
ax.set_xticks([0, 1], ["normal", "malicious"]); ax.set_yticks([0, 1], ["normal", "malicious"])
ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(f"Accuracy {acc:.3f}")
plt.tight_layout(); plt.savefig("confusion_matrix.png", dpi=200)
