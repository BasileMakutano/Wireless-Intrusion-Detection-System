"""Multi-class trainer: 5 real AWID3 attack types + normal, from awid3_train.csv (built by
build_training.py). Usage: python train_v2.py awid3_train.csv"""
import argparse, json, joblib, numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from build_training import FEATS

ap = argparse.ArgumentParser(); ap.add_argument("csv"); a = ap.parse_args()
W = pd.read_csv(a.csv)
print("rows:", len(W)); print(W.attack.value_counts().to_string())

CLASSES = sorted(W.attack.unique(), key=lambda c: (c != "normal", c))  # normal first, rest alphabetic
# Each attack type here comes from its OWN separate recording session (a different pcap, at a
# different time), so a single global time-block split would just put whole classes entirely
# on one side (observed: evil_twin 100% in test, deauth/reassoc/rogue_ap 100% in train). Split
# WITHIN each class instead -- using 10-minute blocks inside that class's own time range, so
# neighbouring seconds of one burst still can't leak across train/test, but every class is
# guaranteed to appear on both sides.
tr_idx, te_idx = [], []
for cls, grp in W.groupby("attack"):
    cls_groups = (grp["w"] // 600).astype(str)
    if cls_groups.nunique() < 2:
        n_te = max(1, int(len(grp) * 0.3))
        te_idx += list(grp.index[-n_te:]); tr_idx += list(grp.index[:-n_te])
        continue
    a, b = next(GroupShuffleSplit(test_size=0.3, random_state=42).split(grp, grp["attack"], cls_groups))
    tr_idx += list(grp.index[a]); te_idx += list(grp.index[b])
Xtr, Xte, ytr, yte = W.loc[tr_idx, FEATS], W.loc[te_idx, FEATS], W.loc[tr_idx, "attack"], W.loc[te_idx, "attack"]
missing_in_test = set(ytr.unique()) - set(yte.unique())
if missing_in_test:
    print(f"NOTE: {missing_in_test} present in training but absent from the test split "
          f"(too little time spread within that class to divide into separate blocks) -- "
          f"their test-set precision/recall will show as 0 or be undefined.")

clf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42).fit(Xtr, ytr)
pred = clf.predict(Xte)
acc = accuracy_score(yte, pred)
cm = confusion_matrix(yte, pred, labels=CLASSES)
report = classification_report(yte, pred, labels=CLASSES, target_names=CLASSES, zero_division=0, output_dict=True)
print(f"\naccuracy: {acc:.4f}")
print(classification_report(yte, pred, labels=CLASSES, target_names=CLASSES, zero_division=0))

joblib.dump(clf, "model_v2.joblib")
joblib.dump(CLASSES, "classes_v2.joblib")
json.dump({"accuracy": acc, "classes": CLASSES, "confusion_matrix": cm.tolist(),
           "n_train": len(Xtr), "n_test": len(Xte), "per_class": report,
           "importances": dict(zip(FEATS, map(float, clf.feature_importances_))),
           "class_support_total": W.attack.value_counts().to_dict()},
          open("metrics_v2.json", "w"), indent=2)

fig, ax = plt.subplots(figsize=(6, 5.5))
im = ax.imshow(cm, cmap="Blues")
for i in range(len(CLASSES)):
    for j in range(len(CLASSES)):
        ax.text(j, i, cm[i, j], ha="center", va="center",
                color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=10)
ax.set_xticks(range(len(CLASSES)), CLASSES, rotation=40, ha="right")
ax.set_yticks(range(len(CLASSES)), CLASSES)
ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(f"Accuracy {acc:.3f}")
plt.tight_layout(); plt.savefig("confusion_matrix_v2.png", dpi=200)
print("\nWrote model_v2.joblib, classes_v2.joblib, metrics_v2.json, confusion_matrix_v2.png")
