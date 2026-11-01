"""Turn awid3_frames_all.csv (one row per frame) into one row per device per second, with the
features the model will learn from, and a label. Run this locally where that CSV lives.

Usage: python build_training.py awid3_frames_all.csv --out awid3_train.csv

Deauth and disassociation floods are merged into one label ("deauth"): AWID3's own filter
matches both with the identical frame pattern (subtype 10 or 12, unprotected), so they are the
same attack signature recorded in two separate sessions, not two different things to learn.
"""
import argparse, sys
import pandas as pd

FEATS = ["n_frames", "n_mgmt", "n_data", "n_ctrl", "n_deauth_disassoc", "n_assoc_reassoc",
          "n_beacon", "n_qos_data", "unprot_ratio", "mean_len", "min_len", "mean_rssi"]

def build(path, chunksize=2_000_000):
    use = ["t", "sa", "ftype", "fsubtype", "protected", "rssi", "len", "attack"]
    head = pd.read_csv(path, nrows=0)
    missing = [c for c in use if c not in head.columns]
    if missing:
        raise SystemExit(f"{path} is missing columns {missing} (has: {list(head.columns)}). "
                          f"This usually means it was built by mixing CSVs from different "
                          f"versions of extract_awid3.py -- regenerate it in one single run.")
    parts = []
    total_in, total_kept = 0, 0
    for i, chunk in enumerate(pd.read_csv(path, usecols=use, chunksize=chunksize)):
        total_in += len(chunk)
        chunk = chunk.dropna(subset=["t", "sa", "ftype", "fsubtype"])
        total_kept += len(chunk)
        chunk["attack"] = chunk["attack"].replace({"disass": "deauth"})
        chunk["w"] = chunk["t"].astype(int)
        g = chunk.groupby(["w", "sa"])
        feat = g.agg(
            n_frames=("t", "size"),
            n_mgmt=("ftype", lambda s: (s == 0).sum()),
            n_data=("ftype", lambda s: (s == 2).sum()),
            n_ctrl=("ftype", lambda s: (s == 1).sum()),
            unprot_ratio=("protected", lambda s: (s.fillna(0) == 0).mean()),
            mean_len=("len", "mean"), min_len=("len", "min"),
            mean_rssi=("rssi", "mean"),
        )
        sub = chunk.fsubtype
        chunk["is_dd"] = chunk.ftype.eq(0) & sub.isin([10, 12])
        chunk["is_ar"] = chunk.ftype.eq(0) & sub.isin([0, 2])
        chunk["is_bc"] = chunk.ftype.eq(0) & sub.eq(8)
        chunk["is_qd"] = chunk.ftype.eq(2) & sub.eq(8)
        extra = chunk.groupby(["w", "sa"])[["is_dd", "is_ar", "is_bc", "is_qd"]].sum()
        extra.columns = ["n_deauth_disassoc", "n_assoc_reassoc", "n_beacon", "n_qos_data"]
        # Label a window by whichever ATTACK type appears, not whichever label has the most
        # frames: a rare/low-rate attack (e.g. a handful of rogue-AP beacons mixed into a
        # window of otherwise-normal traffic) would otherwise always lose a plain majority
        # vote to "normal" and vanish entirely, even though the ground truth says it happened.
        def pick_label(s):
            atk = s[s != "normal"]
            return atk.value_counts().idxmax() if len(atk) else "normal"
        lbl = chunk.groupby(["w", "sa"])["attack"].agg(pick_label)
        part = feat.join(extra).join(lbl).reset_index()
        parts.append(part)
        print(f"  chunk {i+1}: {len(chunk):,} frames -> {len(part):,} device-seconds", file=sys.stderr)
    dropped = total_in - total_kept
    if dropped > 0.1 * total_in:
        print(f"WARNING: {dropped:,} of {total_in:,} frames ({dropped/total_in:.0%}) were "
              f"dropped for missing ftype/fsubtype/t/sa -- that's a lot. Check the input CSV "
              f"wasn't built by concatenating files with different column names.", file=sys.stderr)
    out = pd.concat(parts, ignore_index=True)
    # a device-second that showed up in more than one chunk (rare, at a chunk boundary) --
    # merge those few duplicates by summing counts and re-picking the majority label.
    dup = out.duplicated(["w", "sa"], keep=False)
    if dup.any():
        print(f"  merging {dup.sum():,} rows split across chunk boundaries", file=sys.stderr)
        count_cols = ["n_frames", "n_mgmt", "n_data", "n_ctrl", "n_deauth_disassoc",
                      "n_assoc_reassoc", "n_beacon", "n_qos_data"]
        merged = out.groupby(["w", "sa"]).agg({**{c: "sum" for c in count_cols},
            "mean_len": "mean", "min_len": "min", "mean_rssi": "mean",
            "unprot_ratio": "mean", "attack": lambda s: s.value_counts().idxmax()}).reset_index()
        out = merged
    out[FEATS] = out[FEATS].fillna(0)
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv"); ap.add_argument("--out", default="awid3_train.csv")
    a = ap.parse_args()
    print("Building device-second features (this reads the file in chunks, so it won't load "
          "everything into memory at once) ...", file=sys.stderr)
    out = build(a.csv)
    out.to_csv(a.out, index=False)
    print(f"\nWrote {a.out}: {len(out):,} device-second rows")
    print(out.attack.value_counts().to_string())

if __name__ == "__main__":
    main()
