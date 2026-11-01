"""Shared feature computation: turns raw 802.11 frames into one row per device per one-second
window. Used by both build_training.py (offline, from AWID3 pcaps) and engine.py (live/replay),
so training and detection always compute features the exact same way.

Frame columns expected: t (epoch seconds), sa (transmitter MAC), ftype (0=mgmt,1=ctrl,2=data),
fsubtype (0-15), protected (0/1, NaN treated as 0 -- tshark leaves this blank when unset),
len (frame length in bytes), rssi (signal strength in dBm, may be NaN if unavailable).
"""
import pandas as pd

FEATS = ["n_frames", "n_mgmt", "n_data", "n_ctrl", "n_deauth_disassoc", "n_assoc_reassoc",
          "n_beacon", "n_qos_data", "unprot_ratio", "mean_len", "min_len", "mean_rssi"]

def window_features(df):
    df = df.dropna(subset=["t", "sa", "ftype", "fsubtype"]).copy()
    if df.empty:
        return pd.DataFrame(columns=["w", "sa"] + FEATS)
    df["w"] = df["t"].astype(int)
    g = df.groupby(["w", "sa"])
    feat = g.agg(
        n_frames=("t", "size"),
        n_mgmt=("ftype", lambda s: (s == 0).sum()),
        n_data=("ftype", lambda s: (s == 2).sum()),
        n_ctrl=("ftype", lambda s: (s == 1).sum()),
        unprot_ratio=("protected", lambda s: (s.fillna(0) == 0).mean()),
        mean_len=("len", "mean"), min_len=("len", "min"),
        mean_rssi=("rssi", "mean"),
    )
    sub = df.fsubtype
    df["is_dd"] = df.ftype.eq(0) & sub.isin([10, 12])
    df["is_ar"] = df.ftype.eq(0) & sub.isin([0, 2])
    df["is_bc"] = df.ftype.eq(0) & sub.eq(8)
    df["is_qd"] = df.ftype.eq(2) & sub.eq(8)
    extra = df.groupby(["w", "sa"])[["is_dd", "is_ar", "is_bc", "is_qd"]].sum()
    extra.columns = ["n_deauth_disassoc", "n_assoc_reassoc", "n_beacon", "n_qos_data"]
    out = feat.join(extra).reset_index()
    out[FEATS] = out[FEATS].fillna(0)
    return out
