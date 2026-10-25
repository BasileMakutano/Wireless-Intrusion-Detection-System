"""Turns raw 802.11 frames into per-device, per-second feature rows."""
import numpy as np, pandas as pd

FEATS = ["n_frames", "n_deauth", "deauth_ratio", "n_rx",
         "mean_rssi", "std_rssi", "mean_len", "mgmt_ratio"]

def window_features(df):
    """df columns: t, ta, ra, type, subtype, rssi, len (+ optional y: 1 = attack frame)."""
    df = df.dropna(subset=["ta"]).copy()
    if "y" not in df: df["y"] = 0
    df["w"] = np.floor(df["t"]).astype(int)
    df["mgmt"] = (df["type"] == 0).astype(int)
    df["deauth"] = ((df["type"] == 0) & df["subtype"].isin([10, 12])).astype(int)  # disassoc + deauth
    g = df.groupby(["w", "ta"])
    out = g.agg(n_frames=("t", "size"), n_deauth=("deauth", "sum"), n_rx=("ra", "nunique"),
                mean_rssi=("rssi", "mean"), std_rssi=("rssi", "std"),
                mean_len=("len", "mean"), mgmt_ratio=("mgmt", "mean"), y=("y", "max")).reset_index()
    out["deauth_ratio"] = out["n_deauth"] / out["n_frames"]
    return out.fillna(0)
