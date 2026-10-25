"""Event-based features. One 'event' = a device associating or (dis)associating/deauthenticating.
Works on both the dataset (timestamp, device, associated/disassociated) and live frames."""
import numpy as np, pandas as pd

FEATS = ["n_events", "n_dis", "dis_ratio", "min_gap", "n_10s", "n_60s", "gap_prev"]
CAP = 60.0  # seconds; history never looks further back than this (so live == training)

def window_features(ev):
    """ev columns: t (epoch seconds), dev, dis (1 = disassoc/deauth, 0 = assoc),
    optional y (1 = attack) and stream (keeps separate captures apart)."""
    ev = ev.copy()
    if "y" not in ev: ev["y"] = 0
    if "stream" not in ev: ev["stream"] = 0
    ev = ev.sort_values(["stream", "dev", "t"]).reset_index(drop=True)
    ev["w"] = np.floor(ev["t"]).astype(np.int64)
    ev["gap"] = ev.groupby(["stream", "dev", "w"])["t"].diff()
    g = ev.groupby(["stream", "dev", "w"])
    out = g.agg(n_events=("t", "size"), n_dis=("dis", "sum"), min_gap=("gap", "min"),
                t_first=("t", "min"), y=("y", "max")).reset_index()
    out["dis_ratio"] = out["n_dis"] / out["n_events"]
    out["min_gap"] = out["min_gap"].fillna(1.0).clip(upper=1.0)
    n10 = np.zeros(len(out)); n60 = np.zeros(len(out)); gp = np.full(len(out), CAP)
    for (s, d), idx in out.groupby(["stream", "dev"]).groups.items():
        t = ev.loc[(ev.stream == s) & (ev.dev == d), "t"].to_numpy()   # already sorted
        end = out.loc[idx, "w"].to_numpy() + 1.0
        hi = np.searchsorted(t, end, side="right")
        n10[idx] = hi - np.searchsorted(t, end - 10, side="right")
        n60[idx] = hi - np.searchsorted(t, end - CAP, side="right")
        first = np.searchsorted(t, out.loc[idx, "t_first"].to_numpy(), side="left")
        prev = np.where(first > 0, t[np.maximum(first - 1, 0)], -1e18)
        gp[idx] = np.minimum(out.loc[idx, "t_first"].to_numpy() - prev, CAP)
    out["n_10s"], out["n_60s"], out["gap_prev"] = n10, n60, gp
    return out
