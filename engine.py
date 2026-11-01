"""Detection engine. Each second: build per-device features -> multi-class Random Forest ->
alert for any non-"normal" prediction. One extra rule sits on top, network-wide rather than
per-device: a broadcast deauth (several different devices disconnected in the same second),
which a single-device classifier structurally cannot see.
"""
import csv, os, threading, time, joblib, pandas as pd
from features import window_features, FEATS
from capture import live_frames, pcap_frames, csv_frames

BCAST_MIN_DEVICES = 4

TYPES = {
    "deauth":    dict(label="Deauthentication / disassociation flood", severity="critical",
                       what="This device is sending a burst of forged disconnect messages. Normal devices send at most a handful per minute, so others may be repeatedly kicked off Wi-Fi.",
                       actions=["Record the device MAC and start time.", "Check whether the MAC is your own access point; floods usually spoof it.",
                                "Turn on WPA3 or 802.11w (protected management frames).", "In live mode, triangulate the signal source."]),
    "reassoc":   dict(label="Association / reassociation flood", severity="high",
                       what="This device is flooding connection requests (or short beacon-like frames), which can exhaust an access point's connection table and deny service to real devices.",
                       actions=["Confirm the access point's connection table isn't full.", "Rate-limit or blocklist the source MAC.",
                                "Check for identical, scripted-looking requests."]),
    "rogue_ap":  dict(label="Rogue access point", severity="high",
                       what="This device is broadcasting beacon frames that look wrong for a real access point (abnormally short), a sign of a fake or misconfigured AP nearby.",
                       actions=["Compare the beacon's SSID and BSSID against your known access points.", "Walk down and physically locate unexpected hardware if possible.",
                                "Warn users not to connect to unfamiliar networks with a familiar name."]),
    "evil_twin": dict(label="Evil twin", severity="critical",
                       what="This device is impersonating a legitimate access point (short beacons and/or unprotected disconnect-type frames together), trying to lure clients into connecting to it instead of the real network.",
                       actions=["Check whether this BSSID matches your real access point's known MAC.", "Warn users to verify they're on the genuine network before entering credentials.",
                                "Enable 802.11w so clients can tell forged management frames from real ones."]),
    "bcast":     dict(label="Broadcast deauth (multi-victim)", severity="critical",
                       what="Several devices were disconnected in the same second. A single victim being dropped can be a coincidence; several at once is the signature of a flood aimed at the access point itself.",
                       actions=["Check the access point's own logs for a mass disconnect.", "This usually can't be blocked by MAC alone, since it targets the AP's broadcast address.",
                                "Protected management frames (802.11w) are the main defence."]),
}

class Engine:
    def __init__(self, model_path="model.joblib", classes_path="classes.joblib"):
        self.model = joblib.load(model_path) if os.path.exists(model_path) else None
        self.classes = joblib.load(classes_path) if os.path.exists(classes_path) else None
        self.blocked, self.auto_block = {}, False
        self.reset()

    def reset(self):
        self.running = False; self.error = None; self.history = []; self.alerts = []
        self.total = 0; self.stop_evt = threading.Event()
        self.incidents, self.open, self.cur_ws = [], {}, 0

    def start(self, mode, src, speed=1.0):
        if self.running: return
        if self.model is None or self.classes is None:
            self.error = "No model.joblib/classes.joblib - run train_v2.py first (see README)"; return
        self.reset(); self.running = True
        threading.Thread(target=self._run, args=(mode, src, speed), daemon=True).start()

    def stop(self): self.stop_evt.set()

    def _run(self, mode, src, speed):
        try:
            if mode == "live": frames = live_frames(src, self.stop_evt)
            elif str(src).endswith(".csv"): frames = csv_frames(src, self.stop_evt, speed)
            else: frames = pcap_frames(src, self.stop_evt, speed)
            buf, ws = [], None
            for f in frames:
                if ws is None: ws = int(f["t"])
                if f["t"] >= ws + 1: self._flush(buf, ws); buf, ws = [], int(f["t"])
                buf.append(f)
            if buf: self._flush(buf, ws)
        except Exception as e: self.error = str(e)
        self.running = False

    def _flush(self, buf, ws):
        df = pd.DataFrame(buf)
        W = window_features(df)
        self.total += len(buf); self.cur_ws = ws
        hits = []
        if not W.empty:
            proba = self.model.predict_proba(W[FEATS])
            pred_idx = proba.argmax(axis=1)
            pred = [self.classes[i] for i in pred_idx]
            conf = proba.max(axis=1)
            for (_, r), p, c in zip(W.iterrows(), pred, conf):
                if p != "normal":
                    hits.append((p, r.sa, round(float(c), 3), int(r.n_deauth_disassoc), int(r.n_frames)))
            # Broadcast deauth: several DIFFERENT devices showing deauth/disassoc frames
            # in this same one-second window -- a network-wide pattern no per-device
            # classifier row can see on its own.
            dd = W[W.n_deauth_disassoc > 0]
            if len(dd) >= BCAST_MIN_DEVICES:
                hits.append(("bcast", ",".join(sorted(dd.sa.astype(str))),
                             round(min(1.0, len(dd) / 10), 3), int(dd.n_deauth_disassoc.sum()), int(dd.n_frames.sum())))
        self.history.append(dict(t=ws, frames=len(buf),
                                  deauth=int(W.n_deauth_disassoc.sum()) if not W.empty else 0,
                                  alert=int(bool(hits))))
        self.history = self.history[-120:]
        for atype, mac, conf, ndis, nev in hits:
            a = dict(time=time.strftime("%H:%M:%S"), mac=mac, type=atype, label=TYPES[atype]["label"],
                     deauth=ndis, frames=nev, conf=conf)
            self.alerts.insert(0, a); self.alerts = self.alerts[:200]
            self._incident(a, ws)
            new = not os.path.exists("alerts.csv")
            with open("alerts.csv", "a", newline="") as f:
                w = csv.DictWriter(f, a.keys())
                if new: w.writeheader()
                w.writerow(a)

    def _incident(self, a, ws):
        key = (a["mac"], a["type"])
        inc = self.open.get(key)
        if inc is None or ws - inc["last"] > 10:
            inc = dict(mac=a["mac"], type=a["type"], label=a["label"], severity=TYPES[a["type"]]["severity"],
                       start=ws, first=a["time"], last=ws, peak=0, alerts=0, events=0, conf=0.0)
            self.open[key] = inc; self.incidents.append(inc)
        inc["last"] = ws; inc["peak"] = max(inc["peak"], a["deauth"]); inc["alerts"] += 1
        inc["events"] += a["frames"]; inc["conf"] = max(inc["conf"], a["conf"])
        if self.auto_block and a["type"] != "bcast" and a["mac"] not in self.blocked:
            self.block(a["mac"], f"auto-block ({a['label']})")

    def block(self, mac, reason="manual"):
        if mac in self.blocked: return
        b = dict(mac=mac, time=time.strftime("%H:%M:%S"), reason=reason); self.blocked[mac] = b
        new = not os.path.exists("blocked.csv")
        with open("blocked.csv", "a", newline="") as f:
            w = csv.DictWriter(f, b.keys())
            if new: w.writeheader()
            w.writerow(b)

    def unblock(self, mac): self.blocked.pop(mac, None)

    def state(self):
        return dict(running=self.running, error=self.error, total=self.total,
                    history=self.history, alerts=self.alerts[:100], auto_block=self.auto_block,
                    blocked=list(self.blocked.values()),
                    incidents=[dict(i, duration=i["last"] - i["start"] + 1, active=self.running and self.cur_ws - i["last"] <= 5)
                               for i in reversed(self.incidents)][:30])
