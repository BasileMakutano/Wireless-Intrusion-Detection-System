"""Detection engine: 1-second windows -> features -> model -> alerts (logged to alerts.csv)."""
import csv, os, threading, time, joblib, pandas as pd
from features import window_features, FEATS, CAP
from capture import live_frames, pcap_frames

class Engine:
    def __init__(self, model_path="model.joblib"):
        self.model = joblib.load(model_path) if os.path.exists(model_path) else None
        self.reset()

    def reset(self):
        self.running = False; self.error = None; self.history = []; self.alerts = []
        self.total = 0; self.stop_evt = threading.Event()

    def start(self, mode, src, speed=1.0):
        if self.running: return
        if self.model is None: self.error = "No model.joblib - run train.py first"; return
        self.reset(); self.running = True
        threading.Thread(target=self._run, args=(mode, src, speed), daemon=True).start()

    def stop(self): self.stop_evt.set()

    def _run(self, mode, src, speed):
        try:
            frames = live_frames(src, self.stop_evt) if mode == "live" else pcap_frames(src, self.stop_evt, speed)
            buf, ws, self.recent = [], None, []
            for f in frames:
                if ws is None: ws = int(f["t"])
                if f["t"] >= ws + 1: self._flush(buf, ws); buf, ws = [], int(f["t"])
                buf.append(f)
            if buf: self._flush(buf, ws)
        except Exception as e: self.error = str(e)
        self.running = False

    def _flush(self, buf, ws):
        """Score one second of events, using the last 60 s of history for context."""
        self.recent = [r for r in self.recent if r["t"] > ws + 1 - CAP] + buf
        W = window_features(pd.DataFrame(self.recent))
        W = W[W.w == ws]
        if W.empty: return
        W = W.assign(pred=self.model.predict(W[FEATS]), conf=self.model.predict_proba(W[FEATS])[:, 1])
        self.total += len(buf)
        self.history.append(dict(t=ws, frames=len(buf), deauth=int(sum(r["dis"] for r in buf)), alert=int(W.pred.sum() > 0)))
        self.history = self.history[-120:]
        for _, r in W[W.pred == 1].iterrows():
            a = dict(time=time.strftime("%H:%M:%S"), mac=r.dev, type="Deauth/disassoc flood", deauth=int(r.n_dis),
                     frames=int(r.n_events), conf=round(float(r.conf), 3))
            self.alerts.insert(0, a); self.alerts = self.alerts[:200]
            new = not os.path.exists("alerts.csv")
            with open("alerts.csv", "a", newline="") as f:
                w = csv.DictWriter(f, a.keys())
                if new: w.writeheader()
                w.writerow(a)

    def state(self):
        return dict(running=self.running, error=self.error, total=self.total,
                    history=self.history, alerts=self.alerts[:50])
