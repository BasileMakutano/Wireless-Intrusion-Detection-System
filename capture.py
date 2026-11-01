"""Frame sources for the multi-class detector: live monitor-mode sniffing, pcap replay, or
replay of a small rich-CSV demo file (t, sa, ftype, fsubtype, protected, len, rssi -- the same
schema features.py expects), all via scapy (and pandas for the CSV case)."""
import queue, threading, time
from scapy.all import sniff, PcapReader, RadioTap, Dot11

def parse(p):
    """One 802.11 frame -> the raw fields features.py needs, or None if not a Wi-Fi frame."""
    if not p.haslayer(Dot11): return None
    d = p[Dot11]
    if d.addr2 is None: return None   # no transmitter address (most Control frames) -> unattributable
    rssi = getattr(p[RadioTap], "dBm_AntSignal", None) if p.haslayer(RadioTap) else None
    return dict(t=float(p.time), sa=d.addr2, ftype=d.type, fsubtype=d.subtype,
                protected=int(bool(d.FCfield & 0x40)), len=len(p),
                rssi=None if rssi is None else float(rssi))

def live_frames(iface, stop):
    q = queue.Queue()
    def work():
        sniff(iface=iface, store=False, prn=lambda p: q.put(parse(p)), stop_filter=lambda p: stop.is_set())
    threading.Thread(target=work, daemon=True).start()
    while not stop.is_set():
        try: f = q.get(timeout=1)
        except queue.Empty: continue
        if f: yield f

def pcap_frames(path, stop, speed=1.0):
    last = None
    for p in PcapReader(path):
        if stop.is_set(): return
        f = parse(p)
        if not f: continue
        if last is not None and speed > 0: time.sleep(min(max(f["t"] - last, 0) / speed, 0.5))
        last = f["t"]; yield f

def csv_frames(path, stop, speed=1.0):
    """Replay a small demo CSV with columns: t,sa,ftype,fsubtype,protected,len,rssi."""
    import pandas as pd
    d = pd.read_csv(path).sort_values("t")
    last = None
    for r in d.itertuples():
        if stop.is_set(): return
        if last is not None and speed > 0: time.sleep(min(max(r.t - last, 0) / speed, 0.5))
        last = r.t
        yield dict(t=r.t, sa=r.sa, ftype=r.ftype, fsubtype=r.fsubtype,
                   protected=r.protected, len=r.len, rssi=(None if pd.isna(r.rssi) else r.rssi))
