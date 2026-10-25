"""Frame sources: live monitor-mode sniffing or pcap replay (both via scapy)."""
import queue, threading, time, numpy as np
from scapy.all import sniff, PcapReader, RadioTap, Dot11

def parse(p):
    if not p.haslayer(Dot11): return None
    d = p[Dot11]
    rssi = getattr(p[RadioTap], "dBm_AntSignal", None) if p.haslayer(RadioTap) else None
    return dict(t=float(p.time), ta=d.addr2, ra=d.addr1, type=d.type, subtype=d.subtype,
                rssi=np.nan if rssi is None else rssi, len=len(p))

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
