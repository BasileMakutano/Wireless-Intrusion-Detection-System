"""Frame sources: live monitor-mode sniffing or pcap replay (both via scapy)."""
import queue, threading, time
from scapy.all import sniff, PcapReader, Dot11

ASSOC = {0, 1, 2, 3}      # association / reassociation request + response
DISASSOC = {10, 12}       # disassociation, deauthentication

def parse(p):
    """Convert a Wi-Fi frame into an event matching the training data, or None if irrelevant."""
    if not p.haslayer(Dot11): return None
    d = p[Dot11]
    if d.type != 0 or not d.addr2 or d.subtype not in ASSOC | DISASSOC: return None
    return dict(t=float(p.time), dev=d.addr2, dis=int(d.subtype in DISASSOC))

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
