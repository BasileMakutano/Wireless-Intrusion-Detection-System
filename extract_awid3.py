"""Turn raw AWID3 pcaps into one labelled CSV for training, using the dataset authors' own
published ground truth (Wireshark filters + frame-number ranges for each attack file), see
https://icsdweb.aegean.gr/awid/awid3 ("Proposed Wireshark filter per attack").

Run this on YOUR machine (where the pcaps are) -- it needs tshark (installed with Wireshark).
It does NOT touch the network and only reads the files you point it at.

Usage (only pass the attacks you have; everything else is skipped):
  python extract_awid3.py \
      --deauth     "1. Deauth.pcap" \
      --disass     "2. Disass.pcap" \
      --reassoc    "3. (Re)Assoc.pcap" \
      --rogue_ap   "4. Rogue_AP.pcap" \
      --evil_twin  "7. Evil_Twin.pcap" \
      --out awid3_frames.csv

This can take a few minutes per file (they're millions of frames). It prints a label count
summary at the end -- please share that with me before we build the trainer, so we can see
whether every class has enough attack frames to learn from.

Krack, Kr00k, SQL_Injection, SSH, Malware, SSDP, Botnet and Website_spoofing are deliberately
NOT covered here -- see README.md for why (they need a different detection approach to the
rest of this project: Krack/Kr00k are crypto/handshake exploits, the others are TCP/IP or
application-layer attacks, not Wi-Fi-layer ones).
"""
import argparse, subprocess, sys
import pandas as pd

FIELDS = ["frame.number", "frame.time_epoch", "wlan.sa", "wlan.da", "wlan.bssid",
          "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.protected", "radiotap.dbm_antsignal",
          "frame.len", "wlan.ssid"]
COLS = ["num", "t", "sa", "da", "bssid", "ftype", "fsubtype", "protected", "rssi", "len", "ssid"]
# AWID3's filters use the COMBINED wlan.fc.type_subtype field, which some tshark builds
# don't populate via -e (comes back blank). So we extract type and subtype separately
# (known to work) and recompute the same combined code ourselves: type*16 + subtype.
# Checked against AWID3's own numbers: Data frame type=2, subtype=8 (QoS Data) -> 2*16+8=40,
# which matches the "40" in their Evil_Twin filter exactly.

# (frame-number range, condition on the extracted columns) from the AWID3 site, one per file.
# The wlan.addr==<attacker MAC> / ip.addr==<attacker IP> clauses the site adds for Evil_Twin are
# left out on purpose: a live detector can't know the attacker's MAC in advance, so training on
# it would teach the model to recognise one device instead of the attack pattern.
ATTACKS = {
    "deauth":    (1088022, 1626254, lambda d: d.subtype.isin([10, 12]) & (d.protected == 0)),
    "disass":    (1404237, 2013346, lambda d: d.subtype.isin([10, 12]) & (d.protected == 0)),
    "reassoc":   (1145178, 1833964, lambda d: d.subtype.isin([0, 2, 8]) & (d.len <= 301)),
    "rogue_ap":  (1198551, 1973111, lambda d: (d.subtype == 8) & (d.len < 264)),
    "evil_twin": (1420038, 3778728, lambda d: ((d.subtype == 8) & (d.len < 242)) |
                                               (d.subtype.isin([10, 12, 40]) & (d.protected == 0))),
}

def extract_one(path, label):
    print(f"[{label}] reading {path} with tshark ...", file=sys.stderr)
    cmd = ["tshark", "-r", path, "-T", "fields", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]
    for f in FIELDS: cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed on {path}:\n{proc.stderr[:2000]}")
    from io import StringIO
    d = pd.read_csv(StringIO(proc.stdout), names=COLS, header=None, dtype=str, keep_default_na=False)
    for c in ["num", "t", "ftype", "fsubtype", "protected", "rssi", "len"]:
        d[c] = pd.to_numeric(d[c], errors="coerce")
    d = d.dropna(subset=["num", "t", "ftype", "fsubtype"])
    d["subtype"] = d.ftype * 16 + d.fsubtype   # combined code, matches AWID3's filter numbers
    # tshark only prints "1" for boolean flag fields when set, and leaves the cell blank
    # (not "0") when unset -- so a blank here genuinely means "not protected", i.e. 0.
    d["protected"] = d["protected"].fillna(0)
    lo, hi, cond = ATTACKS[label]
    in_range = (d.num >= lo) & (d.num <= hi)
    d["attack"] = "normal"
    d.loc[in_range & cond(d), "attack"] = label
    print(f"[{label}] {len(d):,} frames, {in_range.sum():,} in the official frame range, "
          f"{(d.attack==label).sum():,} labelled {label}", file=sys.stderr)
    print(f"[{label}] type_subtype codes seen in that range: "
          f"{d.loc[in_range, 'subtype'].value_counts().head(8).to_dict()}", file=sys.stderr)
    return d.drop(columns=["num"])

def main():
    ap = argparse.ArgumentParser()
    for k in ATTACKS: ap.add_argument(f"--{k}")
    ap.add_argument("--out", default="awid3_frames.csv")
    a = ap.parse_args()
    frames = []
    for k in ATTACKS:
        path = getattr(a, k)
        if path: frames.append(extract_one(path, k))
    if not frames:
        print("Pass at least one of: " + ", ".join(f"--{k}" for k in ATTACKS)); return
    out = pd.concat(frames, ignore_index=True)
    out.to_csv(a.out, index=False)
    print(f"\nWrote {a.out}: {len(out):,} frames total")
    print(out.attack.value_counts().to_string())

if __name__ == "__main__":
    main()
