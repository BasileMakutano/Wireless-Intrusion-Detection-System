# Local Wi-Fi WIDS (Random Forest + Flask dashboard)
1. `pip install -r requirements.txt`
2. Train: `python train.py Aassociation-Disassociation_Dataset.csv` (writes model.joblib, metrics.json, confusion_matrix.png).
   The CSV needs columns @timestamp, mac_address, association, dataType (normal/attack).
3. Run: `python app.py` then open http://127.0.0.1:5000
   - PCAP replay: choose "PCAP replay", enter the pcap path.
   - Live: put the adapter in monitor mode, then `sudo python app.py` and enter the interface:
     `sudo ip link set wlan0 down && sudo iw wlan0 set monitor control && sudo ip link set wlan0 up`
     `sudo iw dev wlan0 set channel 6`
4. Lab attack (ONLY your own AP/clients): `sudo aireplay-ng --deauth 0 -a <AP_MAC> wlan0`
Alerts are appended to alerts.csv.

## How the features work
The dataset only has association/disassociation events, so the model uses event timing per device: counts per second, shortest gap, counts over the last 10/60 s and time since the previous event. Live capture converts association, reassociation, disassociation and deauth frames into the same events, so training and live detection use identical features.

## Attack types the system recognises

The training data only contains one attack pattern (disconnect floods), so only that one is detected by the trained Random Forest. Two more are detected with simple, explainable threshold rules built on the same features, described on the poster and in the Model view of the dashboard:

| Type | How it's detected | Severity |
|---|---|---|
| Deauthentication / disassociation flood | Random Forest (trained) | Critical |
| Association flood | Random Forest flags the burst by volume, then a rule relabels it when the burst is mostly *connects* (`dis_ratio <= 0.25`, `n_events >= 12`/s), since the model alone can't tell direction apart from volume | High |
| Broadcast deauth (multi-victim) | Rule: 4+ distinct devices disconnect within the same one-second window, network-wide | Critical |

## Simulating all three attacks

Run `python make_demo.py Aassociation-Disassociation_Dataset.csv` to build four replay files:
- `demo_deauth.csv` — a real attack burst from the dataset, between normal traffic.
- `demo_assoc_flood.csv` — a synthetic connect-request flood (the dataset has no real example of this attack, so it is generated to match the pattern described on the poster).
- `demo_broadcast.csv` — the real attack burst replayed across 5 devices at once, which is what a flood aimed at the access point looks like on the wire.
- `demo_mixed.csv` — all three back to back, for a single end-to-end demo run.

In the dashboard, choose **Replay**, pick one of these files, and press Start.

For a live demo on your own lab access point only:
```bash
# Deauth flood (single victim)
sudo aireplay-ng --deauth 0 -a <AP_MAC> -c <CLIENT_MAC> wlan0mon
# Broadcast deauth (all clients — just omit -c)
sudo aireplay-ng --deauth 0 -a <AP_MAC> wlan0mon
# Association flood (needs mdk4: sudo apt install mdk4)
sudo mdk4 wlan0mon a -a <AP_MAC>
```
