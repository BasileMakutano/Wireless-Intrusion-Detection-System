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
