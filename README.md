# Local Wi-Fi WIDS (Random Forest + Flask dashboard)
1. `pip install -r requirements.txt`
2. Train: `python train.py path/to/awid3_deauth.csv` (writes model.joblib, metrics.json, confusion_matrix.png).
   Use a CSV containing both Normal and Deauth rows. If columns differ, edit COLS in train.py.
3. Run: `python app.py` then open http://127.0.0.1:5000
   - PCAP replay: choose "PCAP replay", enter the pcap path.
   - Live: put the adapter in monitor mode, then `sudo python app.py` and enter the interface:
     `sudo ip link set wlan0 down && sudo iw wlan0 set monitor control && sudo ip link set wlan0 up`
     `sudo iw dev wlan0 set channel 6`
4. Lab attack (ONLY your own AP/clients): `sudo aireplay-ng --deauth 0 -a <AP_MAC> wlan0`
Alerts are appended to alerts.csv.
