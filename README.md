# Wi-Fi Intrusion Detection System

A local tool that watches Wi-Fi management traffic and flags attacks in real time, using a
Random Forest classifier trained on the official AWID3 dataset. Everything runs on your own
machine — no traffic or data ever leaves it.

## What it detects

Five attack types, trained on real, officially-labelled AWID3 captures, plus one extra rule:

| Attack | How it's caught |
|---|---|
| Deauthentication / disassociation flood | Random Forest |
| Association / reassociation flood | Random Forest |
| Rogue access point | Random Forest |
| Evil twin | Random Forest |
| Broadcast deauth (several devices at once) | A separate rule: no single-device model can see "multiple victims in the same second," so this one checks across devices instead of within one |

On our test data the model reached **85% overall accuracy**, with deauth, reassoc and
rogue_ap all scoring 0.9+ precision and recall. Evil twin was the weakest class (around 0.5
precision) — see *Limitations* below for why, and `confusion_matrix.png` / `metrics.json` for
the full breakdown.

**Out of scope:** Krack and Kr00k (these exploit the WPA2 handshake itself, not traffic
patterns — a different kind of detector entirely) and the application-layer attacks AWID3 also
includes (SQL injection, SSH, malware, botnet, SSDP, website spoofing) — those aren't
Wi-Fi-layer attacks, they just happen to have been captured over Wi-Fi, and would need payload
inspection rather than a WIDS.

## How it works

1. **`extract_awid3.py`** reads the raw AWID3 pcaps with tshark and labels each frame using
   the dataset authors' own published ground truth (a frame-number range and a frame-pattern
   filter, per attack — see their site for the originals). This step only needs to run once.
2. **`build_training.py`** turns millions of individual frames into one row per device per
   second — counts, frame types, how much traffic was unprotected, frame length and signal
   stats. That's the unit the model actually learns from.
3. **`train_v2.py`** trains the Random Forest on those rows and reports accuracy, a confusion
   matrix, and per-class precision/recall.
4. **`capture.py` + `engine.py` + `app.py`** are the live system: they read traffic (from a
   file or a monitor-mode adapter), compute the same per-second features, run them through the
   trained model, and raise alerts. **`templates/index.html`** is the dashboard.

Live detection uses the exact same feature code (`features.py`) as training, so there's no
mismatch between what the model learned and what it sees at runtime.

## Running it

```bash
pip install -r requirements.txt

# one-time setup, only if you're rebuilding the model from the raw AWID3 pcaps:
python extract_awid3.py --deauth "..." --disass "..." --reassoc "..." --rogue_ap "..." --evil_twin "..." --out awid3_frames_all.csv
python build_training.py awid3_frames_all.csv --out awid3_train.csv
python train_v2.py awid3_train.csv

# generate files you can replay without any hardware:
python make_demo.py awid3_frames_all.csv

# run the dashboard:
python app.py
# open http://127.0.0.1:5000
```

In the dashboard, choose **Replay**, pick one of the `demo_*.csv` files, and press Start.
For a live test on your own access point, see *Simulating attacks live* below.

## Simulating attacks live (your own lab AP only)

| Attack | Command |
|---|---|
| Deauth (one victim) | `sudo aireplay-ng --deauth 0 -a <AP_MAC> -c <CLIENT_MAC> wlan0mon` |
| Broadcast deauth (all clients) | `sudo aireplay-ng --deauth 0 -a <AP_MAC> wlan0mon` (just drop `-c`) |
| Association flood | `sudo mdk4 wlan0mon a -a <AP_MAC>` |
| Rogue AP / beacon flood | `sudo mdk4 wlan0mon b -s 500` |
| Evil twin | `sudo airbase-ng -e "<real SSID>" -c <channel> wlan0mon` (gives it a different BSSID than the real AP) |

`mdk4` isn't installed by default: `sudo apt install mdk4`.

## Limitations

- Evil twin is the weakest class (≈0.5 precision) — its ground-truth frames overlap in pattern
  with ordinary short beacons, and AWID3 only has one recording session for it, so the model
  has less to learn from and the window-level "which attack dominated this second" labelling
  is noisier here than for the others.
- `rogue_ap` (175 windows) and `reassoc` (260 windows) are small classes — their test-set
  numbers are based on only a few dozen held-out examples each, so treat those scores as
  indicative, not precise.
- The model was trained on one physical testbed's traffic; a different network's normal
  traffic may look different enough to shift the false-alarm rate.
- Blocking in the dashboard only logs a MAC address — it doesn't enforce anything on the
  access point. A real WIPS would need that extra step.

## Use of AI tools

I used Claude (Anthropic) as a coding assistant throughout — to draft the Flask dashboard, the
feature-extraction and training scripts, and to debug issues along the way (including two real
bugs in the AWID3 frame-labelling logic, caught by checking the extracted label counts rather
than trusting the first result). I chose the project's scope, the dataset, the features, and
every design decision described above; I ran and tested the code myself on my own machine, and
I can explain how each part works. All traffic capture and simulated attacks were run only
against the AWID3 dataset or my own authorised lab network.
