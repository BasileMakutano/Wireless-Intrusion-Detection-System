"""Builds poster.pdf (A1 portrait). Edit the CONFIG block, then: python make_poster.py
Needs: pip install reportlab   |   reads metrics.json and timeline_demo.json"""
import json
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor as C
from reportlab.platypus import Paragraph
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm

CONFIG = dict(NAME="YOUR NAME", ID="Student No. 000000", COURSE="Course name and code",
              UNI="University / Department", REPO="github.com/BasileMakutano/Wireless-Intrusion-Detection-System")
W, H = 594 * mm, 841 * mm
INK, MUTE, BLUE, NAVY = C("#14212b"), C("#586875"), C("#1b5fd1"), C("#0f2a44")
GOOD, GOODBG, BAD, BADBG, PANEL, LINE = C("#0b7a6c"), C("#d9f0ec"), C("#c4202f"), C("#fbe1e3"), C("#eef2f5"), C("#d5dde4")
M = json.load(open("metrics.json")); TL = json.load(open("timeline_demo.json"))
cm = M["confusion_matrix"]; tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
rec, pre = tp / (tp + fn) * 100, tp / (tp + fp) * 100

def st(size, color=INK, bold=False, lead=None, **k):
    return ParagraphStyle("s", fontName="Helvetica-Bold" if bold else "Helvetica", fontSize=size, leading=lead or size * 1.3, textColor=color, **k)

c = canvas.Canvas("poster.pdf", pagesize=(W, H)); c.setTitle("WIDS poster")

class Col:
    def __init__(s, x, top, w): s.x, s.y, s.w = x, top, w
    def h(s, t, color=BLUE):
        c.setFillColor(color); c.rect(s.x, s.y - 46, 12, 46, fill=1, stroke=0)
        c.setFont("Helvetica-Bold", 40); c.drawString(s.x + 28, s.y - 36, t); s.y -= 72
    def p(s, t, size=24, color=INK, gap=14, bullet=None):
        p = Paragraph(t, st(size, color, leftIndent=26 if bullet else 0, bulletIndent=0, bulletFontSize=size), bulletText=bullet)
        _, h = p.wrap(s.w, 9999); p.drawOn(c, s.x, s.y - h); s.y -= h + gap
    def bl(s, items, size=24):
        for t in items: s.p(t, size, bullet="\u2022", gap=10)

# ---------- header ----------
c.setFillColor(NAVY); c.rect(0, H - 410, W, 410, fill=1, stroke=0)
c.setFillColor(BLUE); c.rect(0, H - 418, W, 8, fill=1, stroke=0)
t = Paragraph("Detecting Wi-Fi Deauthentication Floods with Machine Learning", st(72, C("#ffffff"), True, 80))
_, th = t.wrap(1100, 999); t.drawOn(c, 60, H - 60 - th)
sub = Paragraph("A local wireless intrusion detection system (WIDS) using a Random Forest classifier and a live dashboard", st(30, C("#b9c8d8")))
_, sh = sub.wrap(1150, 99); sub.drawOn(c, 60, H - 60 - th - 22 - sh)
a = Paragraph(f"<b>{CONFIG['NAME']}</b><br/>{CONFIG['ID']}<br/>{CONFIG['COURSE']}<br/>{CONFIG['UNI']}", st(28, C("#ffffff"), lead=40))
_, ah = a.wrap(420, 999); a.drawOn(c, W - 60 - 420, H - 60 - ah)

MG, GAP = 60, 44; CW = (W - 2 * MG - 2 * GAP) / 3; TOP = H - 410 - 56
X = [MG + i * (CW + GAP) for i in range(3)]
c1, c2, c3 = Col(X[0], TOP, CW), Col(X[1], TOP, CW), Col(X[2], TOP, CW)

# ---------- column 1: problem + design ----------
c1.h("The problem")
c1.p("Wi-Fi management messages are not authenticated. An attacker can forge <b>deauthentication</b> messages and repeatedly disconnect any device from its network. "
     "WPA3 and 802.11w help, but many networks still lack them.", gap=22)
c1.h("How the system works")
steps = ["Traffic source: dataset, pcap or live adapter", "Events: device, time, connect or disconnect",
         "One-second windows per device", "7 timing features per window", "Random Forest (100 trees)", "Alert, alerts.csv and dashboard"]
bh, gp = 60, 26
for i, s_ in enumerate(steps):
    y = c1.y - bh
    c.setFillColor(BLUE if i in (4,) else PANEL); c.setStrokeColor(LINE); c.roundRect(c1.x, y, CW, bh, 10, fill=1, stroke=1)
    c.setFillColor(C("#ffffff") if i == 4 else INK); c.setFont("Helvetica-Bold" if i == 4 else "Helvetica", 23)
    c.drawCentredString(c1.x + CW / 2, y + 21, s_)
    if i < len(steps) - 1:
        c.setFillColor(MUTE); ax = c1.x + CW / 2; c.setStrokeColor(MUTE); c.setLineWidth(3); c.line(ax, y, ax, y - gp + 8)
        c.path = c.beginPath(); c.path.moveTo(ax - 9, y - gp + 16); c.path.lineTo(ax + 9, y - gp + 16); c.path.lineTo(ax, y - gp + 4); c.path.close(); c.drawPath(c.path, fill=1, stroke=0)
    c1.y -= bh + gp
c1.y -= 4
c1.h("The 7 features")
feats = [("Events / second", "activity of one device"), ("Disconnects / second", "deauth + disassoc count"), ("Disconnect share", "disconnects / events"),
         ("Shortest gap", "attacks: milliseconds"), ("Events, last 10 s", "short burst"), ("Events, last 60 s", "longer activity"), ("Time since last event", "normal: long quiet")]
for i, (a_, b_) in enumerate(feats):
    y = c1.y - 46
    if i % 2 == 0: c.setFillColor(PANEL); c.rect(c1.x, y, CW, 46, fill=1, stroke=0)
    c.setFillColor(INK); c.setFont("Helvetica-Bold", 20); c.drawString(c1.x + 10, y + 15, a_)
    c.setFillColor(MUTE); c.setFont("Helvetica", 19); c.drawRightString(c1.x + CW - 10, y + 15, b_)
    c1.y -= 46

# ---------- column 2: data + model ----------
c2.h("The data")
stats = [("376,429", "association events"), ("16", "devices"), ("149,008", "device-seconds"), ("16,596", "attack seconds")]
bw = (CW - 18) / 2
for i, (n_, l_) in enumerate(stats):
    x, y = c2.x + (i % 2) * (bw + 18), c2.y - 100 - (i // 2) * 116
    c.setFillColor(PANEL); c.roundRect(x, y, bw, 100, 12, fill=1, stroke=0)
    c.setFillColor(BLUE); c.setFont("Helvetica-Bold", 50); c.drawCentredString(x + bw / 2, y + 46, n_)
    c.setFillColor(MUTE); c.setFont("Helvetica", 23); c.drawCentredString(x + bw / 2, y + 18, l_)
c2.y -= 2 * 116 + 12
c2.p("<b>Key finding:</b> a normal device connects or disconnects at most once per second (about once every 105 s on average). An attacking device sends up to <b>335 events in one second</b>.", gap=18)
# comparison bars
for lbl, val, col, txt in [("Normal device", 1, GOOD, "1 event / second max"), ("Under attack", 335, BAD, "335 events / second max")]:
    c.setFillColor(INK); c.setFont("Helvetica-Bold", 22); c.drawString(c2.x, c2.y - 22, lbl)
    L = CW - 6; c.setFillColor(LINE); c.rect(c2.x, c2.y - 58, L, 24, fill=1, stroke=0)
    c.setFillColor(col); c.rect(c2.x, c2.y - 58, max(8, L * val / 335), 24, fill=1, stroke=0)
    c.setFillColor(MUTE); c.setFont("Helvetica", 20); c.drawRightString(c2.x + L, c2.y - 22, txt); c2.y -= 82
c2.y -= 10
c2.h("The model")
c2.p("A <b>Random Forest</b> is 100 decision trees that each look at the 7 features and vote. It is a ready-made scikit-learn classifier that labels each device-second as normal or malicious.", gap=12)
c2.bl(["Class-balanced, because attacks are rarer.", f"Split by whole hour blocks: {M['n_train']:,} train, {M['n_test']:,} test windows, so no leakage between neighbouring seconds."])
c2.y -= 6
c2.h("The dashboard")
c2.bl(["Live status, event chart and alert log (MAC, severity, confidence)", "Replays a dataset or watches a live monitor-mode adapter"])

# ---------- column 3: results ----------
c3.h("Results", GOOD)
c.setFillColor(GOOD); c.setFont("Helvetica-Bold", 120); c.drawString(c3.x, c3.y - 96, f"{M['accuracy']*100:.2f}%")
c.setFillColor(MUTE); c.setFont("Helvetica", 24); c.drawString(c3.x, c3.y - 130, f"accuracy on {M['n_test']:,} unseen test windows"); c3.y -= 168
c.setFillColor(INK); c.setFont("Helvetica-Bold", 28); c.drawString(c3.x, c3.y - 24, "Confusion matrix"); c3.y -= 44
lw = 170; cw_ = (CW - lw - 12) / 2; chh = 128
c.setFillColor(MUTE); c.setFont("Helvetica", 20)
c.drawCentredString(c3.x + lw + cw_ / 2, c3.y - 20, "Predicted normal"); c.drawCentredString(c3.x + lw + 12 + cw_ * 1.5, c3.y - 20, "Predicted attack"); c3.y -= 30
cells = [[(tn, "Correctly ignored", GOODBG, GOOD), (fp, "False alarms", BADBG, BAD)], [(fn, "Missed attacks", BADBG, BAD), (tp, "Attacks caught", GOODBG, GOOD)]]
for r, rl in enumerate(["Actually normal", "Actually attack"]):
    y = c3.y - chh
    c.setFillColor(MUTE); c.setFont("Helvetica", 20); c.drawString(c3.x, y + chh / 2 - 6, rl)
    for k, (v, lab, bg, fg) in enumerate(cells[r]):
        x = c3.x + lw + k * (cw_ + 12); c.setFillColor(bg); c.roundRect(x, y, cw_, chh, 10, fill=1, stroke=0)
        c.setFillColor(fg); c.setFont("Helvetica-Bold", 44); c.drawCentredString(x + cw_ / 2, y + 62, f"{v:,}"); c.setFont("Helvetica", 20); c.drawCentredString(x + cw_ / 2, y + 28, lab)
    c3.y -= chh + 10
c3.y -= 8
for lbl, v in [("Recall (attacks caught)", rec), ("Precision (alerts that were real)", pre)]:
    c.setFillColor(INK); c.setFont("Helvetica", 22); c.drawString(c3.x, c3.y - 20, lbl); c.setFont("Helvetica-Bold", 22); c.drawRightString(c3.x + CW, c3.y - 20, f"{v:.1f}%")
    c.setFillColor(LINE); c.rect(c3.x, c3.y - 40, CW, 12, fill=1, stroke=0); c.setFillColor(BLUE); c.rect(c3.x, c3.y - 40, CW * v / 100, 12, fill=1, stroke=0); c3.y -= 62
c3.y -= 8
c.setFillColor(INK); c.setFont("Helvetica-Bold", 28); c.drawString(c3.x, c3.y - 24, "What the model relies on"); c3.y -= 46
NM = {"n_60s": "Events, last 60 s", "n_10s": "Events, last 10 s", "gap_prev": "Time since last event", "n_events": "Events this second", "min_gap": "Shortest gap", "n_dis": "Disconnects this second", "dis_ratio": "Disconnect share"}
imp = sorted(M["importances"].items(), key=lambda kv: -kv[1])[:5]
for k, v in imp:
    c.setFillColor(INK); c.setFont("Helvetica", 21); c.drawString(c3.x, c3.y - 24, NM[k])
    bx = c3.x + 230; bl_ = CW - 230 - 70; c.setFillColor(LINE); c.rect(bx, c3.y - 28, bl_, 18, fill=1, stroke=0)
    c.setFillColor(BLUE); c.rect(bx, c3.y - 28, bl_ * v / imp[0][1], 18, fill=1, stroke=0)
    c.setFillColor(MUTE); c.drawRightString(c3.x + CW, c3.y - 24, f"{v*100:.0f}%"); c3.y -= 40
c3.y -= 14
c.setFillColor(INK); c.setFont("Helvetica-Bold", 28); c.drawString(c3.x, c3.y - 24, "Detection in a simulated attack"); c3.y -= 40
ch = 170; base = c3.y - ch; mx = max(h_["frames"] for h_ in TL); n = len(TL); bwid = CW / n
c.setFillColor(PANEL); c.rect(c3.x, base, CW, ch, fill=1, stroke=0)
for i, h_ in enumerate(TL):
    hh = max(3, (ch - 30) * h_["frames"] / mx); c.setFillColor(BAD if h_["alert"] else BLUE); c.rect(c3.x + i * bwid + 1, base, bwid - 2, hh, fill=1, stroke=0)
c.setFillColor(MUTE); c.setFont("Helvetica", 18); c.drawString(c3.x + 6, base + ch - 20, f"events per second (max {mx})"); c.drawRightString(c3.x + CW - 6, base + ch - 20, "red = alert raised")
c3.y = base - 12
c3.p("Replay of demo_attack.csv: normal traffic, a flood, then normal again. The system raised alerts on the flood seconds only.", 20, MUTE, gap=0)

# ---------- bottom strip ----------
S_TOP, S_BOT = 560, 100
c.setFillColor(PANEL); c.rect(0, S_BOT, W, S_TOP - S_BOT, fill=1, stroke=0)
b1, b2, b3 = Col(X[0], S_TOP - 36, CW), Col(X[1], S_TOP - 36, CW), Col(X[2], S_TOP - 36, CW)
b1.h("Limitations", BAD)
b1.bl(["Attack and normal captures cover different dates, so the model may partly learn each device's habits.", "Most missed attacks are single-event seconds that look normal on their own.",
       "Only deauthentication and disassociation floods are covered.", "A spoofed flood shows under the access point's MAC, not the attacker's."], 23)
b2.h("What I would improve")
b2.bl(["Add a WIPS step: log or block the offending MAC automatically.", "Test on my own live captures and report the difference.", "Detect more attacks: evil twin, beacon flood, disassociation variants.",
       "Add channel hopping and try other models such as Gradient Boosting."], 23)
b3.h("Use of AI tools")
b3.p("I used Claude (Anthropic) as a coding assistant to draft the dashboard, feature extraction and training scripts and to debug setup errors. I chose the scope, data and features, ran and tested everything myself, reviewed every file and can explain each part of the code. "
     "All work used a public dataset or an isolated lab network I am authorised to test.", 22, gap=10)
c.setFillColor(MUTE); c.setFont("Helvetica", 21)
c.drawString(60, 62, f"Code: {CONFIG['REPO']}"); c.drawRightString(W - 60, 62, "Built with Python, scikit-learn, scapy and Flask. Everything runs locally.")
c.setFont("Helvetica", 17); c.drawString(60, 34, "Dataset: association/disassociation event dataset provided for the course [add citation]")
print("column bottoms (must stay above 560):", round(c1.y), round(c2.y), round(c3.y), "| strip text bottoms:", round(b1.y), round(b2.y), round(b3.y), "(must stay above 100)")
c.save()
