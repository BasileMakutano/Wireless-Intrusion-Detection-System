"""Build demo_attack.csv: normal traffic, then a real deauth burst from the dataset, then normal again.
Usage: python make_demo.py Aassociation-Disassociation_Dataset.csv [device1]"""
import sys, pandas as pd
src, dev = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "device1")
d = pd.read_csv(src)
d["t"] = (pd.to_datetime(d["@timestamp"].str.replace(" @ ", " "), format="%b %d, %Y %H:%M:%S.%f") - pd.Timestamp("1970-01-01")) / pd.Timedelta(seconds=1)
d = d[d.mac_address == dev].sort_values("t")
nor, att = d[d.dataType == "normal"], d[d.dataType == "attack"]
sec = att.t.astype(int).value_counts().idxmax()                  # busiest attack second
burst = att[(att.t >= sec - 5) & (att.t <= sec + 15)]
pre, post = nor.iloc[:30], nor.iloc[30:50]
t0 = pre.t.iloc[0]; parts = []
pre = pre.assign(t=pre.t - t0 + 1.7e9)
burst = burst.assign(t=burst.t - burst.t.iloc[0] + pre.t.iloc[-1] + 5)
post = post.assign(t=post.t - post.t.iloc[0] + burst.t.iloc[-1] + 5)
out = pd.concat([pre, burst, post])
out["@timestamp"] = pd.to_datetime(out.t, unit="s").dt.strftime("%b %-d, %Y @ %H:%M:%S.%f").str[:-3]
out[["@timestamp", "mac_address", "association", "dataType"]].to_csv("demo_attack.csv", index=False)
print(f"demo_attack.csv written: {len(pre)} normal, {len(burst)} attack, {len(post)} normal events")
