# SPDX-License-Identifier: GPL-3.0-or-later
# Reference decoder (zxing-cpp, the C++ ZXing) to calibrate dataset difficulty.
import json, sys, collections
import zxingcpp
from PIL import Image, ImageOps
d = sys.argv[1]
m = json.load(open(f"{d}/manifest.json"))
stats = collections.Counter(); tot = collections.Counter()
for e in m:
    img = Image.open(f"{d}/{e['file']}").convert("L")
    res = zxingcpp.read_barcodes(img, formats=zxingcpp.BarcodeFormat.QRCode)
    if not res:
        res = zxingcpp.read_barcodes(ImageOps.invert(img), formats=zxingcpp.BarcodeFormat.QRCode)
    hit = any(r.text == e["data"] for r in res)
    for k in ["all", e["kind"]]:
        tot[(e["cat"], k)] += 1; stats[(e["cat"], k)] += hit
    with open(f"{d}/../ref_hits.txt", "a") as f:
        f.write(f"{e['file']} {int(hit)}\n")
for k in sorted(tot):
    print(k, stats[k], "/", tot[k])
