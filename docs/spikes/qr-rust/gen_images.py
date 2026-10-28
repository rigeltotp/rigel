# SPDX-License-Identifier: GPL-3.0-or-later
# Synthetic QR test images for the qr-rust spike. Fake seeds only.
import base64, json, os, random, sys
import numpy as np, qrcode
from PIL import Image, ImageDraw, ImageFilter

out = sys.argv[1]
rng = random.Random(20261028)
nrng = np.random.default_rng(20261028)
os.makedirs(out, exist_ok=True)

def b32(n):
    return base64.b32encode(bytes(rng.getrandbits(8) for _ in range(n))).decode().rstrip("=")

def payload(kind):
    if kind == "short":
        return f"otpauth://totp/Example:alice%40example.com?secret={b32(10)}&issuer=Example"
    if kind == "medium":
        return f"otpauth://totp/Example%20Bank:alice.smith%40example.com?secret={b32(20)}&issuer=Example%20Bank&algorithm=SHA256&digits=8&period=30"
    if kind == "long":
        return (f"otpauth://totp/Example%20Corporation%20Ltd:alice.smith%2Bwork%40example.com?secret={b32(64)}"
                "&issuer=Example%20Corporation%20Ltd&algorithm=SHA512&digits=8&period=60"
                "&image=https%3A%2F%2Fexample.com%2Fstatic%2Fimages%2Flogos%2Fexample-corporation-logo-512.png")
    raw = base64.b64encode(bytes(rng.getrandbits(8) for _ in range(420))).decode()
    return "otpauth-migration://offline?data=" + raw.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")

ECC = {"L": qrcode.constants.ERROR_CORRECT_L, "M": qrcode.constants.ERROR_CORRECT_M,
       "Q": qrcode.constants.ERROR_CORRECT_Q, "H": qrcode.constants.ERROR_CORRECT_H}

def qr(data, ecc, box, border):
    q = qrcode.QRCode(error_correction=ECC[ecc], box_size=box, border=border)
    q.add_data(data); q.make(fit=True)
    return q.make_image(fill_color="black", back_color="white").convert("L")

def clutter(img, dark):
    d = ImageDraw.Draw(img)
    w, h = img.size
    fg = 230 if dark else 40
    for _ in range(rng.randint(6, 14)):
        x, y = rng.randint(0, w - 200), rng.randint(0, h - 40)
        d.rectangle([x, y, x + rng.randint(80, 600), y + rng.randint(8, 30)], fill=fg if rng.random() < 0.5 else 128)

manifest = []
def save(img, cat, meta, data):
    i = len(manifest)
    fmt = meta.get("fmt", "png")
    name = f"{cat}-{i:04d}.{fmt}"
    if fmt == "jpg":
        img.save(os.path.join(out, name), quality=meta["q"])
    else:
        img.save(os.path.join(out, name))
    manifest.append({"file": name, "cat": cat, "data": data, **meta})

KINDS = ["short", "medium", "long", "migration"]

# Screenshots: crisp rendering, non-integer DPI scaling, UI clutter, dark mode, PNG or JPEG.
for n in range(640):
    kind = KINDS[n % 4]
    ecc = rng.choice("LMQH")
    box = rng.choice([2, 3, 4, 6, 8])
    border = rng.choice([4, 4, 2, 1])
    dark = rng.random() < 0.25
    data = payload(kind)
    code = qr(data, ecc, box, border)
    scale = rng.uniform(0.6, 1.6)
    code = code.resize((max(1, int(code.width * scale)),) * 2, Image.BILINEAR)
    canvas = Image.new("L", (1080, 2400), 245)
    clutter(canvas, False)
    if code.width + 40 > 1080:
        scale2 = 1000 / code.width
        code = code.resize((1000, 1000), Image.BILINEAR); scale *= scale2
    canvas.paste(code, (rng.randint(20, 1080 - code.width - 20), rng.randint(300, 2400 - code.width - 300)))
    if dark:
        canvas = Image.eval(canvas, lambda v: 255 - v)
    fmt = "jpg" if rng.random() < 0.3 else "png"
    save(canvas, "screenshot", {"kind": kind, "ecc": ecc, "box": box, "border": border, "scale": round(scale, 3),
                                "module_px": round(box * scale, 2), "dark": dark, "fmt": fmt, "q": 70}, data)

def perspective_coeffs(src, dst):
    a = []
    for (x, y), (u, v) in zip(dst, src):
        a.append([x, y, 1, 0, 0, 0, -u * x, -u * y]); a.append([0, 0, 0, x, y, 1, -v * x, -v * y])
    b = np.array(src).reshape(8)
    return np.linalg.solve(np.array(a, dtype=float), b).tolist()

# Camera-like frames: perspective, rotation, blur, noise, uneven light, low contrast, JPEG.
for n in range(640):
    kind = KINDS[n % 4]
    ecc = rng.choice("LMQH")
    data = payload(kind)
    code = qr(data, ecc, 8, 4)
    W, H = 1280, 720
    frac = rng.uniform(0.2, 0.65)
    side = int(H * frac)
    code = code.resize((side, side), Image.BILINEAR).rotate(rng.uniform(0, 360), Image.BILINEAR, expand=True, fillcolor=255)
    bg = Image.fromarray(np.clip(nrng.normal(150, 25, (H, W)), 0, 255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(3))
    page = Image.new("L", (code.width + 40, code.height + 40), 235)
    page.paste(code, (20, 20))
    x0, y0 = rng.randint(0, max(0, W - page.width)), rng.randint(0, max(0, H - page.height))
    if page.width > W or page.height > H:
        continue
    bg.paste(page, (x0, y0))
    tilt = rng.uniform(0, 0.25)
    pts = [(0, 0), (W, 0), (W, H), (0, H)]
    dst = [(x + rng.uniform(-tilt, tilt) * W * 0.5, y + rng.uniform(-tilt, tilt) * H * 0.5) for x, y in pts]
    img = bg.transform((W, H), Image.PERSPECTIVE, perspective_coeffs(pts, dst), Image.BILINEAR, fillcolor=90)
    blur = rng.choice([0, 0.5, 1.0, 1.5, 2.0, 2.5])
    if blur:
        img = img.filter(ImageFilter.GaussianBlur(blur))
    arr = np.asarray(img, dtype=float)
    contrast = rng.uniform(0.35, 1.0)
    grad = np.linspace(rng.uniform(-60, 0), rng.uniform(0, 60), W)[None, :]
    noise = rng.choice([0, 5, 10, 20])
    arr = (arr - 128) * contrast + 128 + grad + nrng.normal(0, noise, arr.shape)
    img = Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8))
    q = rng.choice([40, 60, 85])
    save(img, "camera", {"kind": kind, "ecc": ecc, "frac": round(frac, 2), "tilt": round(tilt, 3), "blur": blur,
                         "contrast": round(contrast, 2), "noise": noise, "fmt": "jpg", "q": q}, data)

json.dump(manifest, open(os.path.join(out, "manifest.json"), "w"), indent=0)
print(len(manifest), "images")
