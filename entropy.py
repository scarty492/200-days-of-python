#!/usr/bin/env python3
"""Shannon entropy toolkit.

Entropy is just -Σ p·log2(p). Everything here is about what u do with it:
separating encrypted data from structured data, scoring a password by the search space 
it  actually lives in, and locating high- entropy regions hidden
inside an otherwise dull file.
"""

import argparse
import math
import os
import re
import sys
from collections import Counter

G, HI, DIM, RESET = "\033[32m", "\033[92m", "\033[2;32m", "\033[0m"
colour = sys.stdout.isatty() and "NO_COLOUR" not in os.environ

HIGH = 7.2
GUESS_RATE = 1e10
SPARK = " .:-=+*#@"

BANNER = r"""

 ___ _  _ _____ ___  ___  _____   __
  | __| \| |_   _| _ \/ _ \| _ \ \ / /
  | _|| .` | | | |   / (_) |  _/ \ V /
  |___|_|\_| |_| |_|_\\___/|_|    |_|
"""


def paint(text, shade=G):
    return f"{shade}{text}{RESET}" if colour else text

def row(label, value):
    print(f" {paint(f'{label:<12}', DIM)}{value}")

def entropy(data):
    n = len(data)
    if not n:
        return 0.0
    return -sum((k / n) * math.log2(k / n) for k in Counter(data).values())

def bar(value, ceiling, width=42):
    r = min(1.0, value / ceiling) if ceiling else 0.0
    fill = round(r * width)
    shade = HI if r > 0.85 else  G if r >  0.5 else DIM
    return paint(f"[{'#' * fill}{'-' * (width - fill)}]", shade) + paint(f" {r * 100:3.0f}%", shade)

def spark(value, ceiling=8.0):
    top = len(SPARK) - 1
    return "".join(SPARK[min(top, int(v / ceiling * top))] for v in value)

def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()

def reads_as(h):
    # data-driven instread. of an if-ladder; first threshold that fits wins
    for limit, label in [(1, "single-byte runs - padding or zero-fill"),
                         (2, "structured - text, config, headers"),
                         (5, "natural language, source, markup"),
                         (6.5, "mixed binary or light compression"),
                         (HIGH, "compressed / encoded - zip, jpeg, base64")]:
        if h < limit:
            return label
    return "encrypted or random"

def human_time(secs):
    if secs < 1:
        return "instantly"
    for unit, size in (("yr", 31_536_000), ("d", 86_400), ("h", 3_600), ("m", 60), ("s", 1)):
        if secs >= size:
            v = secs / size
            return f"{v:.0e} {unit}" if v >= 1e6 else f"{v:.0f}{unit}"

# password strength is a search-space question, not a Shannon one ---------------------------

def pool_size(pw):
    size = 0
    if any(c.islower() for c in pw): size += 26
    if any(c.isupper() for c in pw): size += 26
    if any(c.isdigit() for c in pw): size += 10
    if any(not c.isalnum() for c in pw): size += 33
    return size

B64 = re.compile(rb"^[A-Za-z0-9+/=\s]+$")
HEX = re.compile(rb"^[0-9a-fA-F\s]+$")

def classify(data):
    h = entropy(data)
    body = data.strip()
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data) / len(data)

    if printable > 0.95:
        if HEX.match(data) and len(body) % 2 == 0:
            return "hex", h
        if B64.match(data) and len(body) % 4 == 0 and not body.isdigit():
            return "base64", h
        return ("plain text" if h < 5 else "text / mixed"), h
    return ("encrypted or compressed" if h >= HIGH else "binary"), h


# modes --------------------------------------------------------------------------------------

def do_text():
    s = input(paint(" text: ", G))
    if not s:
        return
    uniq = len(set(s))
    h = entropy(s)
    hmax = math.log2(uniq) if uniq > 1 else 0.0
    row("length", f"{len(s)} chars, {uniq} unique")
    row("entropy", f"{h:.3f} bits/char (ceiling {hmax:.3f})")
    row("total", f"{h * len(s):.0f} bits")
    row("random", bar(h, hmax or 1))
    if hmax:
        row("vs random", f"{h / hmax * 100:.0f}% of what this alphabet allows")
    row("frequent", ", ".join(f"{c!r}x{n}" for c, n in Counter(s).most_common(4)))



def do_file(path=None):
    path = (path or input(paint(" file: ", G)).strip()).strip('"')
    if not os.path.isfile(path):
        return print(paint(" no such file", HI))
    data = read_bytes(path)
    if not data:
        return print(paint(" empty file", DIM))
    h = entropy(data)
    row("file", os.path.basename(path))
    row("size", f"{len(data):,} bytes, {len(set(data))}/256 values seen")
    row("entropy", f"{h:.4f} bits/byte")
    row("scale", bar(h, 8))
    row("reads as", reads_as(h))


def do_password():
    pw = input(paint(" password: ", G))
    if not pw:
        return
    pool = pool_size(pw)
    bits = len(pw) * math.log2(pool) if pool > 1 else 0.0
    secs = 2 ** bits / 2 / GUESS_RATE
    grade, shade =  next((g, s) for lim, g, s in (
        (28, "very weak", HI), (36, "weak", HI), (60, "fair", G),
        (128, "strong", G), (math.inf, "very strong", HI)) if bits < lim)
    row("length", f"{len(pw)} chars over a pool of {pool}")
    row("bits", f"{bits:.0f} search-space (Shannon {entropy(pw)  * len(pw):.0f})")
    row("streangth:", bar(bits, 128))
    row("verdict", paint(f"{grade}, ~{human_time(secs)} to crack", shade))



def do_scan():
    path = input(paint(" file: ", G)).strip().strip('"')
    if not os.path.isfile(path):
        return print(paint(" no such file", HI))
    data = read_bytes(path)
    if not data:
        return print(paint(" empty file", DIM))
    # block under 256B cap out at log2(block), so they never reach 8 --- > useless

    block = max(256, len(data) // 256)
    vals = [entropy(data[i:i + block]) for i in range(0, len(data), block)]
    row("size", f"{len(data):,} bytes, {len(vals)} x {block}B blocks")
    row("entropy", f"avg {sum(vals) / len(vals):.2f}, peak {max(vals):.2f}")
    print()
    graph = spark(vals)
    for i in range(0, len(graph), 50):
        print("    " + paint(graph[i:i + 50]) )
    hot = [i for i, v in enumerate(vals) if v >= HIGH]
    if hot:
        print(paint(f"\n {len(hot)} hot block(s), first at offset {hex(hot[0] * block)}", HI))
    else:
        print(paint("\n nothing stand out", DIM))

    
def do_identify():
    s = input(paint("  blob: ", G))
    if not s:
        return
    kind, h = classify(s.encode())
    row("looks like", paint(kind, HI))
    row("entropy", f"{h:.3f} bits/byte")
 
 
def do_compare():
    print(paint("  one per line, blank to finish", DIM))
    rows = sorted(((s, entropy(s)) for s in iter(lambda: input(paint("  > ", G)), "")),
                  key=lambda t: -t[1])
    for s, h in rows:
        label = s if len(s) <= 20 else s[:17] + "..."
        print(f"  {paint(f'{label:<22}')}{bar(h, 8)}")
 
 
MODES = [
    ("string entropy", do_text),
    ("file entropy", do_file),
    ("password strength", do_password),
    ("scan file for hidden entropy", do_scan),
    ("identify a blob (text/hex/base64/binary)", do_identify),
    ("compare strings", do_compare),
]
 
 
def menu():
    print(paint(BANNER, HI))
    while True:
        print()
        for i, (name, _) in enumerate(MODES, 1):
            print(paint(f"  {i}", G) + f"  {name}")
        print(paint("  q", G) + "  quit")
        pick = input(paint("\n  > ", HI)).strip()
        if pick in ("q", "0", ""):
            return
        if pick.isdigit() and 1 <= int(pick) <= len(MODES):
            print()
            MODES[int(pick) - 1][1]()
        else:
            print(paint("  ?", DIM))
 
 
def main():
    global colour
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("file", nargs="?", help="scan this file and exit")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()
    if args.no_color:
        colour = False
    if args.file:
        print(paint(BANNER, HI))
        return do_file(args.file)
    try:
        menu()
    except (KeyboardInterrupt, EOFError):
        print()
 
 
if __name__ == "__main__":
    main()