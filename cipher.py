#!/usr/bin/env python3
"""Caesar + Vigenere cipher suite.
 
Encrypt, decrypt, and break both classic ciphers. Caesar is broken by trying
all 26 shifts and scoring each one by letter frequency. Vigenere is broken by
using the index of coincidence to guess the key length, then cracking each
column as its own little Caesar cipher. Case and punctuation are left alone --
only letters get shifted.
"""
 
import argparse
import os
import sys
from collections import Counter
 
 
# Green terminal colours -- just plain ANSI codes. We switch them off when the
# output isn't a real terminal (e.g. piped to a file) or when NO_COLOR is set.
GREEN = "\033[32m"
BRIGHT = "\033[92m"
DIM = "\033[2;32m"
RESET = "\033[0m"
use_colour = sys.stdout.isatty() and "NO_COLOR" not in os.environ
 
 
# How often each letter turns up in ordinary English, as a percentage. This
# table is the whole trick behind cracking -- it's how we tell a real
# decryption apart from random garbage.
ENGLISH_FREQ = {
    "a": 8.2, "b": 1.5, "c": 2.8, "d": 4.3, "e": 12.7, "f": 2.2, "g": 2.0,
    "h": 6.1, "i": 7.0, "j": 0.15, "k": 0.77, "l": 4.0, "m": 2.4, "n": 6.7,
    "o": 7.5, "p": 1.9, "q": 0.095, "r": 6.0, "s": 6.3, "t": 9.1, "u": 2.8,
    "v": 0.98, "w": 2.4, "x": 0.15, "y": 2.0, "z": 0.074,
}
 
 
BANNER = r"""
   ___ ___ ___ _  _ ___ ___
  / __|_ _| _ \ || | __| _ \
 | (__ | ||  _/ __ | _||   /
  \___|___|_| |_||_|___|_|_\
"""
 
 
def colour(text, shade=GREEN):
    if use_colour:
        return shade + text + RESET
    return text
 
 
def show(label, value):
    # print a label and its value, with the labels lined up in a column
    print("  " + colour(label.ljust(11), DIM) + value)
 
 
# --- the ciphers -------------------------------------------------------------
 
def caesar(text, shift):
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shifted = (ord(ch) - base + shift) % 26 + base
            result.append(chr(shifted))
        else:
            result.append(ch)          # leave spaces, punctuation, digits as-is
    return "".join(result)
 
 
def vigenere(text, key, decrypt=False):
    # turn the key word into a list of shifts:  a -> 0, b -> 1, ... z -> 25
    shifts = [ord(k.lower()) - ord("a") for k in key if k.isalpha()]
    if not shifts:
        return text
 
    result = []
    key_pos = 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shift = shifts[key_pos % len(shifts)]
            if decrypt:
                shift = -shift
            shifted = (ord(ch) - base + shift) % 26 + base
            result.append(chr(shifted))
            key_pos += 1               # only move along the key on real letters
        else:
            result.append(ch)
    return "".join(result)
 
 
# --- the analysis behind the cracking ----------------------------------------
 
def english_score(text):
    # A chi-squared test: compare the letters in `text` against how often
    # those letters show up in English. The lower the score, the more the
    # text looks like real English.
    letters = [ch for ch in text.lower() if ch.isalpha()]
    if not letters:
        return float("inf")
 
    counts = Counter(letters)
    total = len(letters)
    score = 0.0
    for letter, freq in ENGLISH_FREQ.items():
        expected = freq / 100 * total
        actual = counts.get(letter, 0)
        score += (actual - expected) ** 2 / expected
    return score
 
 
def index_of_coincidence(text):
    # Roughly: the chance that two letters pulled out at random are the same.
    # English text sits around 0.067; random text around 0.038.
    letters = [ch for ch in text.lower() if ch.isalpha()]
    total = len(letters)
    if total < 2:
        return 0.0
 
    counts = Counter(letters)
    pairs = sum(n * (n - 1) for n in counts.values())
    return pairs / (total * (total - 1))
 
 
def smallest_period(key):
    # "wolfwolf" is really just "wolf" repeated, so shrink it back down
    for size in range(1, len(key) + 1):
        unit = key[:size]
        if unit * (len(key) // size) == key:
            return unit
    return key
 
 
def crack_caesar(text):
    # There are only 26 possible shifts, so just try every one and keep
    # whichever result looks most like English.
    best_shift = 0
    best_score = float("inf")
    for shift in range(26):
        candidate = caesar(text, -shift)
        score = english_score(candidate)
        if score < best_score:
            best_score = score
            best_shift = shift
    return best_shift, caesar(text, -best_shift)
 
 
def crack_vigenere(text, max_key_length=16):
    letters = [ch.lower() for ch in text if ch.isalpha()]
    if len(letters) < 40:
        return "", text               # too little text for the stats to work
 
    # Step 1 -- guess the key length.
    # If we take every Nth letter and N is the real key length, all those
    # letters were shifted by the same key letter, so that slice reads like
    # plain English and scores a high index of coincidence.
    def average_ioc(length):
        columns = [letters[start::length] for start in range(length)]
        scores = [index_of_coincidence("".join(col)) for col in columns]
        return sum(scores) / length
 
    max_key_length = min(max_key_length, len(letters) // 4)
    ioc_by_length = {length: average_ioc(length)
                     for length in range(1, max_key_length + 1)}
 
    # Multiples of the real length score high too, so rather than the very
    # highest, take the shortest length that gets within 90% of the best.
    best = max(ioc_by_length.values())
    key_length = min(length for length, score in ioc_by_length.items()
                     if score >= 0.9 * best)
 
    # Step 2 -- crack each column.
    # Each column is now just a plain Caesar cipher, which we already handle,
    # so run the Caesar cracker once per column to recover each key letter.
    key = ""
    for start in range(key_length):
        column = "".join(letters[start::key_length])
        shift, _ = crack_caesar(column)
        key += chr(shift + ord("a"))
 
    return smallest_period(key), vigenere(text, smallest_period(key), decrypt=True)
 
 
# --- the menu modes ----------------------------------------------------------
 
def do_caesar_encrypt():
    text = input(colour("  text:  ", GREEN))
    shift = int(input(colour("  shift: ", GREEN)) or 3)
    show("cipher", colour(caesar(text, shift), BRIGHT))
 
 
def do_caesar_decrypt():
    ciphertext = input(colour("  cipher: ", GREEN))
    shift = int(input(colour("  shift:  ", GREEN)) or 3)
    show("text", colour(caesar(ciphertext, -shift), BRIGHT))
 
 
def do_caesar_crack():
    ciphertext = input(colour("  cipher: ", GREEN))
    if not ciphertext:
        return
    best_shift, plaintext = crack_caesar(ciphertext)
 
    # Print all 26 shifts so you can eyeball them, and flag the best guess.
    print()
    for shift in range(26):
        guess = caesar(ciphertext, -shift)[:50]
        if shift == best_shift:
            print(colour(f"  {shift:>2}  {guess}", BRIGHT) + colour("  <- best", BRIGHT))
        else:
            print(colour(f"  {shift:>2}  {guess}", DIM))
    print()
    show("shift", str(best_shift))
    show("plaintext", colour(plaintext, BRIGHT))
 
 
def do_vigenere_encrypt():
    text = input(colour("  text: ", GREEN))
    key = input(colour("  key:  ", GREEN))
    show("cipher", colour(vigenere(text, key), BRIGHT))
 
 
def do_vigenere_decrypt():
    ciphertext = input(colour("  cipher: ", GREEN))
    key = input(colour("  key:    ", GREEN))
    show("text", colour(vigenere(ciphertext, key, decrypt=True), BRIGHT))
 
 
def do_vigenere_crack():
    ciphertext = input(colour("  cipher: ", GREEN))
    if not ciphertext:
        return
    key, plaintext = crack_vigenere(ciphertext)
    if not key:
        print(colour("  too short to break reliably (need ~40+ letters)", BRIGHT))
        return
    show("key length", str(len(key)))
    show("key", colour(key, BRIGHT))
    show("plaintext", colour(plaintext[:220], BRIGHT))
    print(colour("  (statistical guess -- short or unusual text can fool it)", DIM))
 
 
MODES = [
    ("Caesar   - encrypt", do_caesar_encrypt),
    ("Caesar   - decrypt", do_caesar_decrypt),
    ("Caesar   - crack (tries all 26 shifts)", do_caesar_crack),
    ("Vigenere - encrypt", do_vigenere_encrypt),
    ("Vigenere - decrypt", do_vigenere_decrypt),
    ("Vigenere - crack (index of coincidence)", do_vigenere_crack),
]
 
 
def menu():
    print(colour(BANNER, BRIGHT))
    while True:
        print()
        for number, (name, _) in enumerate(MODES, start=1):
            print(colour(f"  {number}", GREEN) + "  " + name)
        print(colour("  q", GREEN) + "  quit")
 
        choice = input(colour("\n  > ", BRIGHT)).strip()
        if choice in ("q", "0", ""):
            return
        if choice.isdigit() and 1 <= int(choice) <= len(MODES):
            print()
            name, run_mode = MODES[int(choice) - 1]
            run_mode()
        else:
            print(colour("  ?", DIM))
 
 
def main():
    global use_colour
    parser = argparse.ArgumentParser(description="Caesar + Vigenere cipher suite")
    parser.add_argument("--no-color", action="store_true")
    if parser.parse_args().no_color:
        use_colour = False
    try:
        menu()
    except (KeyboardInterrupt, EOFError):
        print()
 
 
if __name__ == "__main__":
    main()
