#!/usr/bin/env python3
"""Independent Paillier reference, used only to cross-check the JavaScript code.

Written from the definition in Paillier (1999) with Python's built-in integers.
It shares no code with the JavaScript implementation: different language,
different big-number arithmetic, different random source.

Protocol: one JSON request on standard input, one JSON answer on standard
output. Every large number travels as a hexadecimal string.
"""
import json
import math
import secrets
import sys


def to_int(hex_text):
    return int(hex_text, 16)


def to_hex(value):
    return format(value, "x")


def private_key(p, q):
    """Derive (n, lambda, mu) from the two primes."""
    n = p * q
    lam = math.lcm(p - 1, q - 1)
    mu = pow(lam, -1, n)
    return n, lam, mu


def encrypt(n, m):
    """c = (1 + m*n) * r^n mod n^2, with r random in Z*_n."""
    n2 = n * n
    while True:
        r = secrets.randbelow(n - 1) + 1
        if math.gcd(r, n) == 1:
            break
    return ((1 + m * n) * pow(r, n, n2)) % n2


def decrypt(p, q, c):
    """m = L(c^lambda mod n^2) * mu mod n, with L(x) = (x - 1) / n."""
    n, lam, mu = private_key(p, q)
    x = pow(c, lam, n * n)
    return ((x - 1) // n) * mu % n


def handle(req):
    op = req["op"]
    if op == "modpow":
        return {"result": to_hex(pow(to_int(req["base"]), to_int(req["exp"]), to_int(req["mod"])))}
    if op == "derive":
        n, lam, mu = private_key(to_int(req["p"]), to_int(req["q"]))
        return {"n": to_hex(n), "lambda": to_hex(lam), "mu": to_hex(mu)}
    if op == "encrypt":
        n = to_int(req["n"])
        return {"c": [to_hex(encrypt(n, int(m))) for m in req["m"]]}
    if op == "decrypt":
        p, q = to_int(req["p"]), to_int(req["q"])
        return {"m": [str(decrypt(p, q, to_int(c))) for c in req["c"]]}
    if op == "add":
        n2 = to_int(req["n"]) ** 2
        acc = 1
        for c in req["c"]:
            acc = (acc * to_int(c)) % n2
        return {"result": to_hex(acc)}
    if op == "scalar":
        n2 = to_int(req["n"]) ** 2
        return {"result": to_hex(pow(to_int(req["c"]), int(req["k"]), n2))}
    raise ValueError(f"unknown op: {op}")


def main():
    req = json.load(sys.stdin)
    # A request is either one operation or a list of operations.
    answer = [handle(r) for r in req] if isinstance(req, list) else handle(req)
    json.dump(answer, sys.stdout)


if __name__ == "__main__":
    main()
