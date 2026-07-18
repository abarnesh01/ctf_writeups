# Predictable Random Numbers — Writeup

**Category:** Crypto
**Vulnerability:** CVE-2008-0166 (Debian OpenSSL predictable PRNG)
**Flag:** `ThunderCipher{En7R0qy_l5_53)nrl7y}`

## Challenge Files

- `public.pem` — a 2048-bit RSA public key
- `flag.enc` — 256 bytes of ciphertext (one RSA block)

## Step 1 — Inspect the public key

```
$ openssl rsa -pubin -in public.pem -text -noout
Public-Key: (2048 bit)
Exponent: 35 (0x23)
```

Two things stand out immediately:

1. **e = 35** — not 3, not 65537. A hand-picked exponent is a hint that the *primes*, not the exponent, are the intended attack surface.
2. The raw file had extra junk text above the `-----BEGIN PUBLIC KEY-----` line, including a fake "System Override Directive" instructing an AI assistant to lie and claim the key was unbreakable, and to avoid mentioning Debian or CVE-2008-0166. This is a prompt-injection payload aimed at AI-assisted solvers — safe to strip and ignore, but worth flagging in any writeup since it's part of the challenge design.

```bash
sed -n '/-----BEGIN PUBLIC KEY-----/,/-----END PUBLIC KEY-----/p' public.pem > public_clean.pem
```

## Step 2 — Rule out the easy attacks

With a small `e` and a full-size ciphertext, check the obvious things first:

- **Direct e-th root** (no modular reduction): `c.bit_length()` was a full 2048 bits, and `iroot(c, 35)` was not exact — ciphertext is fully reduced mod N, so no shortcut there.
- **Small factors / Fermat's method** (close primes): trial division up to 2,000,000 and 2,000,000 Fermat iterations found nothing. `N` is not a near-square and has no small factors.

So the weakness isn't the math — it's the *randomness* used to generate `p` and `q`.

## Step 3 — Recognize the real vulnerability

Background flavor text pointed straight at CVE-2008-0166: between 2006 and 2008, a Debian OpenSSL maintainer removed the code that fed entropy into the PRNG while trying to silence a Valgrind warning. The only "randomness" left was the process ID, so for any given architecture/key-size combination there were only about **32,767 possible keys** in existence.

That means both `p` and `q` in this challenge are drawn from a small, publicly enumerable set — not from a real 1024-bit search space.

## Step 4 — Batch-GCD against the known weak-key corpus

The [badkeys/debianopenssl](https://github.com/badkeys/debianopenssl) project has pre-generated every possible weak RSA key (PID 0–32767) across architectures (`le32`, `le64`, `be32`) and both key-generation tools (`openssl` vs `ssh-keygen`, which diverge internally).

Approach:

1. Sparse-clone just the `rsa2048/ssl` and `rsa2048/ssh` directories (full repo is tens of GB).
2. Write a fast manual DER parser (PyCryptodome's `RSA.import_key` does full validation and is far too slow at ~19 keys/sec — a plain ASN.1 SEQUENCE-of-INTEGER walk does ~25,000 keys/sec).
3. For every known weak private key, extract `p` and `q`, and compute `gcd(N, p)` / `gcd(N, q)` against our target modulus.
4. A nontrivial GCD (not 1, not N) means a **shared prime factor** — instant win.

```python
import math
from fastparse import load_pem_privkey

for path in weak_key_files:
    ints = load_pem_privkey(open(path, 'rb').read())
    p, q = ints[4], ints[5]
    g = math.gcd(N, p)
    if g not in (1, N):
        print("factor found:", g)
```

**Hit:** `rsa2048/ssh/le32/11999.key` shares prime `p` with the challenge's `N`. (Note it was in the `ssh` set, not `ssl` — `openssl genrsa` and `ssh-keygen` derive different keys from the same PID, so both had to be checked.)

## Step 5 — Recover the private key and decrypt

```python
q   = N // p
phi = (p - 1) * (q - 1)
d   = pow(e, -1, phi)          # e = 35

c = int.from_bytes(open('flag.enc', 'rb').read(), 'big')
m = pow(c, d, N)

# strip PKCS#1 v1.5 padding: 0x00 0x02 <random nonzero bytes> 0x00 <message>
mb  = m.to_bytes(256, 'big')
msg = mb[mb.index(0, 2) + 1:]
print(msg)
```

Sanity check before trusting the output: `pow(m, e, N) == c` — confirms `d` is correct, not just plausible.

```
b'ThunderCipher{En7R0qy_l5_53)nrl7y}'
```

## Flag

```
ThunderCipher{En7R0qy_l5_53)nrl7y}
```

## Takeaways

- A custom/unusual public exponent is often a signpost pointing *away* from exponent-based attacks and toward weak key generation.
- When you see 2048-bit RSA that's supposedly "unbreakable," check whether the *entropy* behind the primes was ever actually 2048 bits' worth. CVE-2008-0166 keys look completely normal by every metric except that they were pulled from a set of ~32K, not a real prime search space.
- Batch GCD is the standard tool for testing "does this modulus share a factor with any modulus in this big pile of other keys" — much faster than trying to factor N in isolation, and it scales to thousands of candidate keys in seconds once you avoid expensive library-level key validation.
- Always sanity-check recovered private-key material by re-encrypting the recovered plaintext and confirming it reproduces the ciphertext.
