# Reference generators

`generate.py` is a stdlib-only reference client. It obtains the first challenge,
runs a disclosed benign control, and submits a proof only when the target response
contains a 64-hex candidate whose commitment matches the initial challenge. It
never prints the private token.

```sh
python3 generate.py --target TARGET --case benign
```

`curl-positive` is only for the curl fixture: it exercises the application URL
policy's numeric-IPv4 normalization and is explicitly a public composition
replay, not a new curl vulnerability. `forged-proof` submits a deliberately
wrong secret and is a negative control.

The files under `samples/` are benign functional controls, not exploit proofs.
A normal response establishes basic operation only. A generator must run against
the exact published image; the Oracle binds that image hash and the original
controller capture.
