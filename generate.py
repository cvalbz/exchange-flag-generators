#!/usr/bin/env python3
"""Reference generator: initial commitment -> target input -> optional private-token proof.

The default is a benign negative control. curl-positive is a disclosed loopback
URL-normalization replay, NOT an undisclosed curl vulnerability.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
SAMPLES = HERE / "samples"
HEX_PATTERN = re.compile(rb"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")


def commitment(target, nonce, secret):
    return hashlib.sha256(
        b"exchange-flag-v1\0"
        + target.encode()
        + b"\0"
        + nonce.encode()
        + b"\0"
        + secret.encode()
    ).hexdigest()


def request(host, port, path, body=None, timeout=75):
    headers = {
        "Connection": "close",
        "Content-Length": str(len(body) if body is not None else 0),
    }
    if body is not None:
        headers["Content-Type"] = "application/octet-stream"
    req = urllib.request.Request(
        f"http://{host}:{port}{path}", data=body, headers=headers
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read(2 * 1024 * 1024)


def initial_challenge(host, target, deadline):
    while time.monotonic() < deadline:
        try:
            value = json.loads(request(host, 8080, "/challenge", timeout=3))
            if value["protocol"] != "exchange-flag-v1" or value["target"] != target:
                raise RuntimeError("target challenge identity mismatch")
            if len(value["nonce"]) != 32 or len(value["commitment"]) != 64:
                raise RuntimeError("invalid challenge encoding")
            return value
        except (OSError, ValueError, KeyError):
            time.sleep(0.5)
    raise TimeoutError("target challenge was not ready within the generator budget")


def stream_bytes(raw):
    yield raw
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        return
    if not isinstance(value, dict):
        return
    artifacts = value.get("artifacts", [])
    blobs = [value.get(name) for name in ("stdout_base64", "stderr_base64")]
    if isinstance(artifacts, list):
        blobs.extend(
            item.get("data_base64") for item in artifacts[:16] if isinstance(item, dict)
        )
    for blob in blobs:
        if isinstance(blob, str):
            try:
                yield base64.b64decode(blob, validate=True)
            except ValueError:
                pass


def redis_control(host):
    with socket.create_connection((host, 6379), timeout=10) as channel:
        channel.sendall(
            b"*3\r\n$4\r\nAUTH\r\n$10\r\nresearcher\r\n$13\r\nexchange-test\r\n"
            b"*1\r\n$4\r\nPING\r\n"
            b"*3\r\n$4\r\nEVAL\r\n$9\r\nreturn 42\r\n$1\r\n0\r\n"
        )
        expected = b"+OK\r\n+PONG\r\n:42\r\n"
        raw = b""
        while len(raw) < len(expected):
            part = channel.recv(65536)
            if not part:
                raise RuntimeError("Redis control disconnected")
            raw += part
        if raw != expected:
            raise RuntimeError("Redis control failed")
        return raw


def run_input(host, target, case):
    if target == "php2shell":
        return request(host, 80, "/")
    if target == "nginx":
        return request(host, 80, "/")
    if target == "redis":
        return redis_control(host)
    names = {
        "brotli2shell": "hello.br",
        "dompurify": "hello.html",
        "ghostscript": "hello.pdf",
        "imagemagick": "hello.png",
        "libarchive": "hello.tar",
        "libxml2": "hello.xml",
        "linux-lpe": "hello.elf",
        "pcre2": "hello.regex",
        "v8": "hello.html",
    }
    if target == "curl":
        # curl accepts shortened numeric IPv4 forms that ipaddress.ip_address()
        # rejects. This exercises the disclosed APPLICATION policy composition.
        payload = (
            b"http://127.1:8081/flag\n"
            if case == "curl-positive"
            else b"file:///etc/passwd\n"
        )
    else:
        payload = (SAMPLES / names[target]).read_bytes()
    return request(host, 8080, "/input", payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument(
        "--case", choices=["benign", "curl-positive", "forged-proof"], default="benign"
    )
    args = parser.parse_args()
    if args.case == "curl-positive" and args.target != "curl":
        parser.error("curl-positive is only a curl policy replay")
    host = os.environ.get("TARGET_HOST", "127.0.0.1")
    started = time.monotonic()
    challenge = initial_challenge(host, args.target, started + 105)
    raw = run_input(host, args.target, args.case)
    candidates = {
        m.group().decode("ascii")
        for data in stream_bytes(raw)
        for m in HEX_PATTERN.finditer(data)
    }
    proof = next(
        (
            s
            for s in candidates
            if commitment(args.target, challenge["nonce"], s) == challenge["commitment"]
        ),
        None,
    )
    if args.case == "forged-proof":
        proof = "0" * 64
    if proof is not None:
        body = json.dumps(
            {"nonce": challenge["nonce"], "secret": proof}, separators=(",", ":")
        ).encode()
        response = json.loads(request(host, 8080, "/proof", body, timeout=5))
        if response != {"received": True}:
            raise RuntimeError("proof receipt failed")
    # Never print private tokens; qualifying evidence is already in original PCAP.
    print(
        json.dumps(
            {
                "target": args.target,
                "case": args.case,
                "proof_submitted": proof is not None,
                "response_sha256": hashlib.sha256(raw).hexdigest(),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        )
    )


if __name__ == "__main__":
    main()
