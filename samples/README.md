# Benign functional inputs

These are smoke-test controls, not exploit proofs. `hello.br` decodes to
`hello\n`; `hello.tar` contains a regular `hello.txt`; the PNG and PDF contain a
small solid image and a one-page rectangle; the XML is ordinary markup; the
regex file has one matching and one nonmatching subject; and `hello.elf` is a
159-byte static x86-64 ELF that writes `hello\n` (for the linux-lpe adapter).
`invalid.url` is rejected by the curl fixture's URL policy.

Examples:

```sh
python3 markets_research/_vm/smoke.py markets_research/out/brotli2shell.qcow2 \
  --input markets_research/_vm/samples/hello.br --expected-stdout $'hello\n'
python3 markets_research/_vm/smoke.py markets_research/out/libarchive.qcow2 \
  --input markets_research/_vm/samples/hello.tar --expected-artifact hello.txt
python3 markets_research/_vm/smoke.py markets_research/out/ghostscript.qcow2 \
  --input markets_research/_vm/samples/hello.pdf --expected-artifact page-1.png
python3 markets_research/_vm/smoke.py markets_research/out/linux-lpe.qcow2 \
  --input markets_research/_vm/samples/hello.elf --expected-stdout $'hello\n'
python3 markets_research/_vm/smoke.py markets_research/out/php2shell.qcow2 \
  --http-port 80 --http-path / --http-expect 'PHP fixture'
```

A normal response to a benign input establishes basic operation only, not
security or exploitability.
