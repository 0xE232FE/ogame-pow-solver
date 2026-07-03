Reverse Engineering: PoW Challenge (`.pow`) + WASM Solver
1. Overview
Two files were analyzed:
File	Type	Role
`e361f4482a3a5c6f4148.wasm`	WebAssembly (Rust / `wasm-bindgen`)	Solves the proof-of-work challenges
`a408099f-a5a1-4ae9-9eae-bd0e712173bb.pow`	JSON	Contains the PoW challenges + a browser-fingerprinting instrumentation payload
The system combines two independent mechanisms:
Proof-of-work (PoW) — a hashcash-style rate-limiter, solved by the wasm module.
Instrumentation / fingerprinting probes — JS snippets embedded in the `.pow` JSON that are not related to the wasm module and appear designed to detect non-browser / headless / automated clients (one probe literally renders the string `"CAPTCHA probe"` to a canvas).
This document covers the PoW mechanism in full (reverse engineered, verified, and reimplemented) and describes the fingerprinting payload at a factual level without providing spoofing/bypass logic for it.
---
2. `.pow` File Structure
The file is JSON with two top-level keys:
```json
{
  "pow": {
    "algorithm": "sha-256",
    "challenges": [
      { "salt": "<64-hex-char string>", "target": "00000" },
      ...
    ]
  },
  "instrumentation": "<JSON-encoded string, see below>"
}
```
`pow.algorithm`: always `"sha-256"` in the sample.
`pow.challenges`: an array of 10 `{salt, target}` pairs. Each is solved independently.
`salt`: a random hex string (unique per challenge).
`target`: a hex-digit prefix the resulting digest must start with (here, `"00000"` — 5 leading zero hex digits, i.e. ~20 bits of difficulty per challenge).
`instrumentation`: a JSON string (double-encoded) containing an array of 15 fingerprinting probe objects: `{id, type, code}`. `type` is one of `canvas`, `dom`, `prototype`, `bitwise`. See §5.
---
3. PoW Algorithm
3.1 Rule
For a given `(salt, target)` pair, find the smallest non-negative integer `nonce` such that:
```
sha256(salt + decimal_string(nonce))
```
produces a hex digest whose prefix equals `target`.
3.2 How this was determined
Disassembled the wasm to WAT (`wasm2wat`) and confirmed the SHA-256 round constants (`0x428a2f98` = `1116352408`, etc.) are statically embedded — indicating a self-contained SHA-256 implementation (Rust's `sha2` crate, compiled in).
The module exports a single relevant function:
```
   solve_pow(salt_ptr: i32, salt_len: i32, target_ptr: i32, target_len: i32) -> i64
   ```
Only one import is required (`wbg.__wbindgen_init_externref_table`), confirming the function is pure computation with no host/JS callbacks — it does not touch the instrumentation probes.
Instantiated the module with `wasmtime` (Python bindings), wrote `salt`/`target` strings into linear memory via the exported `__wbindgen_malloc`, and called `solve_pow` directly with real challenge data.
Cross-verified the returned nonce against a plain Python brute-force (`hashlib.sha256`), confirming:
The formula is `sha256(salt + str(nonce))` — no separator, no leading zero padding, decimal (not hex) nonce encoding.
The wasm returns the minimal nonce (identical to brute-forcing from `nonce = 0` upward), i.e. no shortcuts or precomputation — just an optimized brute-force loop.
3.3 Verified Results
All 10 challenges from the sample `.pow` file, solved via the wasm module and cross-checked with an independent brute-force:
#	salt (prefix)	target	nonce	sha256(salt+nonce)
0	`c8ea7be2079a…`	`00000`	`817404`	`000000060ba5022e…`
1	`c7bbcc3a652f…`	`00000`	`984221`	`000001e9aeda84c7…`
2	`4cb78a67c9ae…`	`00000`	`2472995`	`000007ae3ca0888f…`
3	`c7cbd427f4d3…`	`00000`	`519766`	`0000099f05b61481…`
4	`2bacbc8d2ef9…`	`00000`	`552678`	`00000687443522b6…`
5	`0d08af1891eb…`	`00000`	`2034183`	`00000f83a91f4969…`
6	`ebaa3f448267…`	`00000`	`3952503`	`00000906152cd2a5…`
7	`9a438ebae1ed…`	`00000`	`363315`	`00000b7be605b58e…`
8	`a7fbc3f7119f…`	`00000`	`546293`	`00000df1fa291512…`
9	`3d73a4640de7…`	`00000`	`320787`	`00000654a5108a86…`
All 10 solved by the wasm module in ~5.5 s total (single-threaded, `wasmtime`).
---
4. Go Reimplementation
A faithful Go port (`powsolve.go`) was written and validated against the above table — it produces byte-identical nonces to the wasm module for every challenge.
Core logic:
```go
func solve(salt, target string) int64 {
    var nonce int64
    for {
        h := sha256.Sum256([]byte(salt + strconv.FormatInt(nonce, 10)))
        if strings.HasPrefix(hex.EncodeToString(h[:]), target) {
            return nonce
        }
        nonce++
    }
}
```
A parallel variant (`solveParallel`) is used by default: it partitions the nonce space into bounded windows, searches each window across goroutines, and — because the minimum nonce matters — takes the smallest hit within a window before advancing to the next window (preserving the "smallest nonce wins" semantics of the wasm reference implementation).
Usage:
```bash
go build -o powsolve .
./powsolve path/to/challenge.pow
```
Sample output (validated against the wasm module):
```
algorithm: sha-256, 10 challenge(s)
[0] salt=c8ea7be2079a... target=00000 nonce=817404 hash=000000060ba5022e... valid=true
...
solved 10 challenge(s) in 16.09s   # single-core sandbox; scales with core count
```
---
5. Instrumentation Payload (Fingerprinting Probes)
The `instrumentation` field decodes to 15 objects, each with an `id`, a `type`, and a JS `code` snippet meant to be `eval`'d in a real browser context. These are independent of the wasm PoW solver — no shared code path exists between them.
Type	Count	What it measures
`canvas`	6	Renders text (specific font/color/string) to an offscreen `<canvas>`, hashes the resulting pixel buffer. Output depends on OS font rendering, GPU/driver, and anti-aliasing — classic canvas fingerprinting. One probe renders the literal string `"CAPTCHA probe"`.
`dom`	2	Creates a hidden, styled `<div>` and reads back `clientWidth` / `offsetHeight`. Value depends on the browser's layout/font-metrics engine.
`prototype`	4	XORs a seed value against boolean checks like `typeof navigator/window/document/setTimeout/eval` and whether `Function.prototype.toString.call(eval)` contains `"[native code]"` — used to detect missing/patched browser globals typical of headless or scripted environments.
`bitwise`	3	Pure integer arithmetic with no environment dependency (constant seeds, shifts, XORs). Likely padding/noise mixed in with the real probes, or a checksum of sorts.
Assessment: combined with the PoW gate, this payload is consistent with an anti-bot / anti-automation checkpoint intended to distinguish genuine browser execution from headless or scripted clients, rather than a pure rate-limiting mechanism. Reimplementation or spoofing of these specific probes was intentionally not produced as part of this analysis.
---
6. Summary
The `.pow` file bundles a standard hashcash-style PoW challenge set with a separate browser-fingerprinting probe payload.
The wasm module (`solve_pow`) is a pure, optimized SHA-256 brute-forcer implementing `sha256(salt + nonce)` with a hex-prefix target — no fingerprinting logic inside it.
The algorithm was independently confirmed via black-box testing (wasmtime) and Python brute-force cross-checks, then ported to Go with matching output.
The `instrumentation` payload is a separate, browser-only fingerprinting layer not analyzed for spoofing/bypass purposes.
