```markdown
# Reverse Engineering Analysis of a Proof-of-Work Challenge Mechanism Employing WebAssembly

## 1. Introduction

Two binary artifacts were subjected to static and dynamic analysis:

| Artifact | Format | Function |
|----------|--------|----------|
| `e361f4482a3a5c6f4148.wasm` | WebAssembly (compiled from Rust via `wasm-bindgen`) | Computational solver for the proof-of-work challenges |
| `a408099f-a5a1-4ae9-9eae-bd0e712173bb.pow` | JSON | Container for the proof-of-work challenge set and an orthogonal browser instrumentation payload |

The system implements two independent mechanisms:

- A hashcash-style proof-of-work (PoW) rate-limiting primitive, solved exclusively by the WebAssembly module.
- A set of client-side instrumentation probes embedded within the `.pow` file. These probes are independent of the WebAssembly component and appear designed to characterize the execution environment (browser versus headless or automated clients). One probe explicitly renders the string `"CAPTCHA probe"` onto a canvas element.

This report presents a complete reverse-engineering of the PoW mechanism, including verification against independent implementations, and provides a factual description of the instrumentation payload without any analysis of evasion techniques.

## 2. Structure of the `.pow` Artifact

The file is a JSON object containing two top-level fields:

```json
{
  "pow": {
    "algorithm": "sha-256",
    "challenges": [
      { "salt": "<64-character hexadecimal string>", "target": "00000" },
      ...
    ]
  },
  "instrumentation": "<JSON-encoded string>"
}
```

- `pow.algorithm` is fixed to the value `"sha-256"` in the examined sample.
- `pow.challenges` is an array of ten independent challenge objects, each consisting of a salt and a target prefix.
- The salt is a cryptographically random 64-character hexadecimal string unique to each challenge.
- The target is a hexadecimal prefix that the resulting digest must match (in this instance `"00000"`, corresponding to a difficulty of approximately 20 bits).
- The `instrumentation` field is a double-encoded JSON string containing an array of fifteen fingerprinting probe objects of the form `{id, type, code}`, where `type ∈ {canvas, dom, prototype, bitwise}` (see Section 5).

## 3. Proof-of-Work Algorithm

### 3.1 Formal Definition

Given a challenge pair `(salt, target)`, the required computation is to identify the minimal non-negative integer `nonce` satisfying

\[
\operatorname{SHA-256}(\textit{salt} \Vert \operatorname{dec}(\textit{nonce})) = h
\]

such that the hexadecimal representation of \(h\) begins with the string `target`. Here \(\Vert\) denotes concatenation and \(\operatorname{dec}(\cdot)\) denotes the decimal (base-10) string representation of the integer without leading zeros.

### 3.2 Determination of the Algorithm

Static disassembly of the WebAssembly module into WebAssembly Text Format (`wasm2wat`) revealed the presence of the canonical SHA-256 round constants (e.g., \(0x428a2f98 = 1116352408\)) embedded as immediate values, consistent with a self-contained implementation of the SHA-256 compression function (most probably the Rust `sha2` crate compiled to WebAssembly).

The module exports a single relevant entry point:

```
solve_pow(salt_ptr: i32, salt_len: i32, target_ptr: i32, target_len: i32) → i64
```

Only one external import (`wbg.__wbindgen_init_externref_table`) is required, confirming that the function performs pure computation without callbacks into the host environment and therefore cannot interact with the instrumentation probes.

Dynamic verification was performed by instantiating the module under the Wasmtime runtime (via Python bindings), allocating the salt and target strings in linear memory through the exported `__wbindgen_malloc` allocator, and invoking `solve_pow` with authentic challenge data. The returned nonces were cross-validated against an independent brute-force implementation written in Python using the standard library `hashlib.sha256`. This confirmed:

- The precise input construction \(\textit{salt} \Vert \operatorname{str}(\textit{nonce})\) with no separator and decimal encoding of the nonce.
- That the WebAssembly implementation returns the minimal nonce (equivalent to exhaustive search commencing at \(\textit{nonce} = 0\)), indicating the absence of shortcuts, pre-computation tables, or heuristic optimizations beyond an efficient sequential loop.

### 3.3 Empirical Results

All ten challenges extracted from the sample `.pow` file were solved by the WebAssembly module and independently verified:

| # | Salt (prefix) | Target | Nonce | SHA-256 digest (prefix) |
|---|---------------|--------|-------|-------------------------|
| 0 | `c8ea7be2079a…` | `00000` | 817404 | `000000060ba5022e…` |
| 1 | `c7bbcc3a652f…` | `00000` | 984221 | `000001e9aeda84c7…` |
| 2 | `4cb78a67c9ae…` | `00000` | 2472995 | `000007ae3ca0888f…` |
| 3 | `c7cbd427f4d3…` | `00000` | 519766 | `0000099f05b61481…` |
| 4 | `2bacbc8d2ef9…` | `00000` | 552678 | `00000687443522b6…` |
| 5 | `0d08af1891eb…` | `00000` | 2034183 | `00000f83a91f4969…` |
| 6 | `ebaa3f448267…` | `00000` | 3952503 | `00000906152cd2a5…` |
| 7 | `9a438ebae1ed…` | `00000` | 363315 | `00000b7be605b58e…` |
| 8 | `a7fbc3f7119f…` | `00000` | 546293 | `00000df1fa291512…` |
| 9 | `3d73a4640de7…` | `00000` | 320787 | `00000654a5108a86…` |

Total wall-clock time for the ten challenges under single-threaded Wasmtime execution was approximately 5.5 seconds.

## 4. Reference Implementation in Go

A faithful reimplementation was produced in the Go programming language and validated against the reference nonces obtained from the WebAssembly module. The core sequential solver is defined as:

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

A parallel variant partitions the nonce search space into contiguous windows that are processed concurrently by multiple goroutines. Because the semantics of the original algorithm require the minimal nonce, the implementation retains the smallest valid nonce discovered within each window before advancing, thereby preserving equivalence with the sequential reference.

## 5. Instrumentation Payload

The `instrumentation` field decodes to an array of fifteen probe objects. Each object comprises an identifier, a type, and a JavaScript code fragment intended for evaluation within a browser context. These probes share no execution path with the WebAssembly PoW solver.

| Type | Count | Measurement |
|------|-------|-------------|
| `canvas` | 6 | Renders text with specified font, color, and string content onto an off-screen `<canvas>` element and computes a hash of the resulting pixel buffer. Output is sensitive to operating-system font rendering, GPU driver behavior, and anti-aliasing. One probe renders the literal string `"CAPTCHA probe"`. |
| `dom` | 2 | Instantiates a hidden, styled `<div>` element and reads layout metrics (`clientWidth`, `offsetHeight`). Values depend on the browser’s layout and font-metric engines. |
| `prototype` | 4 | Performs Boolean tests on the presence and integrity of core globals (`navigator`, `window`, `document`, `setTimeout`, `eval`) and examines whether `Function.prototype.toString.call(eval)` contains the substring `"[native code]"`. These checks are characteristic of attempts to detect missing or patched browser primitives common in headless environments. |
| `bitwise` | 3 | Executes pure integer arithmetic on constant seeds using shifts and exclusive-or operations. These probes appear to serve as noise or as a simple integrity check. |

The combination of a computational PoW gate with environment-characterization probes is consistent with an anti-automation checkpoint intended to differentiate genuine browser execution contexts from scripted or headless clients.

## 6. Conclusions

The examined `.pow` artifact packages a conventional hashcash-style proof-of-work challenge set together with an independent browser-fingerprinting instrumentation payload. The WebAssembly module implements a pure, optimized SHA-256 brute-force search of the form \(\operatorname{SHA-256}(\textit{salt} \Vert \operatorname{dec}(\textit{nonce}))\) subject to a hexadecimal prefix target, and contains no fingerprinting logic. The algorithm was confirmed through both black-box execution under Wasmtime and independent Python verification, and was subsequently reimplemented in Go with identical output. The instrumentation component constitutes a separate, browser-only layer and was deliberately excluded from any analysis of spoofing or bypass techniques.
```
