# Guidelines for Claude-Code Contributions  
*(nitro_enclave_bench project)*

Welcome, Claude!  Please follow the rules below whenever you generate
code, docs, or shell snippets for this repository.

---

## 1  General Objectives
* Produce a minimal, **re-usable** benchmark harness that shows how many
  subscription and notification requests a Nitro Enclave can handle on
  various CPU/RAM shapes.
* Prioritise **cryptographic correctness** first, then realism, then
  absolute performance.  Incorrect crypto is a blocker.

---

## 2  Coding Standards
| Area | Rule |
|------|------|
| Language | Rust 1.77 + Edition 2021 only |
| Formatting | Run `cargo fmt --all` before suggesting a commit |
| Linting | Keep `#![deny(clippy::all, unsafe_code)]` except for the single `unsafe` block needed to call `sodiumoxide::init()` |
| Error handling | Use `anyhow::{Result, Context}` for human-friendly errors |
| Concurrency | Tokio 1.x, prefer `select!` + `mpsc` over `spawn_blocking` |
| Secrets | **Never** hard-code keys/seeds; use `rand::rngs::OsRng` |
| Docs | Every public fn needs a `///` explaining *why*, not just *what* |

---

## 3  Crypto Implementation Rules
1. **Asymmetric decrypt / re-encrypt**  
   * Use `sodiumoxide::crypto::sealedbox::{open, seal}` (X25519 + XChaCha20-Poly1305).  
   * Fail closed: if `open()` errors, return *no* plaintext.
2. **Symmetric decrypt / encrypt**  
   * `sodiumoxide::crypto::secretbox` with *random, 24-byte* nonces
     generated per message (`crypto::secretbox::gen_nonce()`).
3. Nonce Handling  
   * Nonces are sent **unencrypted** alongside the ciphertext in the vsock
     frame (`<nonce||cipher>`).  The parent must echo them back so the
     histogram covers full round-trip cost.
4. Test Vectors  
   * Unit-test each crypto path with the vectors produced by
     `libsodium-testgen`.  CI must fail if vectors change.
5. Timing-safety  
   * All constant-time primitives come from libsodium; do **not** roll
     your own `memcmp`.

---

## 4  Branch & Commit Etiquette
* Each milestone is a separate PR into `main`.
* Squash-merge with a message template:
[milestone-N] 
• feature/bug-fix summary (1 line)
• performance impact
• test coverage added
* Do not push generated binaries or `.eif` files.

---

## 5  Performance-test Conventions
| Metric | Source |
|--------|--------|
| `p50`, `p95`, `max` | `hdrhistogram` in the parent process |
| CPU % | Read `/sys/fs/cgroup/cpu.stat` for the enclave cgroup |
| Memory | `smaps_rollup` once per second; report peak RSS |
| RPS sweep stop-condition | `p95 > 2 × p50` or any error rate > 0.1 % |

All benchmarks must be reproducible with **one** command:

```bash
./scripts/run_all.sh --shape m7i.large
```

## 6  Security & Privacy
	•	No proprietary Braze keys or real XMTP data in tests.
	•	Assume the repo is public; scrub anything company-sensitive.
	•	Keep parent ↔ enclave TLS to localhost; never reach external net in CI.

⸻

## 7  When in doubt

Ask the human user for clarification before guessing.  It is always OK to
pause and request more detail rather than introduce silent assumptions.
