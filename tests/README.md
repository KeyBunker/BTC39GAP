# C regression tests

Run from the repository root with the same GCC/Clang and make environment used
for the application (including MSYS2/MinGW on Windows):

```
make test
make sanitize
make test-full
```

## What is checked

| Suite | Checks |
| --- | --- |
| `test_security` | Actual wipe before both unlock and unmap/free; all bytes, guard bytes, 16 alignments, page boundaries, OS allocation/lock/unlock failures, 64-bit allocation sizes, multiplication overflow, worker allocation/create/join failures, waiting for an active worker after a failed join, and progress ordering. Argon2's internal clearing is tested both enabled and disabled, with 1, 2 and 4 worker threads. |
| `test_terminal` | Mode restoration and cancellation through platform API doubles; each redirected standard stream; every possible input byte; cancellation during input; line limits, EOF, wallet numbers and field validation. |
| `test_files` | Actual temporary files containing public dummy data: trimming, internal whitespace, shared path/output buffer, exact/insufficient capacity, cancellation, missing/non-regular/empty/binary inputs, 64-KiB read boundaries, and sizes immediately below, at and above 1 MiB. Rejected input must clear the destination. |
| `test_reference` | Existing Argon2/V4/BIP39/BIP86/QR vectors; independent frozen SHA-512 padding/block vectors; streaming chunks; HMAC long keys and overlapping buffers; PBKDF2 output boundaries and overflow rejection; key separation and unambiguous surname framing. |
| `test_full --small` | Calls the application's real `derive_bip39_entropy`, first validates its production Argon2 configuration, then substitutes 32 KiB only inside the test wrapper. Runs real Argon2 and compares master, entropy and fingerprint against the existing fixed vectors. Checks arena wipe, input/workspace cleanup, allocation-error and cancellation paths, and that 100% appears only after verified release. This runs in `make test`. |
| `test_full` | Two actual 8-GiB derivations with public dummy inputs. Inspects **every byte of the 8 GiB** while still mapped, before unlock and again before unmap/free. One run disables Argon2's own clear flag to verify the callback independently. Outputs must agree between runs. This runs only in `make test-full`. |

The full test needs sufficient available RAM for 8 GiB plus process/worker and
system overhead. It does not silently fall back to the small mode. The full-size
outputs are checked for reproducibility; the independent fixed-output comparison
is performed in the 32-KiB mode. The production profile is never modified.
