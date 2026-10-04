# C regression tests

Run from the repository root with the same GCC/Clang and make environment used
for the application (including MSYS2/MinGW on Windows):

```
make test
make sanitize
make test-full
```

## Test output

Test targets show one result line per suite and a final summary. The title is
cyan, successful results are green, and failures are red when output goes to
a terminal. Status colors are disabled for redirected output or `NO_COLOR=1`.

Compiler commands and successful test transcripts are hidden by default.
Compiler warnings remain visible. A failed build or test shows its complete
transcript and returns its original failure status; make stops without printing
a success summary. Use `make test V=1` to see the commands and all test output.
The same display options work with `make sanitize`, `make test-reference`,
`make test-full`, and `make self-test`.

## Expected validation messages

`test_terminal` deliberately tries a file with a secret that is too short, a
file containing an invalid control character, and a missing file. Each case is
marked `[EXPECTED TEST REJECTION: ...]` before the application's `Invalid Test
file` or `Invalid Secret` message, then retries with valid public dummy input.
These validation messages appear in verbose output or when running
`./tests/test_terminal` directly, and use the normal text color. They are
expected; the suite still checks the result and
prints its success message only after all checks pass. A failed `CHECK` prints
`check failed` and exits with a failure status, causing `make test` to fail.

## What is checked

| Suite | Checks |
| --- | --- |
| `test_security` | Actual wipe before both unlock and unmap/free; all bytes, guard bytes, 16 alignments, page boundaries, OS allocation/lock/unlock failures, 64-bit allocation sizes, multiplication overflow, worker allocation/create/join failures, waiting for an active worker after a failed join, and progress ordering. Argon2's internal clearing is tested both enabled and disabled, with 1, 2 and 4 worker threads. |
| `test_terminal` | Mode restoration and cancellation through platform API doubles; each redirected standard stream; every possible input byte; cancellation during input; line limits, EOF, wallet numbers and field validation; normalized length checks, literal `text:` preview re-entry, idempotence and trailing-buffer wiping; explicit `file:` loading, literal paths, retry source tracking, and surname/secret visibility across wallet numbers, native filename extraction and filename/fallback display. |
| `test_files` | Actual temporary files containing public dummy data: trimming, CRLF/LF/CR/mixed-ending equivalence, tab normalization, literal backslashes and prefixes, shared path/output buffer, exact/insufficient capacity, cancellation, missing/non-regular/empty/binary inputs, 64-KiB read boundaries, and sizes immediately below, at and above 1 MiB. Rejected input must clear the destination. |
| `test_reference` | Existing Argon2/V4/BIP39/BIP86/QR vectors; independent frozen SHA-512 padding/block vectors; streaming chunks; HMAC long keys and overlapping buffers; PBKDF2 output boundaries and overflow rejection; key separation and unambiguous surname framing. |
| `test_full --small` | Calls the application's real `derive_bip39_entropy`, first validates its production Argon2 configuration, then substitutes 32 KiB only inside the test wrapper. Runs real Argon2 and compares master, entropy and fingerprint against the existing fixed vectors. Checks arena wipe, input/workspace cleanup, allocation-error and cancellation paths, and that 100% appears only after verified release. This runs in `make test`. |
| `test_full` | Two actual 8-GiB derivations with public dummy inputs. Inspects **every byte of the 8 GiB** while still mapped, before unlock and again before unmap/free. One run disables Argon2's own clear flag to verify the callback independently. Outputs must agree between runs. This runs only in `make test-full`. |

The full test needs sufficient available RAM for 8 GiB plus process/worker and
system overhead. It does not silently fall back to the small mode. The full-size
outputs are checked for reproducibility; the independent fixed-output comparison
is performed in the 32-KiB mode. The production profile is never modified.
