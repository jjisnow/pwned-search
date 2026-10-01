# Code audit and upstream review — 2026-10-02

## Scope and upstream decision

Reviewed every tracked file in this fork at
`cc223698044101a444444b5a4d83793e46a5451e` (Python CLI, README and licence).
Compared against upstream `mikepound/pwned-search` at
`04c14391c72ee22086a096ff46bf9d019d0cc3d5`:
29 upstream-only commits and seven fork-only commits. This is a selective update,
not a merge of all upstream files or a claim of full upstream synchronisation.

Incorporated upstream's UTF-8 hashing fix (`1127482`), integer count handling
(`3279ad4`), Python entry-point convention, dependency instructions and Docker
support (`986a2af`), with additional audit fixes. Preserved readable Python 3
output. Did not adopt obsolete Python 2 compatibility or upstream's narrowed
Unicode-only CLI error handler, which lets network failures crash a batch.

Upstream's alternate language ports, GUI/browser versions and password generator
are separate products outside this fork's existing Python scope. They have not
been imported. In particular, the generator at the reviewed revision uses
`random` for credentials and inclusive `randint(0, len(sequence))`, which can
index past the end. Its presence upstream is not a reason to add it here.

## Findings and fixes

| Severity | Original behaviour | Resolution |
| --- | --- | --- |
| High | Passwords and full hashes printed to stdout and errors | Position-only output, hidden terminal prompt, redacted network/encoding errors |
| High | `strip()` changes leading/trailing whitespace, checking a different password | Preserve exact arguments; remove only one stdin record terminator |
| High | Matched counts are strings; `"0"` is truthy and incorrectly reports found | Always return integer counts; discard zero-count padding |
| Medium | ASCII hashing rejects Unicode passwords | UTF-8 hashing without normalisation, following HIBP's documented protocol |
| Medium | Requests have no timeout and transport failures are not normalised | Connect/read timeouts, safe `RuntimeError` failures, reject redirects |
| Medium | Malformed or empty responses have no reliable failure contract | Validate all response records before returning any result; reject duplicate real suffixes |
| Medium | Bare `except` catches Ctrl+C and programming bugs; failure shares found status | Catch expected lookup errors only; distinct failure/interruption statuses |
| Medium | No padded requests | Request `Add-Padding: true` |
| Low | No dependency manifest, regression tests or installation instructions | Requests manifest, offline regression suite and complete README |
| Low | Upstream container copies the whole repository and runs as root | Minimal allowlisted context, slim versioned Python base and unprivileged user |

SHA-1 remains because the range protocol requires it. It is explicitly marked as
non-security use and must not be reused as a password-storage scheme.

## Validation and limits

- 14 offline unittest cases pass, covering Unicode, whitespace, counts/padding,
  response validation, HTTP/transport failures, redaction, batching, exit status,
  hidden input and propagation of interrupts/programming errors.
- Dependency version checked against the package index: Requests 2.34.2; manifest
  requires that version or newer within major version 2.
- Invalid UTF-8 subprocess input fails safely with exit code 2 and no traceback.
- Live public-value lookup could not complete in this network-restricted environment.
  Docker is not installed here, so container build/runtime checks were not run.

CLI text and error exit codes deliberately change for privacy and automation.
Callers parsing the old plaintext output must adapt. The function name and
`(sha1, count)` return shape are preserved; the count is now consistently an int.
Requests are sequential with no persistent cache, retry loop or range retention.
Passwords still exist in process memory; Python cannot guarantee their erasure.
API availability and results depend on HIBP, and absence is not a safety verdict.

Protocol reference: [HIBP API documentation](https://haveibeenpwned.com/API/v3),
including UTF-8 hashing, five-character ranges and zero-count response padding.
