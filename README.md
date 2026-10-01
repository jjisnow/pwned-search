# pwned-search

Check passwords against [Have I Been Pwned's Pwned Passwords](https://haveibeenpwned.com/Passwords)
using its [hash range API](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange).
Only the first five characters of a locally computed SHA-1 hash are sent over
HTTPS. The full password and hash stay local, and response padding is requested.
No API key is needed.

## Install

Requires Python 3.10 or newer and Requests. From the repository directory:

```sh
python -m venv .venv
```

Activate with `source .venv/bin/activate` on macOS/Linux, or
`.venv\Scripts\Activate.ps1` in Windows PowerShell. Then:

```sh
python -m pip install -r requirements.txt
```

## Check passwords

For a single password, run:

```sh
python -X utf8 pwned.py
```

When standard input is a terminal, the tool prompts without displaying what you
type. If hidden input is unavailable, it fails rather than echoing the password.
For batch checks, supply one UTF-8 password per line:

```sh
python -X utf8 pwned.py < passwords.txt
another-command | python -X utf8 pwned.py
```

The file redirection example is for shells supporting `<`, such as Bash or
Windows cmd.exe. In PowerShell, use `Get-Content -Encoding utf8 passwords.txt |
python -X utf8 pwned.py` and ensure the shell's pipe output is UTF-8. The
`-X utf8` option controls Python's encoding, not the producing shell's encoding.

Leading/trailing spaces and tabs are significant. Only each stdin line's LF or
CRLF terminator is removed. A blank line checks the empty password; empty input
checks nothing and exits successfully. Passwords containing embedded line breaks
cannot be represented by this line-based format; use the Python function for those.

Command-line arguments remain supported (`python pwned.py 'example password'`),
but prefer the hidden prompt: arguments can appear in shell history and process
listings. Use password files only when their access permissions are appropriate.

Output identifies inputs by position, never by their password or full hash:

```text
Password 1 was found with 123 occurrences
Password 2 was not found in the dataset
```

Errors go to stderr; processing continues with remaining passwords. Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | All checked passwords were absent from the dataset, or no input was supplied |
| 1 | At least one password was found, and every check completed |
| 2 | At least one check failed; takes precedence over code 1 |
| 130 | Interrupted with Ctrl+C |

A password being absent does **not** establish that it is strong, unique or safe.
If a password is found, replace it wherever you use it with a unique password.
The remote service still sees your hash prefix and network metadata; range
queries and padding reduce disclosure, rather than providing complete anonymity.

## Python interface

```python
from pwned import lookup_pwned_api

sha1, count = lookup_pwned_api("example password")
```

Returns `(uppercase_sha1, integer_count)`; zero includes padding entries. Inputs
are hashed exactly as UTF-8, without trimming or Unicode normalisation. Failures
in transport, HTTP status or response validation raise `RuntimeError`; encoding
failures raise `UnicodeError`. Connect/read timeouts are 5/15 seconds respectively,
not a deadline for the entire request. Redirects are rejected. This function
returns the full hash for compatibility; avoid logging it.

## Docker

```sh
docker build -t pwned .
docker run --rm -it pwned
docker run --rm -i pwned < passwords.txt
```

Use `-it` for the hidden prompt, or `-i` to pass stdin through for batch input.
The container runs as an unprivileged user and copies only the script and dependency
manifest; local password files are excluded from the build context.

## Tests and upstream

```sh
python -m unittest discover -s tests -v
```

Tests use synthetic inputs and mocked HTTP responses; they require no network.
This fork selectively incorporates relevant improvements from
[mikepound/pwned-search](https://github.com/mikepound/pwned-search) and maintains
the Python CLI. See [AUDIT.md](AUDIT.md) for the comparison, fixes and limits.
