#!/usr/bin/env python3
"""Check complete passwords against Have I Been Pwned's hash range API."""

import getpass
import hashlib
import re
import sys
import warnings

import requests


API_URL = "https://api.pwnedpasswords.com/range/"
REQUEST_TIMEOUT = (5, 15)  # Connect and read timeouts, in seconds.
RANGE_LINE = re.compile(r"([0-9A-F]{35}):([0-9]+)", re.IGNORECASE)


def lookup_pwned_api(pwd):
    """Return (uppercase SHA-1, integer occurrence count) for an exact password.

    Passwords are encoded as UTF-8 without trimming or Unicode normalisation.
    Only the first five hash characters are sent over HTTPS; matching happens
    locally. Zero means absent from the returned dataset, not necessarily safe.
    Raises RuntimeError on transport, HTTP or malformed-response failures and
    UnicodeError when the input cannot be encoded as UTF-8.
    """
    # SHA-1 is required by this lookup protocol, not used for password storage.
    sha1pwd = hashlib.sha1(pwd.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    head, tail = sha1pwd[:5], sha1pwd[5:]
    try:
        with requests.get(
            API_URL + head,
            headers={"Add-Padding": "true", "User-Agent": "pwned-search"},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        ) as res:
            if res.status_code != 200:
                raise RuntimeError(f"Pwned Passwords returned HTTP {res.status_code}")
            body = res.text
    except requests.RequestException:
        # Raw exception text can contain request metadata. Keep CLI errors safe.
        raise RuntimeError(
            "Unable to contact Pwned Passwords (network/TLS/timeout error)"
        ) from None

    count = 0
    seen = set()
    lines = body.splitlines()
    if not lines:
        raise RuntimeError("Pwned Passwords returned an empty response")
    for line in lines:
        match = RANGE_LINE.fullmatch(line)
        if match is None:
            raise RuntimeError("Pwned Passwords returned a malformed response")
        suffix, raw_count = match.groups()
        suffix = suffix.upper()
        try:
            occurrences = int(raw_count)
        except ValueError:
            raise RuntimeError("Pwned Passwords returned an invalid count") from None
        # Zero-count padding carries no result; ignore it even if it matches.
        if occurrences == 0:
            continue
        if suffix in seen:
            raise RuntimeError("Pwned Passwords returned duplicate hash suffixes")
        seen.add(suffix)
        if suffix == tail:
            count = occurrences
    return sha1pwd, count


def _stdin_passwords(stream):
    """Remove one record terminator only, preserving password whitespace."""
    for line in stream:
        if line.endswith("\n"):
            line = line[:-1]
            if line.endswith("\r"):
                line = line[:-1]
        yield line


def main(args):
    """Run checks; return 0 for absent, 1 for found, 2 for any failed check."""
    ec = 0
    if args:
        passwords = args
    elif sys.stdin.isatty():
        # Never fall back to echoing a password when hidden input is unavailable.
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                passwords = [getpass.getpass("Password: ")]
        except (getpass.GetPassWarning, EOFError):
            print("Unable to read a hidden password; use piped input instead.", file=sys.stderr)
            return 2
    else:
        passwords = _stdin_passwords(sys.stdin)

    for number, pwd in enumerate(passwords, 1):
        label = f"Password {number}"
        try:
            _, count = lookup_pwned_api(pwd)
        except (RuntimeError, UnicodeError) as error:
            reason = (
                "Unable to encode password as UTF-8"
                if isinstance(error, UnicodeError) else str(error)
            )
            print(f"{label} could not be checked: {reason}", file=sys.stderr)
            ec = 2
            continue
        if count:
            print(f"{label} was found with {count} occurrences")
            ec = max(ec, 1)
        else:
            print(f"{label} was not found in the dataset")
    return ec


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("Check interrupted.", file=sys.stderr)
        sys.exit(130)
    except UnicodeError:
        print("Unable to decode input; provide UTF-8 text.", file=sys.stderr)
        sys.exit(2)
