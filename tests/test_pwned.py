"""Offline regressions: no real passwords or network calls."""

import contextlib
import hashlib
import io
import subprocess
import sys
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import requests

import pwned


class LookupTests(unittest.TestCase):
    def response(self, text, status=200):
        response = Mock(status_code=status, text=text)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        return response

    def test_utf8_exact_password_and_private_request(self):
        password = "  päss 🔑\t"
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        response = self.response(f"{'0' * 35}:0\r\n{digest[5:]}:42\r\n")
        with patch("pwned.requests.get", return_value=response) as get:
            self.assertEqual(pwned.lookup_pwned_api(password), (digest, 42))
        get.assert_called_once_with(
            pwned.API_URL + digest[:5],
            headers={"Add-Padding": "true", "User-Agent": "pwned-search"},
            timeout=(5, 15), allow_redirects=False,
        )
        response.__exit__.assert_called_once()

    def test_absent_and_zero_padding_are_integer_zero(self):
        digest = hashlib.sha1(b"example").hexdigest().upper()
        for text in ("0" * 35 + ":123", digest[5:] + ":0"):
            with self.subTest(text=text), patch("pwned.requests.get", return_value=self.response(text)):
                _, count = pwned.lookup_pwned_api("example")
                self.assertIs(type(count), int)
                self.assertEqual(count, 0)

    def test_all_non_200_statuses_fail(self):
        for status in (204, 301, 404, 429, 503):
            with self.subTest(status=status), patch("pwned.requests.get", return_value=self.response("", status)):
                with self.assertRaisesRegex(RuntimeError, f"HTTP {status}"):
                    pwned.lookup_pwned_api("example")

    def test_network_errors_do_not_expose_exception_metadata(self):
        for exception in (requests.Timeout, requests.ConnectionError, requests.exceptions.SSLError):
            with self.subTest(exception=exception), patch("pwned.requests.get", side_effect=exception("secret metadata")):
                with self.assertRaises(RuntimeError) as caught:
                    pwned.lookup_pwned_api("example")
                self.assertNotIn("secret", str(caught.exception))

    def test_malformed_response_never_means_absent(self):
        digest = hashlib.sha1(b"example").hexdigest().upper()
        for text in ("", "<html>Error</html>", "ABC:1", "0" * 35 + ":-1",
                     "0" * 35 + ":oops", "0" * 35 + ":1:2",
                     digest[5:] + ":1\ninvalid", "0" * 35 + ":1\n" + "0" * 35 + ":2"):
            with self.subTest(text=text), patch("pwned.requests.get", return_value=self.response(text)):
                with self.assertRaises(RuntimeError):
                    pwned.lookup_pwned_api("example")

    def test_padding_cannot_override_real_match(self):
        digest = hashlib.sha1(b"example").hexdigest().upper()
        text = f"{digest[5:].lower()}:9\n{digest[5:]}:0"
        with patch("pwned.requests.get", return_value=self.response(text)):
            self.assertEqual(pwned.lookup_pwned_api("example"), (digest, 9))


class CliTests(unittest.TestCase):
    def run_main(self, args, outcomes, stdin=""):
        output, errors = io.StringIO(), io.StringIO()
        with patch("pwned.sys.stdin", io.StringIO(stdin)), \
             patch("pwned.lookup_pwned_api", side_effect=outcomes) as lookup, \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = pwned.main(args)
        return code, output.getvalue(), errors.getvalue(), lookup

    def test_stdin_preserves_spaces_tabs_empty_and_final_record(self):
        values = ["  example\t", "", "last "]
        code, output, errors, lookup = self.run_main([], [("hash", 0)] * 3, "  example\t\r\n\nlast ")
        self.assertEqual([call.args[0] for call in lookup.call_args_list], values)
        self.assertEqual(code, 0)
        self.assertEqual(output.count("was not found"), 3)
        self.assertEqual(errors, "")

    def test_arguments_are_unchanged_and_secrets_are_not_printed(self):
        for count in (0, 5):
            code, output, errors, lookup = self.run_main(["  secret\t"], [("full-secret-hash", count)])
            lookup.assert_called_once_with("  secret\t")
            self.assertEqual(code, int(count > 0))
            self.assertNotIn("secret", output + errors)

    def test_failed_check_dominates_found_and_batch_continues(self):
        code, output, errors, lookup = self.run_main(
            ["one", "two", "three"], [RuntimeError("service unavailable"), ("hash", 1), ("hash", 0)])
        self.assertEqual(code, 2)
        self.assertEqual(lookup.call_count, 3)
        self.assertIn("Password 1 could not be checked", errors)
        self.assertIn("Password 2 was found", output)
        self.assertIn("Password 3 was not found", output)

    def test_encoding_errors_are_redacted(self):
        error = UnicodeEncodeError("utf-8", "secret", 0, 1, "bad character")
        code, output, errors, _ = self.run_main(["secret"], [error])
        self.assertEqual(code, 2)
        self.assertNotIn("secret", output + errors)

    def test_interrupts_and_programming_errors_propagate(self):
        for error in (KeyboardInterrupt(), TypeError("bug")):
            with self.subTest(error=error), self.assertRaises(type(error)):
                self.run_main(["example"], [error])

    def test_invalid_utf8_subprocess_fails_without_exposing_input(self):
        script = Path(pwned.__file__).resolve()
        result = subprocess.run(
            [sys.executable, "-X", "utf8", str(script)],
            input=b"\xff\n", capture_output=True, timeout=5,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"UTF-8", result.stderr)
        self.assertNotIn(b"\xff", result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)

    def test_terminal_uses_hidden_prompt(self):
        with patch("pwned.sys.stdin.isatty", return_value=True), \
             patch("pwned.getpass.getpass", return_value=" example ") as prompt, \
             patch("pwned.lookup_pwned_api", return_value=("hash", 0)) as lookup, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(pwned.main([]), 0)
            prompt.assert_called_once_with("Password: ")
            lookup.assert_called_once_with(" example ")

    def test_hidden_input_failure_has_no_network_request(self):
        for error in (pwned.getpass.GetPassWarning("unsafe"), EOFError()):
            with self.subTest(error=error), patch("pwned.sys.stdin.isatty", return_value=True), \
                 patch("pwned.getpass.getpass", side_effect=error), \
                 patch("pwned.lookup_pwned_api") as lookup, \
                 contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(pwned.main([]), 2)
                lookup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
