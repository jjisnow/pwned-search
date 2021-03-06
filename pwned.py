import hashlib
import requests
import sys


def lookup_pwned_api(pwd):
    """Returns hash and number of times password was seen in pwned database.

    Args:
        pwd: password to check

    Returns:
        A (sha1, count) tuple where sha1 is SHA1 hash of pwd and count is number
        of times the password was seen in the pwned database.  count equal zero
        indicates that password has not been found.

    Raises:
        RuntimeError: if there was an error trying to fetch data from pwned
            database.
    """
    sha1pwd = hashlib.sha1(pwd.encode('ascii')).hexdigest().upper()
    head, tail = sha1pwd[:5], sha1pwd[5:]
    url = 'https://api.pwnedpasswords.com/range/' + head
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError('Error fetching "{}": {}'.format(
            url, res.status_code))
    hash_tail_counts = dict(line.split(':') for line in res.text.splitlines())
    count = hash_tail_counts.get(tail,0)
    return sha1pwd, count


def main(args):
    ec = 0
    for pwd in args or sys.stdin:
        pwd = pwd.strip()
        try:
            sha1pwd, count = lookup_pwned_api(pwd)

            if count:
                print(f"{pwd} was found with {count} occurrences (hash: {sha1pwd})")
                ec = 1
            else:
                print(pwd, "was not found")
        except:
            print(f"{pwd} could not be checked: {sys.exc_info()[1]}")
            ec = 1
            continue
    return ec


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
