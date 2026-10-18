import argparse
import sys

from core.generator import generate_password


def main() -> int:
    p = argparse.ArgumentParser(description="KeyForge password generator")
    p.add_argument("-l", "--length", type=int, default=20)
    p.add_argument("--no-upper", action="store_true")
    p.add_argument("--no-lower", action="store_true")
    p.add_argument("--no-digits", action="store_true")
    p.add_argument("--no-symbols", action="store_true")
    a = p.parse_args()
    try:
        pw = generate_password(
            a.length,
            upper=not a.no_upper,
            lower=not a.no_lower,
            digits=not a.no_digits,
            symbols=not a.no_symbols,
        )
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(pw)
    return 0


if __name__ == "__main__":
    sys.exit(main())
