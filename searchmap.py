#!/usr/bin/env python3
"""searchmap launcher — keeps ~/.local/bin/searchmap working without install.
The implementation lives in the `smap` package next to this file."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from smap.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
