#!/usr/bin/env python3
"""Point d'entree de fwmon."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fwmon.tui import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
