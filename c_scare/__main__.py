# SPDX-License-Identifier: GPL-2.0-only
"""
C-Scare package main entry point.

This allows running the package as:
    python -m c_scare <command>

Which is equivalent to:
    python -m c_scare.runner <command>
"""

import sys
from .runner import main

if __name__ == '__main__':
    sys.exit(main())