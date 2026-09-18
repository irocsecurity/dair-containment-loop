# Copyright 2026 IROC Security LLC
# SPDX-License-Identifier: Apache-2.0

"""Entry point: ``python -m dair_containment``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
