#!/usr/bin/env python3
"""
Zero-Trust Cloud Edge & Intelligent WAF Bot Defense Mesh - Root CLI Entrypoint
"""
import sys
from src.cli import main

if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.argv.append("simulate")
    main()
