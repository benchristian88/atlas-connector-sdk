# SPDX-License-Identifier: Apache-2.0
"""Build a versioned wheel with a fixed SOURCE_DATE_EPOCH and pinned backend."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    subprocess.run([sys.executable, "-m", "build", "--wheel", "--no-isolation", *sys.argv[1:]],
                   cwd=ROOT, env={**os.environ, "SOURCE_DATE_EPOCH": "315532800"}, check=True)
