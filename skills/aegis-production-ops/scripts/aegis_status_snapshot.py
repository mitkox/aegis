#!/usr/bin/env python3
"""Read-only Aegis host status snapshot."""

import json
import os
import shutil
import subprocess
from pathlib import Path


def run(argv):
    if shutil.which(argv[0]) is None:
        return {"available": False, "argv": argv}
    completed = subprocess.run(argv, check=False, text=True, capture_output=True)
    return {
        "available": True,
        "argv": argv,
        "status": completed.returncode,
        "stdout": completed.stdout[:20000],
        "stderr": completed.stderr[:20000],
    }


def main():
    snapshot = {
        "hostname": os.uname().nodename,
        "aegis_audit_log": str(Path("/var/log/aegis/audit.jsonl")),
        "commands": {
            "aegis_doctor": run(["aegis", "doctor"]),
            "apt_sources": run(["apt-cache", "policy"]),
        },
    }
    print(json.dumps(snapshot, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
