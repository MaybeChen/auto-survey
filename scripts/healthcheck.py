"""Service-friendly health check returning a nonzero exit code on failure."""
import json
from pathlib import Path
import argparse

from src.config import load_config
from src.health import run_checks

parser = argparse.ArgumentParser()
parser.add_argument("--config", type=Path)
args = parser.parse_args()
result = run_checks(load_config(args.config))
print(json.dumps(result, indent=2, ensure_ascii=False))
raise SystemExit(0 if result["healthy"] else 1)
