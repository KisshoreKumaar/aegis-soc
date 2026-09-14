#!/usr/bin/env python3
"""Generate synthetic canonical telemetry as JSON Lines, without running an attack."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from aegis.demo import SCENARIOS, scenario

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--scenario', choices=[s['id'] for s in SCENARIOS], default='attack-chain')
args = parser.parse_args()
for event in scenario(args.scenario):
    print(json.dumps(event))
