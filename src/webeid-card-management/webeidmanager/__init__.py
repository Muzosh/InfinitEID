from pathlib import Path

import yaml

config_dir = Path(__file__).resolve().parent.parent / "config"

with open(config_dir / "config.yaml", encoding="utf8") as f:
    CONFIG = dict(yaml.safe_load(f))
with open(config_dir / "apdulist.yaml", encoding="utf8") as f:
    APDU_LIST = dict(yaml.safe_load(f))
