import json
import logging
from pathlib import Path
from regipy.registry import RegistryHive
from regipy.plugins.utils import run_relevant_plugins

# Silence noisy regipy decoding logs
logging.getLogger("regipy").setLevel(logging.ERROR)

def parse(hive_path: Path):
    """Parse a registry hive using regipy plugins and return events."""
    hive = RegistryHive(str(hive_path))
    output = run_relevant_plugins(hive, as_json=True)

    events = []
    for plugin_name, results in output.items():
        if not results:
            continue
        # Normalize each plugin result into your pipeline schema
        for entry in results if isinstance(results, list) else [results]:
            events.append({
                "source": "registry",
                "plugin": plugin_name,
                "hive": hive_path.name,
                "data": entry
            })
    return events
