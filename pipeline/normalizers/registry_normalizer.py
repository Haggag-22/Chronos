def normalize_registry_event(event: dict) -> dict:
    """
    Normalize a Registry event into the standard schema.
    Extracts LastWrite timestamp if available.
    """
    data = event.get("data", {})
    return {
        "timestamp": data.get("last_write") or event.get("timestamp"),
        "source": "registry",
        "plugin": event.get("plugin"),
        "hive": event.get("hive"),
        "key_path": data.get("key_path"),
        "value_name": data.get("name"),
        "value_data": data.get("value"),
        "severity": event.get("severity", "info")
    }