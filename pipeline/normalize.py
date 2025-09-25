from pipeline.normalizers import (
    normalize_registry_event,
    normalize_mft_event,
    normalize_prefetch_event,
    normalize_memory_event,
    normalize_disk_event
)


def normalize_events(event: dict) -> dict:
    """Dispatch event to the correct normalizer based on its source."""
    source = event.get("source", "").lower()

    if source == "registry":
        return normalize_registry_event(event)
    elif source == "mft":
        return normalize_mft_event(event)
    elif source == "prefetch":
        return normalize_prefetch_event(event)
    elif source == "memory":
        return normalize_memory_event(event)
    elif source == "disk":
        return normalize_disk_event(event)
    else:
       print("Normalization Failed")
