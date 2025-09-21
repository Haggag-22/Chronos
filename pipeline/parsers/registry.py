from pathlib import Path
from regipy import RegistryHive
from regipy.utils import convert_wintime
from regipy.exceptions import RegistryKeyNotFoundException
from pipeline.utils.mitre_registry_mapping import ALL_REGISTRY_KEYS  # import the generated list

def to_iso(ts):
    if isinstance(ts, int):
        try:
            return convert_wintime(ts).isoformat()
        except Exception:
            return "Unknown"
    elif hasattr(ts, "isoformat"):
        return ts.isoformat()
    return "Unknown"

def normalize_hive_path(hive_path: str) -> str:
    p = Path(hive_path).expanduser().resolve()
    return str(p).replace("/", "\\")

def open_hive(hive_path: str) -> RegistryHive:
    system_path = normalize_hive_path(hive_path)
    return RegistryHive(system_path)

def print_header(key_path: str, key) -> None:
    print(f"\nRegistry Key: {key_path}")
    print("-" * 60)
    print(f"Subkey Name : {key.name}")
    ts = to_iso(getattr(getattr(key, "header", None), "last_modified", None))
    print(f"Last Written: {ts}\n")

def print_values(key) -> None:
    values = list(key.iter_values())
    if values:
        print("Values:")
        for i, val in enumerate(values, 1):
            name = val.name or "(Default)"
            print(f"{i}. {name} = {val.value} ({val.value_type})")
    else:
        print("No values")

def print_subkeys(key) -> None:
    subs = list(key.iter_subkeys())
    if subs:
        print("\nSubkeys:")
        for s in subs:
            print(f" - {s.name}")
    else:
        print("\nNo subkeys")

def contains_placeholders(path: str) -> bool:
    # Skip keys with placeholders/wildcards that are not literal registry keys
    for token in ("<", ">", "{", "}", "*", "..."):
        if token in path:
            return True
    return False

def top_level_segment(path: str) -> str:
    # return first path component: for "Software\\Microsoft\\..." -> "Software"
    p = path.lstrip("\\")
    return p.split("\\", 1)[0] if p else ""

def main():
    hive_path = "C:/Temp/NTUSER.DAT"   # replace or accept from CLI
    hive = open_hive(hive_path)

    # Build a set of available top-level keys on this hive to short-circuit accesses
    try:
        root_subs = {s.name for s in hive.root.subkeys}  # regipy exposes hive.root.subkeys list
    except Exception:
        # fallback: try to list first-level keys via get_key of common names
        root_subs = set()

    print(f"Top-level keys in this hive:\n\\ " + "\n\\ ".join(sorted(root_subs)))
    print()

    # Counters
    total_keys = len(ALL_REGISTRY_KEYS)
    skipped_placeholders = 0
    skipped_top_missing = 0
    accessed_success = 0
    key_not_found = 0
    other_errors = 0

    # Iterate mapping keys
    for raw_key in ALL_REGISTRY_KEYS:
        # normalize to use backslashes and no leading slash (regipy accepts both)
        key_path = raw_key.replace("/", "\\").lstrip("\\")
        if contains_placeholders(key_path):
            # skip placeholder-like entries (these aren't literal keys)
            skipped_placeholders += 1
            print(f"[!] Skipping placeholder/wildcard key: {raw_key}")
            continue

        top = top_level_segment(key_path)
        if root_subs and top and top not in root_subs:
            # probably not present in this hive (different hive type) -> skip
            skipped_top_missing += 1
            print(f"[!] Top-level segment missing in hive, skipping {raw_key} (missing '{top}')")
            continue

        # try the key with a leading backslash (Regipy accepts either)
        try:
            key = hive.get_key("\\" + key_path)
        except RegistryKeyNotFoundException as e:
            # helpful diagnostic and continue
            key_not_found += 1
            print(f"[!] Could not access {key_path}: {e}")
            continue
        except Exception as e:
            other_errors += 1
            print(f"[!] Unexpected error accessing {key_path}: {type(e).__name__}: {e}")
            continue

        # Print header/values/subkeys
        try:
            print_header(key_path, key)
            print_values(key)
            print_subkeys(key)
            accessed_success += 1
        except Exception as e:
            other_errors += 1
            print(f"[!] Error printing data for {key_path}: {type(e).__name__}: {e}")

    attempted = total_keys - skipped_placeholders - skipped_top_missing
    success_rate = (accessed_success / attempted * 100) if attempted else 0.0

    # Summary
    print("\n" + "="*60)
    print("Summary:")
    print(f" Total mapping keys                : {total_keys}")
    print(f" Skipped (placeholders/wildcards)  : {skipped_placeholders}")
    print(f" Skipped (top-level missing)       : {skipped_top_missing}")
    print(f" Attempted to access keys          : {attempted}")
    print(f" Successfully accessed keys        : {accessed_success}")
    print(f" Keys not found                    : {key_not_found}")
    print(f" Other errors                      : {other_errors}")
    print(f" Access success rate               : {accessed_success}/{attempted} ({success_rate:.1f}%)")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
