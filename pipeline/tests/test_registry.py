from pathlib import Path
from pipeline.parsers import registry_ttest   # import your parser module

def main():
    # Point to your test hive (the copy you saved earlier with reg save)
    hive_path = Path(r"C:\Temp\NTUSER.DAT")

    # Call your parser
    results = registry_ttest.parse(hive_path)

    for artifact in results["artifacts"]:
            print(artifact)

if __name__ == "__main__":
    main()
