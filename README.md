# ⏱️ Chronos: Automated Forensic Artifact Pipeline

Chronos is a forensic analysis framework that automates the ingestion, parsing, normalization, and reporting of digital artifacts.  
It is built for **incident responders, forensic analysts, and detection engineers** who need a fast and extensible way to process evidence.

---

##  Features
- **Evidence ingestion**: Supports disk images, memory dumps, registry hives, MFT, and Prefetch files.  
- **Automated parsing**: Modular parsers for Registry, Prefetch, MFT, Disk, and Memory artifacts.  
- **Normalization layer**: Converts raw parser outputs into a unified JSONL schema.  
- **Reporting**: Generates manifest, events timeline, and results JSON for every case.  
- **CLI Tooling**: Simple and extensible CLI powered by [Typer](https://typer.tiangolo.com/).  



