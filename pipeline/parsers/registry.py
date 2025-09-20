"""
Registry Parser with MITRE ATT&CK Integration
Parses registry hives and maps findings to MITRE ATT&CK techniques
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

# Import MITRE mapping
from pipeline.utils.mitre_mapping import analyze_registry_artifacts, get_technique_by_registry_key

logger = logging.getLogger(__name__)

def parse_registry_hive(hive_path: Path, hive_type: str = "NTUSER") -> List[Dict[str, Any]]:
    """
    Parse a registry hive and extract relevant keys for MITRE ATT&CK analysis
    
    Args:
        hive_path: Path to the registry hive file
        hive_type: Type of hive (NTUSER, SYSTEM, SOFTWARE, SAM)
        
    Returns:
        List of registry events with MITRE ATT&CK mappings
    """
    events = []
    
    try:
        # Define key paths to extract based on hive type
        key_paths = get_key_paths_by_hive_type(hive_type)
        
        for key_path in key_paths:
            # Simulate registry key extraction (replace with actual registry parsing)
            registry_data = extract_registry_key_data(hive_path, key_path)
            
            if registry_data:
                # Map to MITRE ATT&CK techniques
                mitre_matches = get_technique_by_registry_key(key_path)
                
                event = {
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "registry_key",
                    "hive_type": hive_type,
                    "key_path": key_path,
                    "data": registry_data,
                    "mitre_techniques": mitre_matches,
                    "severity": "high" if mitre_matches else "low"
                }
                
                events.append(event)
                
                if mitre_matches:
                    logger.warning(f"Suspicious registry key found: {key_path}")
                    for match in mitre_matches:
                        logger.warning(f"  -> {match['technique_id']}: {match['technique_name']}")
    
    except Exception as e:
        logger.error(f"Error parsing registry hive {hive_path}: {e}")
    
    return events

def get_key_paths_by_hive_type(hive_type: str) -> List[str]:
    """
    Get relevant registry key paths based on hive type
    
    Args:
        hive_type: Type of registry hive
        
    Returns:
        List of key paths to extract
    """
    key_mappings = {
        "NTUSER": [
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowSuperHidden"
        ],
        "SYSTEM": [
            "CurrentControlSet\\Services",
            "CurrentControlSet\\Control\\Terminal Server",
            "CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
            "CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"
        ],
        "SOFTWARE": [
            "Microsoft\\Windows\\CurrentVersion\\Run",
            "Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
            "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
            "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
            "Policies\\Microsoft\\Windows Defender",
            "Microsoft\\Windows Defender\\Real-Time Protection"
        ],
        "SAM": [
            "SAM\\Domains\\Account\\Users"
        ]
    }
    
    return key_mappings.get(hive_type, [])

def extract_registry_key_data(hive_path: Path, key_path: str) -> Dict[str, Any]:
    """
    Extract data from a specific registry key
    This is a placeholder - replace with actual registry parsing logic
    
    Args:
        hive_path: Path to registry hive
        key_path: Registry key path to extract
        
    Returns:
        Dictionary containing key data
    """
    # Placeholder implementation
    # In a real implementation, you would use libraries like regipy or winreg
    return {
        "key_exists": True,
        "last_modified": datetime.now().isoformat(),
        "values": {
            "sample_value": "sample_data"
        }
    }

def analyze_registry_for_attacks(registry_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze registry events for potential attack techniques
    
    Args:
        registry_events: List of registry events
        
    Returns:
        Analysis results with MITRE ATT&CK mappings
    """
    # Extract registry keys from events
    registry_keys = [event["key_path"] for event in registry_events]
    
    # Analyze using MITRE mapping
    analysis = analyze_registry_artifacts(registry_keys)
    
    # Add additional context
    analysis["total_events"] = len(registry_events)
    analysis["events_with_techniques"] = len([e for e in registry_events if e.get("mitre_techniques")])
    
    return analysis

def generate_mitre_report(analysis_results: Dict[str, Any]) -> str:
    """
    Generate a human-readable MITRE ATT&CK report
    
    Args:
        analysis_results: Results from registry analysis
        
    Returns:
        Formatted report string
    """
    report = []
    report.append("=== MITRE ATT&CK Registry Analysis Report ===\n")
    
    report.append(f"Total Registry Artifacts: {analysis_results['total_artifacts']}")
    report.append(f"Events with MITRE Techniques: {analysis_results['events_with_techniques']}\n")
    
    if analysis_results["matched_techniques"]:
        report.append("DETECTED ATTACK TECHNIQUES:")
        report.append("-" * 40)
        
        for tactic, techniques in analysis_results["matched_techniques"].items():
            report.append(f"\n{tactic}:")
            for technique in techniques:
                report.append(f"  - {technique}")
    
    if analysis_results["suspicious_keys"]:
        report.append("\nSUSPICIOUS REGISTRY KEYS:")
        report.append("-" * 40)
        
        for key_info in analysis_results["suspicious_keys"]:
            report.append(f"\nKey: {key_info['key']}")
            for technique in key_info["techniques"]:
                report.append(f"  -> {technique['technique_id']}: {technique['technique_name']}")
    
    return "\n".join(report)

def parse(evidence_path: Path) -> List[Dict[str, Any]]:
    """
    Main parsing function for registry analysis
    Integrates with the existing Chronos pipeline
    
    Args:
        evidence_path: Path to evidence (disk image, memory dump, etc.)
        
    Returns:
        List of parsed registry events with MITRE mappings
    """
    events = []
    
    # This would integrate with your existing evidence mounting/parsing logic
    # For now, return empty list as placeholder
    logger.info("Registry parsing with MITRE ATT&CK integration not yet fully implemented")
    
    return events
