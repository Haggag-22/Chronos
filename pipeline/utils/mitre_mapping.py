"""
MITRE ATT&CK Registry Key Mapping
Maps tactics and techniques to specific registry keys for forensic analysis
"""

MITRE_REGISTRY_MAPPING = {
    "TA0001": {
        "tactic": "Initial Access",
        "techniques": {
            "T1055": {
                "name": "Process Injection",
                "registry_keys": [
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit"
                ]
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "registry_keys": [
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
                ]
            }
        }
    },
    "TA0003": {
        "tactic": "Persistence",
        "techniques": {
            "T1547": {
                "name": "Boot or Logon Autostart Execution",
                "registry_keys": [
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit"
                ]
            },
            "T1543": {
                "name": "Create or Modify System Process",
                "registry_keys": [
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost"
                ]
            },
            "T1546": {
                "name": "Event Triggered Execution",
                "registry_keys": [
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
                ]
            },
            "T1574": {
                "name": "Hijack Execution Flow",
                "registry_keys": [
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                    "HKLM\\SOFTWARE\\Classes\\exefile\\shell\\open\\command"
                ]
            }
        }
    },
    "TA0004": {
        "tactic": "Privilege Escalation",
        "techniques": {
            "T1548": {
                "name": "Abuse Elevation Control Mechanism",
                "registry_keys": [
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorUser"
                ]
            },
            "T1547": {
                "name": "Boot or Logon Autostart Execution",
                "registry_keys": [
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell"
                ]
            }
        }
    },
    "TA0005": {
        "tactic": "Defense Evasion",
        "techniques": {
            "T1562": {
                "name": "Impair Defenses",
                "registry_keys": [
                    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoFolderOptions",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools"
                ]
            },
            "T1574": {
                "name": "Hijack Execution Flow",
                "registry_keys": [
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                    "HKLM\\SOFTWARE\\Classes\\exefile\\shell\\open\\command"
                ]
            },
            "T1036": {
                "name": "Masquerading",
                "registry_keys": [
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
                ]
            }
        }
    },
    "TA0007": {
        "tactic": "Discovery",
        "techniques": {
            "T1083": {
                "name": "File and Directory Discovery",
                "registry_keys": [
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowSuperHidden"
                ]
            },
            "T1016": {
                "name": "System Network Configuration Discovery",
                "registry_keys": [
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures"
                ]
            }
        }
    },
    "TA0008": {
        "tactic": "Lateral Movement",
        "techniques": {
            "T1021": {
                "name": "Remote Services",
                "registry_keys": [
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA"
                ]
            },
            "T1076": {
                "name": "Remote Desktop Protocol",
                "registry_keys": [
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
                ]
            }
        }
    },
    "TA0010": {
        "tactic": "Exfiltration",
        "techniques": {
            "T1041": {
                "name": "Exfiltration Over C2 Channel",
                "registry_keys": [
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyEnable",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer"
                ]
            }
        }
    },
    "TA0011": {
        "tactic": "Command and Control",
        "techniques": {
            "T1071": {
                "name": "Application Layer Protocol",
                "registry_keys": [
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyEnable",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections"
                ]
            },
            "T1055": {
                "name": "Process Injection",
                "registry_keys": [
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
                ]
            }
        }
    }
}

