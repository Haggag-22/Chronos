from typing import Dict, List

MITRE_REGISTRY_MAPPING = {
    "TA0001": {
        "tactic": "Initial Access",
        "techniques": {
            "T1055": {
                "name": "Process Injection",
                "registry_keys": [
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit"
                ]
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "registry_keys": [
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
                ]
            }
        }
    },
    
    "TA0002": {
        "tactic": "Execution",
        "techniques": {
            "T1559": {
                "name": "Inter-Process Communication",
                "registry_keys": [
                    "Software\\Classes\\AppID",
                    "Software\\Microsoft\\Ole"
                ]
            },
            "T1053": {
                "name": "Scheduled Task/Job",
                "registry_keys": [
                    "System\\CurrentControlSet\\Control\\Lsa\\SubmitControl",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks",
                    "System\\CurrentControlSet\\Services"
                ]
            },
            "T1204": {
                "name": "User Execution",
                "registry_keys": [
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
                ]
            }
        }
    },
    
    "TA0003": {
        "tactic": "Persistence",
        "techniques": {
            "T1098": {
                "name": "Account Manipulation",
                "registry_keys": [

                    "System\\CurrentControlSet\\Control\\Lsa",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList"
                ]
            },
            "T1197": {
                "name": "BITS Jobs",
                "registry_keys": [
                    "Software\\Microsoft\\Windows\\CurrentVersion\\BITS",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\BITS"
                ]
            },
            "T1547": {
                "name": "Boot or Logon Autostart Execution",
                "registry_keys": [
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\load",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                    "Software\\Microsoft\\Active Setup\\Installed Components",
                    "System\\CurrentControlSet\\Control\\Session Manager\\SafeDllSearchMode",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
                    "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
                ]
            },
            "T1037": {
                "name": "Boot or Logon Initialization Scripts",
                "registry_keys": [
                    "Software\\Policies\\Microsoft\\Windows\\System\\Scripts",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
                ]
            },
            "T1671": {
                "name": "Cloud Application Integration",
                "registry_keys": [
                    "Software\\<CloudVendorOrApp>",
                    "Software\\<CloudVendorOrApp>"
                ]
            },
            "T1554": {
                "name": "Compromise Host Software Binary",
                "registry_keys": [
                    "System\\CurrentControlSet\\Services\\<ServiceName>\\ImagePath",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs"
                ]
            },
            "T1136": {
                "name": "Create Account",
                "registry_keys": [
                    "SAM",
                    "System\\CurrentControlSet\\Services\\<ServiceName>\\ObjectName"
                ]
            },
            "T1543": {
                "name": "Create or Modify System Process",
                "registry_keys": [
                    "System\\CurrentControlSet\\Services",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
                    "System\\CurrentControlSet\\Services\\<ServiceName>\\ImagePath"
                ]
            },
            "T1546": {
                "name": "Event Triggered Execution",
                "registry_keys": [
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
                ]
            },
            "T1668": {
                "name": "Exclusive Control",
                "registry_keys": []
            },
            "T1133": {
                "name": "External Remote Services",
                "registry_keys": [
                    "System\\CurrentControlSet\\Services\\TermService",
                    "System\\CurrentControlSet\\Services\\RpcSs"
                ]
            },
            "T1574": {
                "name": "Hijack Execution Flow",
                "registry_keys": [
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
                    "Software\\Classes\\exefile\\shell\\open\\command",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\ShellExecuteHooks"
                ]
            },
            "T1525": {
                "name": "Implant Internal Image",
                "registry_keys": []
            },
            "T1556": {
                "name": "Modify Authentication Process",
                "registry_keys": [
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers",
                    "System\\CurrentControlSet\\Control\\Lsa",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify"
                ]
            },
            "T1112": {
                "name": "Modify Registry",
                "registry_keys": [
                    "Software\\*",
                    "Software\\*",
                    "System\\CurrentControlSet\\Services\\<ServiceName>\\Parameters"
                ]
            },
            "T1137": {
                "name": "Office Application Startup",
                "registry_keys": [
                    "Software\\Microsoft\\Office\\<Version>\\<App>\\Startup",
                    "Software\\Microsoft\\Office\\<Version>\\<App>\\Startup",
                    "Software\\Microsoft\\Office\\<App>\\Addins\\<AddinName>",
                    "Software\\Classes\\CLSID\\{...}"
                ]
            },
            "T1653": {
                "name": "Power Settings",
                "registry_keys": [
                    "System\\CurrentControlSet\\Control\\Power",
                    "Control Panel\\PowerCfg"
                ]
            },
            "T1542": {
                "name": "Pre-OS Boot",
                "registry_keys": [
                    "System\\CurrentControlSet\\Services\\<BootDriverService>",
                    "System\\CurrentControlSet\\Control\\BootStatusPolicy"
                ]
            },
            "T1053": {
                "name": "Scheduled Task/Job",
                "registry_keys": [
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"
                ]
            },
            "T1505": {
                "name": "Server Software Component",
                "registry_keys": [
                    "Software\\<ServerVendor>",
                    "System\\CurrentControlSet\\Services\\<ServerService>"
                ]
            },
            "T1176": {
                "name": "Software Extensions",
                "registry_keys": [
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",
                    "Software\\Policies\\Google\\Chrome\\Extensions"
                ]
            },
            "T1205": {
                "name": "Traffic Signaling",
                "registry_keys": []
            },
            "T1078": {
                "name": "Valid Accounts",
                "registry_keys": [
                    "SAM",
                    "System\\CurrentControlSet\\Services\\<ServiceName>\\ObjectName"
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
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorUser"
                ]
            },
            "T1547": {
                "name": "Boot or Logon Autostart Execution",
                "registry_keys": [
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell"
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
                    "Software\\Policies\\Microsoft\\Windows Defender",
                    "Software\\Microsoft\\Windows Defender\\Real-Time Protection",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoFolderOptions",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools"
                ]
            },
            "T1574": {
                "name": "Hijack Execution Flow",
                "registry_keys": [
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                    "Software\\Classes\\exefile\\shell\\open\\command"
                ]
            },
            "T1036": {
                "name": "Masquerading",
                "registry_keys": [
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
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
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowSuperHidden"
                ]
            },
            "T1016": {
                "name": "System Network Configuration Discovery",
                "registry_keys": [
                    "System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures"
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
                    "System\\CurrentControlSet\\Control\\Terminal Server",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA"
                ]
            },
            "T1076": {
                "name": "Remote Desktop Protocol",
                "registry_keys": [
                    "System\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections",
                    "System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
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
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyEnable",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer"
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
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyEnable",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections"
                ]
            },
            "T1055": {
                "name": "Process Injection",
                "registry_keys": [
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
                ]
            }
        }
    }
}


ALL_REGISTRY_KEYS=[
    "Software\\Classes\\AppID",
    "Software\\Classes\\exefile\\shell\\open\\command",
    "Software\\Microsoft\\Active Setup\\Installed Components",
    "Software\\Microsoft\\Office\\<App>\\Addins\\<AddinName>",
    "Software\\Microsoft\\Office\\<Version>\\<App>\\Startup",
    "Software\\Microsoft\\Ole",
    "Software\\Microsoft\\Windows Defender\\Real-Time Protection",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\load",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers",
    "Software\\Microsoft\\Windows\\CurrentVersion\\BITS",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowSuperHidden",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyEnable",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoFolderOptions",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorUser",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\ShellExecuteHooks",
    "Software\\Policies\\Google\\Chrome\\Extensions",
    "Software\\Policies\\Microsoft\\Windows Defender",
    "Software\\Policies\\Microsoft\\Windows\\System\\Scripts",
    "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    
    ## Controls in CurrentControlSet
    "System\\CurrentControlSet\\Control\\BootStatusPolicy",
    "System\\CurrentControlSet\\Control\\Lsa",
    "System\\CurrentControlSet\\Control\\Lsa\\SubmitControl",
    "System\\CurrentControlSet\\Control\\Power",
    "System\\CurrentControlSet\\Control\\Session Manager\\SafeDllSearchMode",
    "System\\CurrentControlSet\\Control\\Terminal Server",
    "System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
    "System\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections",
    
    ## Services in CurrentControlSet
    "System\\CurrentControlSet\\Services",
    "System\\CurrentControlSet\\Services\\<BootDriverService>",
    "System\\CurrentControlSet\\Services\\<ServerService>",
    "System\\CurrentControlSet\\Services\\<ServiceName>\\ImagePath",
    "System\\CurrentControlSet\\Services\\<ServiceName>\\ObjectName",
    "System\\CurrentControlSet\\Services\\<ServiceName>\\Parameters",
    "System\\CurrentControlSet\\Services\\RpcSs",
    "System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
    "System\\CurrentControlSet\\Services\\TermService"
]

HIGH_VALUE_SERVICES = {
    "TermService",
    "Schedule",
    "Spooler",
    "BITS",
    "WinRM",
    "RemoteRegistry",
    "RpcSs",
    "EventLog",
    "Tcpip",
    "MsMpSvc",
    "LanmanServer",
    "LanmanWorkstation",
    "TermService"
}
