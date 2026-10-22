"""
Evidence-based MITRE ATT&CK mapping rules.

These rules map behavioral evidence found in CTI text
to candidate MITRE ATT&CK technique IDs.

An IOC itself is NOT directly mapped to an ATT&CK technique.
"""

ATTACK_RULES = [
    {
        "technique_id": "T1059.001",
        "keywords": [
            "powershell",
            "power shell",
            "powershell.exe",
            "invoke-expression",
            "invoke expression",
            "pwsh"
        ],
        "evidence_type": "behavior",
        "confidence": 0.90
    },

    {
        "technique_id": "T1059.003",
        "keywords": [
            "windows command shell",
            "cmd.exe",
            "command prompt",
            "cmd /c"
        ],
        "evidence_type": "behavior",
        "confidence": 0.90
    },

    {
        "technique_id": "T1059.004",
        "keywords": [
            "unix shell",
            "linux shell",
            "bash",
            "sh -c",
            "/bin/bash"
        ],
        "evidence_type": "behavior",
        "confidence": 0.90
    },

    {
        "technique_id": "T1105",
        "keywords": [
            "downloaded a file",
            "download file",
            "downloaded payload",
            "download  payload",
            "download a payload",
            "downloaded malware",
            "transfer tool",
            "transferred tool",
            "wget",
            "curl"
        ],
        "evidence_type": "behavior",
        "confidence": 0.85
    },

    {
        "technique_id": "T1047",
        "keywords": [
            "windows management instrumentation",
            "wmi",
            "wmic",
            "wmic.exe"
        ],
        "evidence_type": "behavior",
        "confidence": 0.90
    },

    {
        "technique_id": "T1053",
        "keywords": [
            "scheduled task",
            "scheduled task created",
            "scheduled task was created",
            "task scheduler"
        ],
        "evidence_type": "behavior",
        "confidence": 0.85
    },

    {
        "technique_id": "T1027",
        "keywords": [
            "obfuscated",
            "obfuscation",
            "encoded powershell",
            "encoded command",
            "base64 encoded",
            "base64-encoded"
        ],
        "evidence_type": "behavior",
        "confidence": 0.80
    },

    {
        "technique_id": "T1003",
        "keywords": [
            "credential dumping",
            "dump credentials",
            "dumped credentials",
            "lsass dump",
            "lsass memory",
            "security account manager",
            "sam database"
        ],
        "evidence_type": "behavior",
        "confidence": 0.90
    },

    {
        "technique_id": "T1560",
        "keywords": [
            "archive collected data",
            "archived collected data",
            "compressed collected data",
            "compressed files",
            "created zip archive",
            "zip archive"
        ],
        "evidence_type": "behavior",
        "confidence": 0.80
    },

    {
        "technique_id": "T1036",
        "keywords": [
            "masquerading",
            "masqueraded",
            "renamed executable",
            "renamed malware",
            "legitimate filename"
        ],
        "evidence_type": "behavior",
        "confidence": 0.75
    }
]