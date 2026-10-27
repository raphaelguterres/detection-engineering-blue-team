window.DETECTION_DASHBOARD = {
  "summary": {
    "detections": 5,
    "techniques": 5,
    "tactics": 3,
    "regression_pairs": 5
  },
  "tactics": {
    "defense-evasion": 1,
    "execution": 1,
    "persistence": 3
  },
  "severities": {
    "high": 3,
    "medium": 2
  },
  "detections": [
    {
      "id": "DET-WIN-LOCALACCOUNT-001",
      "technique": "T1136.001",
      "tactic": "persistence",
      "severity": "high",
      "status": "production",
      "simulation": "simulations/windows/net-user-add.md"
    },
    {
      "id": "DET-WIN-PS-ENC-001",
      "technique": "T1059.001",
      "tactic": "execution",
      "severity": "high",
      "status": "production",
      "simulation": "simulations/windows/powershell-encoded-command.md"
    },
    {
      "id": "DET-WIN-RUNDLL32-001",
      "technique": "T1218.011",
      "tactic": "defense-evasion",
      "severity": "medium",
      "status": "production",
      "simulation": "simulations/windows/rundll32-user-writable-path.md"
    },
    {
      "id": "DET-WIN-RUNKEY-001",
      "technique": "T1547.001",
      "tactic": "persistence",
      "severity": "high",
      "status": "production",
      "simulation": "simulations/windows/run-key-modification.md"
    },
    {
      "id": "DET-WIN-SCHTASKS-001",
      "technique": "T1053.005",
      "tactic": "persistence",
      "severity": "medium",
      "status": "production",
      "simulation": "simulations/windows/schtasks-create.md"
    }
  ]
};
