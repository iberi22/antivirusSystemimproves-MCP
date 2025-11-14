import psutil
from typing import List, Dict, Any

# A list of suspicious process names. This is a simple example; a real-world
# implementation would use a more sophisticated method of identifying suspicious
# processes.
SUSPICIOUS_PROCESS_NAMES = [
    "mimikatz.exe",
    "powersploit.exe",
    "msfvenom.exe",
]

# A list of sensitive directories that should not be written to by most processes.
SENSITIVE_DIRECTORIES = [
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
]

def check_running_processes() -> List[Dict[str, Any]]:
    """
    Checks running processes for suspicious behavior.

    Returns:
        A list of suspicious findings.
    """
    findings = []
    for proc in psutil.process_iter(['pid', 'name', 'open_files', 'connections']):
        try:
            # Check for suspicious process names
            if proc.info['name'] and proc.info['name'].lower() in SUSPICIOUS_PROCESS_NAMES:
                findings.append({
                    "pid": proc.info['pid'],
                    "name": proc.info['name'],
                    "reason": "Suspicious process name",
                })

            # Check for writing to sensitive directories
            if proc.info['open_files']:
                for file in proc.info['open_files']:
                    for sensitive_dir in SENSITIVE_DIRECTORIES:
                        if file.path.lower().startswith(sensitive_dir.lower()):
                            findings.append({
                                "pid": proc.info['pid'],
                                "name": proc.info['name'],
                                "reason": f"Writing to sensitive directory: {file.path}",
                            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return findings
