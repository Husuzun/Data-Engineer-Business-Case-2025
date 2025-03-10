"""
Configuration settings for the CVE Data Processing Pipeline
"""

# Database Connection Settings
PG_HOST = "localhost"
PG_PORT = 5432
PG_DATABASE = "cvedb"
PG_USER = "postgres"
PG_PASSWORD = "Pass.0210"

# API Settings
OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama2"

# Data Source Settings
ZIP_URL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
EXTRACT_DIR = "cvelist_extracted"

# Cache Settings
OS_CACHE_FILE = "os_cache.json"

# OS Reference List
OS_REFERENCE_LIST = [
    "CentOS 7", "CentOS 8", "CentOS 9",
    "Debian 9", "Debian 10", "Debian 11", "Debian 12",
    "MacOS 11 Big Sur", "MacOS 12 Monterey", "MacOS 13 Ventura", "MacOS 14 Sonoma",
    "Red Hat Enterprise Linux 7", "Red Hat Enterprise Linux 8", "Red Hat Enterprise Linux 9",
    "Rocky Linux 8", "Rocky Linux 9",
    "SUSE 15",
    "Ubuntu 18.04", "Ubuntu 18.10", "Ubuntu 19.04", "Ubuntu 19.10",
    "Ubuntu 20.04", "Ubuntu 20.10", "Ubuntu 21.04", "Ubuntu 21.10",
    "Ubuntu 22.04", "Ubuntu 22.10", "Ubuntu 23.04", "Ubuntu 23.10", "Ubuntu 24.04",
    "Windows 7", "Windows 8.1", "Windows 10", "Windows 11",
    "Windows Server", "Windows Server 2008", "Windows Server 2008 R2",
    "Windows Server 2012", "Windows Server 2012 R2", "Windows Server 2016",
    "Windows Server 2019", "Windows Server 2022", "Windows Server 2025"
]

# OS Aliases (common OS naming variations)
OS_ALIASES = {
    # Red Hat Enterprise Linux kısaltmaları
    "rhel": "Red Hat Enterprise Linux",
    "rhel 9": "Red Hat Enterprise Linux 9",
    "rhel 8": "Red Hat Enterprise Linux 8",
    "rhel 7": "Red Hat Enterprise Linux 7",
    "red hat": "Red Hat Enterprise Linux",
    
    # SUSE Linux kısaltmaları
    "sles": "SUSE 15",
    "suse linux enterprise server": "SUSE 15",
    
    # Genel Linux referansları
    "linux": "Linux Generic",
    "linux kernel": "Linux Generic",
    
    # Diğer OS'ler
    "pan-os": "PAN-OS",  # Palo Alto Networks OS
    "android": "Android",
    "macos": "MacOS"
} 