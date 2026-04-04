"""
mac_vendor.py - MAC Address OUI Vendor Lookup
==============================================
Identifies the hardware manufacturer from the first 3 octets (OUI)
of a MAC/BSSID address.

Uses a bundled OUI database (oui_database.txt) and falls back to
a built-in dictionary of common vendors.

An unknown or randomized vendor increases the network's risk score
because rogue access points often use cheap or spoofed MAC addresses.
"""

import os
import re

# ---------------------------------------------------------------------------
# Built-in OUI table (fallback if oui_database.txt is missing)
# Covers the most common legitimate AP manufacturers
# ---------------------------------------------------------------------------
BUILTIN_OUI = {
    "00:00:0C": "Cisco",
    "00:0F:66": "Cisco-Linksys",
    "00:17:F2": "Apple",
    "00:1A:2B": "Cisco",
    "00:1C:BF": "Netgear",
    "00:1D:7E": "Cisco-Linksys",
    "00:1E:E5": "Cisco",
    "00:21:29": "Cisco",
    "00:22:55": "Belkin",
    "00:23:69": "Cisco-Linksys",
    "00:24:01": "Netgear",
    "00:26:B9": "Dell",
    "00:50:F2": "Microsoft",
    "00:90:4C": "Epigram",
    "00:A0:C9": "Intel",
    "00:E0:4C": "Realtek",
    "04:18:D6": "Cisco",
    "04:4F:AA": "Zyxel",
    "08:00:27": "VirtualBox",
    "10:02:B5": "Ubiquiti",
    "18:64:72": "Cisco",
    "1C:7E:E5": "Cisco",
    "20:AA:4B": "Cisco",
    "24:A4:3C": "Ubiquiti",
    "28:94:0F": "Ubiquiti",
    "2C:30:33": "Belkin",
    "30:46:9A": "Belkin",
    "38:22:D6": "Cisco",
    "3C:5A:B4": "Google",
    "44:E4:D9": "Ubiquiti",
    "48:5D:36": "Cisco",
    "50:C7:BF": "Tp-Link",
    "5C:AA:FD": "Apple",
    "60:A4:4C": "Cisco",
    "64:66:B3": "Cisco",
    "68:72:51": "Cisco",
    "6C:70:9F": "Cisco",
    "74:EA:3A": "Asus",
    "78:24:AF": "Cisco",
    "7C:2E:BD": "Cisco",
    "80:2A:A8": "Ubiquiti",
    "84:1B:5E": "Cisco",
    "88:1D:FC": "Cisco",
    "8C:3B:AD": "Cisco",
    "90:35:CB": "Apple",
    "90:48:9A": "Cisco",
    "94:D9:B3": "Cisco",
    "98:AC:AC": "Cisco",
    "A0:1D:48": "Netgear",
    "A4:C3:F0": "Apple",
    "AC:84:C6": "Cisco",
    "B0:7F:B9": "Cisco",
    "B4:A9:FC": "Apple",
    "B8:27:EB": "Raspberry Pi",
    "BC:EE:7B": "Apple",
    "C0:25:E9": "Cisco",
    "C4:64:13": "Cisco",
    "C8:4C:75": "Cisco",
    "CC:D4:A1": "Cisco",
    "D0:57:7B": "Tp-Link",
    "D4:CA:6D": "Cisco",
    "D8:67:D9": "Tp-Link",
    "DC:A4:CA": "Apple",
    "E0:CB:1D": "Cisco",
    "E4:8D:8C": "Cisco",
    "E8:65:49": "Cisco",
    "EC:8C:A2": "Cisco",
    "F0:25:72": "Cisco",
    "F4:5C:89": "Apple",
    "F8:1E:DF": "Apple",
    "FC:EC:DA": "Cisco",
    "FC:F8:AE": "Apple",
}

# OUI prefixes associated with randomized/spoofed MACs or cheap chipsets
# These are not inherently malicious but warrant higher scrutiny
SUSPICIOUS_VENDORS = {
    "DE:AD:BE",  # Common in spoofed/fake MACs
    "BA:DC:AF",  # Common in spoofed/fake MACs
    "FA:KE:AC",  # Obviously fake
    "02:00:00",  # Locally administered bit set (randomized MAC)
    "06:00:00",
    "0A:00:00",
    "0E:00:00",
}

# Path to the optional external OUI database
_OUI_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui_database.txt")

# Cache the loaded database to avoid repeated disk reads
_oui_cache: dict[str, str] = {}
_db_loaded = False


def _load_oui_database():
    """
    Load the OUI database from oui_database.txt into memory.
    Falls back to built-in table if the file is unavailable.

    File format (IEEE standard):
        XX-XX-XX   (hex)   VendorName

    or simple tab/space separated:
        XX:XX:XX VendorName
    """
    global _oui_cache, _db_loaded

    if _db_loaded:
        return

    # Always seed with built-in table
    _oui_cache = {k.upper(): v for k, v in BUILTIN_OUI.items()}

    if os.path.isfile(_OUI_DB_PATH):
        try:
            with open(_OUI_DB_PATH, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Support formats: "AA-BB-CC   Vendor" or "AA:BB:CC Vendor"
                    parts = re.split(r'[\s\t]+', line, maxsplit=1)
                    if len(parts) == 2:
                        oui_raw, vendor = parts
                        oui_norm = oui_raw.replace("-", ":").upper()
                        if len(oui_norm) == 8:  # AA:BB:CC
                            _oui_cache[oui_norm] = vendor.strip()
            print(f"[OUI] Loaded {len(_oui_cache)} OUI entries from database.")
        except Exception as e:
            print(f"[OUI] Could not load oui_database.txt: {e}. Using built-in table.")
    else:
        print("[OUI] oui_database.txt not found. Using built-in OUI table.")

    _db_loaded = True


def get_vendor(bssid: str) -> str:
    """
    Identify the hardware vendor from a BSSID/MAC address.

    Extracts the first 3 octets (OUI) and looks them up in the database.

    Args:
        bssid: MAC address string, e.g. "00:1A:2B:3C:4D:5E" or "00-1A-2B-3C-4D-5E".

    Returns:
        Vendor name string, or "Unknown" if not found.
    """
    _load_oui_database()

    if not bssid:
        return "Unknown"

    # Normalize separators to colons and uppercase
    normalized = bssid.replace("-", ":").upper().strip()

    # Check for locally administered bit (bit 1 of first octet) → randomized MAC
    try:
        first_octet = int(normalized.split(":")[0], 16)
        if first_octet & 0x02:
            return "Randomized/Local MAC"
    except (ValueError, IndexError):
        pass

    # Extract OUI (first 3 octets)
    parts = normalized.split(":")
    if len(parts) < 3:
        return "Unknown"

    oui = ":".join(parts[:3])

    # Check suspicious patterns
    if oui in SUSPICIOUS_VENDORS:
        return "Suspicious (Spoofed)"

    vendor = _oui_cache.get(oui, "Unknown")
    return vendor


def is_suspicious_vendor(bssid: str) -> bool:
    """
    Return True if the vendor cannot be identified or appears spoofed.

    Args:
        bssid: MAC address string.

    Returns:
        True if vendor is unknown or suspicious.
    """
    vendor = get_vendor(bssid)
    return vendor in ("Unknown", "Randomized/Local MAC", "Suspicious (Spoofed)")
