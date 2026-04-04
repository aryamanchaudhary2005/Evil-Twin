"""
known_networks.py - Trusted WiFi Network Database
==================================================
Manages the JSON database of known/trusted WiFi network fingerprints.

This database is used by the analyzer to detect anomalies such as:
- A known WPA2 network suddenly appearing as Open
- A known network appearing on an unexpected channel
- An unrecognized BSSID for a familiar SSID

The database is stored in known_wifi.json in the application directory.
"""

import json
import os
from scanner import get_connected_profile_names, get_profile_details

# Path to the persistent trusted-network JSON database
_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "known_wifi.json")


def load_known_networks() -> dict:
    """
    Load the trusted network database from known_wifi.json.

    If the file does not exist, returns an empty dict.

    Returns:
        Dict keyed by SSID with fingerprint data:
        {
            "CampusWiFi": {
                "security": "WPA2-Personal",
                "trusted_bssids": ["00:11:22:33:44:55"],
                "channels": [6],
                "last_seen": "2024-01-01"
            }
        }
    """
    if not os.path.isfile(_DB_PATH):
        return {}
    try:
        with open(_DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Sanitize: old format may have plain strings as values instead of dicts
        sanitized = {}
        for ssid, val in data.items():
            if ssid.startswith("_"):
                continue  # skip comment keys
            if isinstance(val, dict):
                sanitized[ssid] = val
            elif isinstance(val, str):
                sanitized[ssid] = {"security": val, "trusted_bssids": [], "channels": []}
        print(f"[KnownNetworks] Loaded {len(sanitized)} trusted networks.")
        return sanitized
    except (json.JSONDecodeError, OSError) as e:
        print(f"[KnownNetworks] Error loading database: {e}")
        return {}


def save_known_networks(known: dict) -> bool:
    """
    Persist the trusted network database to known_wifi.json.

    Args:
        known: Dict of trusted network fingerprints.

    Returns:
        True on success, False on failure.
    """
    try:
        with open(_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(known, f, indent=2, ensure_ascii=False)
        print(f"[KnownNetworks] Saved {len(known)} trusted networks.")
        return True
    except OSError as e:
        print(f"[KnownNetworks] Error saving database: {e}")
        return False


def import_from_windows_profiles() -> dict:
    """
    Import trusted WiFi fingerprints from Windows saved profiles.

    Uses 'netsh wlan show profiles' and per-profile detail queries
    to populate the trusted network database.

    Returns:
        Dict of trusted network fingerprints (same format as load_known_networks).
    """
    known = load_known_networks()
    profile_names = get_connected_profile_names()

    for name in profile_names:
        details = get_profile_details(name)
        ssid = details.get("ssid", name)

        if ssid not in known:
            # Create a new entry with just the security info
            # (we don't know the BSSID unless the user is currently connected)
            known[ssid] = {
                "security": details.get("security", "Unknown"),
                "trusted_bssids": [],
                "channels": [],
            }
            print(f"[KnownNetworks] Imported profile: {ssid} ({details.get('security')})")
        else:
            # Update security info but preserve trusted BSSIDs
            known[ssid]["security"] = details.get("security", known[ssid].get("security", "Unknown"))

    save_known_networks(known)
    return known


def add_trusted_network(ssid: str, bssid: str, security: str, channel: int, known: dict) -> dict:
    """
    Mark a specific network as trusted and add its fingerprint.

    Args:
        ssid:     Network SSID.
        bssid:    Access point BSSID/MAC.
        security: Security type string (e.g., "WPA2-Personal").
        channel:  Operating channel number.
        known:    Existing known-networks dict to update.

    Returns:
        Updated known-networks dict.
    """
    if ssid not in known:
        known[ssid] = {
            "security": security,
            "trusted_bssids": [],
            "channels": [],
        }

    entry = known[ssid]

    # Add BSSID if not already trusted
    if bssid and bssid not in entry.get("trusted_bssids", []):
        entry.setdefault("trusted_bssids", []).append(bssid)

    # Record channel if not already known
    if channel and channel not in entry.get("channels", []):
        entry.setdefault("channels", []).append(channel)

    # Update security (prefer stricter/newer value)
    entry["security"] = security

    save_known_networks(known)
    return known


def remove_trusted_network(ssid: str, known: dict) -> dict:
    """
    Remove a network from the trusted database.

    Args:
        ssid:  SSID to remove.
        known: Existing dict to modify.

    Returns:
        Updated dict with the SSID removed (if present).
    """
    if ssid in known:
        del known[ssid]
        save_known_networks(known)
        print(f"[KnownNetworks] Removed trusted entry: {ssid}")
    return known


def is_known_network(ssid: str, known: dict) -> bool:
    """Check if an SSID exists in the trusted database."""
    return ssid in known


def get_trusted_bssids(ssid: str, known: dict) -> list[str]:
    """Return the list of trusted BSSIDs for a given SSID."""
    return known.get(ssid, {}).get("trusted_bssids", [])


def get_known_security(ssid: str, known: dict) -> str:
    """Return the expected security type for a known SSID."""
    return known.get(ssid, {}).get("security", "Unknown")


def get_known_channels(ssid: str, known: dict) -> list[int]:
    """Return the list of channels a known SSID has been seen on."""
    return known.get(ssid, {}).get("channels", [])
