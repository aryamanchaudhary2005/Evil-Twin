"""
scanner.py - WiFi Network Scanner
===================================
Handles scanning nearby WiFi networks using Windows 'netsh' command-line tools.
Parses raw netsh output into structured Python dictionaries.

Supports:
- Scanning visible SSIDs and BSSIDs
- Signal strength conversion (% -> dBm)
- Channel, authentication, and encryption extraction
"""

import subprocess
import re
import platform
import random  # Used only for demo/fallback mode on non-Windows systems


def run_netsh(args: list[str]) -> str:
    """
    Execute a netsh command and return its stdout as a string.

    Args:
        args: List of arguments to pass after 'netsh'.

    Returns:
        Command output as a decoded string, or empty string on failure.
    """
    try:
        result = subprocess.run(
            ["netsh"] + args,
            capture_output=True,
            text=True,
            timeout=15,
            encoding="utf-8",
            errors="replace"
        )
        return result.stdout
    except FileNotFoundError:
        # netsh not available (non-Windows system)
        return ""
    except subprocess.TimeoutExpired:
        return ""
    except Exception as e:
        print(f"[Scanner] netsh error: {e}")
        return ""


def signal_percent_to_dbm(percent: int) -> int:
    """
    Convert Windows WiFi signal percentage to approximate dBm.

    Windows reports signal as 0-100%, where:
        100% ≈ -50 dBm (excellent)
          0% ≈ -100 dBm (no signal)

    Formula: dBm = (percent / 2) - 100

    Args:
        percent: Signal strength as integer 0-100.

    Returns:
        Approximate dBm value as negative integer.
    """
    try:
        pct = int(percent)
        dbm = (pct / 2) - 100
        return int(dbm)
    except (ValueError, TypeError):
        return -100


def parse_netsh_networks(raw_output: str) -> list[dict]:
    """
    Parse the output of 'netsh wlan show networks mode=bssid'.

    Extracts per-BSSID records including SSID, BSSID, signal, channel,
    authentication type, and encryption type.

    Args:
        raw_output: Raw string output from netsh.

    Returns:
        List of network dictionaries.
    """
    networks = []
    current_ssid = None
    current_auth = "Unknown"
    current_enc = "Unknown"

    # Split into blocks by SSID header
    # Each SSID block may contain multiple BSSID entries
    ssid_blocks = re.split(r'\nSSID\s+\d+\s*:', raw_output)

    for block in ssid_blocks[1:]:  # Skip text before first SSID
        lines = block.strip().splitlines()
        if not lines:
            continue

        # First line of the block is the SSID name
        current_ssid = lines[0].strip()
        current_auth = "Unknown"
        current_enc = "Unknown"

        # Parse authentication and encryption at SSID level
        for line in lines:
            line_stripped = line.strip()
            if re.match(r'Authentication\s*:', line_stripped):
                current_auth = line_stripped.split(":", 1)[1].strip()
            elif re.match(r'Encryption\s*:', line_stripped):
                current_enc = line_stripped.split(":", 1)[1].strip()

        # Now find all BSSID sub-blocks within this SSID block
        bssid_blocks = re.split(r'\n\s+BSSID\s+\d+\s*:', block)

        for bssid_block in bssid_blocks[1:]:
            bssid_lines = bssid_block.strip().splitlines()
            if not bssid_lines:
                continue

            bssid_val = bssid_lines[0].strip()
            signal_pct = 0
            channel = 0
            bssid_auth = current_auth
            bssid_enc = current_enc

            for bline in bssid_lines[1:]:
                bline = bline.strip()
                if re.match(r'Signal\s*:', bline):
                    sig_str = bline.split(":", 1)[1].strip().replace("%", "")
                    try:
                        signal_pct = int(sig_str)
                    except ValueError:
                        signal_pct = 0
                elif re.match(r'Channel\s*:', bline):
                    ch_str = bline.split(":", 1)[1].strip()
                    try:
                        channel = int(ch_str)
                    except ValueError:
                        channel = 0

            # Build security string like "WPA2-Personal"
            security = build_security_string(bssid_auth, bssid_enc)

            network = {
                "ssid": current_ssid,
                "bssid": bssid_val.upper(),
                "signal": signal_percent_to_dbm(signal_pct),
                "signal_pct": signal_pct,
                "channel": channel,
                "authentication": bssid_auth,
                "encryption": bssid_enc,
                "security": security,
            }
            networks.append(network)

    return networks


def build_security_string(auth: str, enc: str) -> str:
    """
    Combine authentication and encryption into a human-readable security string.

    Args:
        auth: Authentication type (e.g., 'WPA2-Personal').
        enc:  Encryption type (e.g., 'CCMP').

    Returns:
        Formatted security string.
    """
    auth = auth.strip()
    enc = enc.strip()

    if auth in ("Open", ""):
        return "Open"
    if "WPA3" in auth:
        return "WPA3"
    if "WPA2" in auth:
        if "Enterprise" in auth:
            return "WPA2-Enterprise"
        return "WPA2-Personal"
    if "WPA" in auth:
        return "WPA-Personal"
    if "WEP" in auth or enc == "WEP":
        return "WEP"
    return auth or "Unknown"


def _force_wifi_rescan():
    """
    Force Windows to perform a fresh WiFi radio scan.

    Windows caches WiFi scan results internally and only refreshes every
    30-60 seconds. If a hotspot is renamed, the OLD name stays in cache.
    We trigger a fresh scan by waking the adapter and waiting briefly.
    """
    try:
        subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, timeout=5
        )
        import time
        time.sleep(2)  # Allow radio scan to complete
    except Exception:
        pass


def _deduplicate_by_bssid(networks: list[dict]) -> list[dict]:
    """
    Remove duplicate entries with the same BSSID.

    netsh can occasionally return the same BSSID twice (once with old
    cached data and once with fresh data). Keep only the first occurrence
    since results are returned newest-first after a forced rescan.
    """
    seen_bssids = set()
    unique = []
    for net in networks:
        bssid = net.get("bssid", "")
        if bssid and bssid not in seen_bssids:
            seen_bssids.add(bssid)
            unique.append(net)
    return unique


def scan_networks() -> list[dict]:
    """
    Main scanning function. Forces a fresh Windows WiFi scan, then runs
    'netsh wlan show networks mode=bssid' and returns parsed results.

    On non-Windows platforms (Linux/macOS), returns demo data for testing.

    Why _force_wifi_rescan() matters:
        Windows caches WiFi scan results. If you rename a hotspot from
        "SRMIST" to "Hello", Windows still shows "SRMIST" for up to 60
        seconds. Forcing a rescan makes renamed networks appear immediately.

    Returns:
        List of network info dicts, each with keys:
            ssid, bssid, signal, signal_pct, channel,
            authentication, encryption, security
    """
    if platform.system() != "Windows":
        print("[Scanner] Non-Windows system detected. Using demo data.")
        return _generate_demo_networks()

    # Force a fresh radio scan so renamed/new networks appear with correct names
    print("[Scanner] Triggering fresh WiFi radio scan...")
    _force_wifi_rescan()

    raw = run_netsh(["wlan", "show", "networks", "mode=bssid"])

    if not raw:
        print("[Scanner] No output from netsh. Are you on Windows with a WiFi adapter?")
        return []

    networks = parse_netsh_networks(raw)

    # Remove any duplicate BSSIDs from cached+fresh overlap
    networks = _deduplicate_by_bssid(networks)

    print(f"[Scanner] Found {len(networks)} networks.")
    return networks


def get_connected_profile_names() -> list[str]:
    """
    Retrieve the names of all saved WiFi profiles on this Windows machine.

    Returns:
        List of profile name strings.
    """
    if platform.system() != "Windows":
        return ["HomeWiFi", "OfficeNet", "CampusWiFi"]

    raw = run_netsh(["wlan", "show", "profiles"])
    profiles = re.findall(r'All User Profile\s*:\s*(.+)', raw)
    return [p.strip() for p in profiles]


def get_profile_details(profile_name: str) -> dict:
    """
    Retrieve detailed information for a saved WiFi profile.

    Args:
        profile_name: SSID / profile name string.

    Returns:
        Dict with keys: ssid, authentication, encryption, security
    """
    if platform.system() != "Windows":
        return {"ssid": profile_name, "authentication": "WPA2-Personal",
                "encryption": "CCMP", "security": "WPA2-Personal"}

    raw = run_netsh(["wlan", "show", "profile", f'name="{profile_name}"', "key=clear"])

    auth = "Unknown"
    enc = "Unknown"

    for line in raw.splitlines():
        line = line.strip()
        if re.match(r'Authentication\s*:', line):
            auth = line.split(":", 1)[1].strip()
        elif re.match(r'Cipher\s*:', line):
            enc = line.split(":", 1)[1].strip()

    return {
        "ssid": profile_name,
        "authentication": auth,
        "encryption": enc,
        "security": build_security_string(auth, enc),
    }


# ---------------------------------------------------------------------------
# Demo data generator (used on non-Windows for testing/development)
# ---------------------------------------------------------------------------

def _generate_demo_networks() -> list[dict]:
    """Generate realistic-looking demo WiFi networks for testing on non-Windows."""
    return [
        # Legitimate network
        {"ssid": "HomeWiFi",       "bssid": "A4:C3:F0:11:22:33", "signal": -55,
         "signal_pct": 90, "channel": 6,  "authentication": "WPA2-Personal",
         "encryption": "CCMP", "security": "WPA2-Personal"},

        # Evil Twin of HomeWiFi - same SSID, different BSSID, strong signal
        {"ssid": "HomeWiFi",       "bssid": "DE:AD:BE:EF:00:01", "signal": -30,
         "signal_pct": 140, "channel": 11, "authentication": "Open",
         "encryption": "None", "security": "Open"},

        # Legitimate office network
        {"ssid": "OfficeNet",      "bssid": "00:1A:2B:3C:4D:5E", "signal": -70,
         "signal_pct": 60, "channel": 1,  "authentication": "WPA2-Enterprise",
         "encryption": "CCMP", "security": "WPA2-Enterprise"},

        # Rogue OfficeNet clone on wrong channel
        {"ssid": "OfficeNet",      "bssid": "FA:KE:AC:CE:55:00", "signal": -50,
         "signal_pct": 100, "channel": 13, "authentication": "WPA-Personal",
         "encryption": "TKIP", "security": "WPA-Personal"},

        # Completely safe network
        {"ssid": "CampusWiFi",     "bssid": "00:11:22:33:44:55", "signal": -65,
         "signal_pct": 70, "channel": 36, "authentication": "WPA2-Personal",
         "encryption": "CCMP", "security": "WPA2-Personal"},

        # Unknown open network - suspicious
        {"ssid": "FREE_WIFI",      "bssid": "BA:DC:AF:E0:00:01", "signal": -45,
         "signal_pct": 110, "channel": 6,  "authentication": "Open",
         "encryption": "None", "security": "Open"},

        # WEP (very outdated, suspicious)
        {"ssid": "OldRouter",      "bssid": "00:0F:66:AB:CD:EF", "signal": -80,
         "signal_pct": 40, "channel": 11, "authentication": "Open",
         "encryption": "WEP", "security": "WEP"},

        # Safe 5 GHz network
        {"ssid": "Neighbors_5G",   "bssid": "FC:EC:DA:11:22:33", "signal": -75,
         "signal_pct": 50, "channel": 149, "authentication": "WPA2-Personal",
         "encryption": "CCMP", "security": "WPA2-Personal"},
    ]
