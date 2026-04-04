"""
analyzer.py - WiFi Phishing Detection Engine
=============================================
Smart Evil Twin / phishing WiFi detection with two scenarios:

SCENARIO A - Campus impersonation WITH peers (e.g. fake "SRMIST" hotspot):
  - Majority OUI check: campus has consistent hardware vendor, phone hotspot differs
  - Majority security check: campus WPA2-Enterprise, phone hotspot WPA2-Personal
  - Strongest signal + different OUI: attacker is physically close to victim

SCENARIO B - Solo impersonation (renamed hotspot, no visible real peers):
  - Compare against known_wifi.json database
  - Any security downgrade, channel mismatch, or untrusted BSSID is flagged
  - Open standalone networks scored appropriately

KEY DESIGN DECISIONS:
  - Randomized MAC check only fires on SOLO APs (not campus multi-AP nets)
    because Windows netsh sometimes reports enterprise APs with local-bit MACs
  - OUI majority requires >= 3 peers to establish a clear pattern
  - Security mismatch gap of 1 level triggers for known networks (strict)
  - Security mismatch gap of 1 level triggers vs majority peers too
"""

from collections import Counter
from mac_vendor import get_vendor
from known_networks import (
    is_known_network,
    get_trusted_bssids,
    get_known_security,
    get_known_channels,
)

# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------
SCORE_EVIL_TWIN_SECURITY      = 55   # Security weaker than majority peers
SCORE_EVIL_TWIN_DIFF_OUI      = 45   # Different manufacturer from majority peers
SCORE_SECURITY_MISMATCH_KNOWN = 40   # Downgrade vs saved known-network profile
SCORE_OPEN_WITH_PEERS         = 35   # Open AP while same-SSID peers use encryption
SCORE_STRONGEST_DIFF_OUI      = 25   # Strongest signal AND different OUI from peers
SCORE_RANDOMIZED_MAC_SOLO     = 20   # Randomized MAC on a solo (no peers) network
SCORE_UNTRUSTED_BSSID         = 20   # Not in saved trusted BSSID list (small nets)
SCORE_WEP_NETWORK             = 20   # WEP encryption (critically broken)
SCORE_OPEN_STANDALONE         = 10   # Open AP with no encrypted peers
SCORE_CHANNEL_MISMATCH        = 10   # Wrong channel vs saved profile

# Thresholds
THRESHOLD_PHISHING   = 55
THRESHOLD_SUSPICIOUS = 25

# Minimum peers needed to run majority-based checks
MIN_PEERS_FOR_MAJORITY = 3

# Security ranking (higher = more secure)
SECURITY_RANK = {
    "WPA3":            5,
    "WPA2-Enterprise": 4,
    "WPA2-Personal":   3,
    "WPA-Personal":    2,
    "WEP":             1,
    "Open":            0,
    "Unknown":        -1,
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _get_oui(bssid: str) -> str:
    """Extract first 3 octets (OUI) from a BSSID, normalized uppercase."""
    if not bssid:
        return ""
    parts = bssid.upper().replace("-", ":").split(":")
    return ":".join(parts[:3]) if len(parts) >= 3 else ""


def _is_locally_administered(bssid: str) -> bool:
    """
    Return True if MAC has locally-administered bit set (bit 1 of first octet).
    Indicates a randomized or manually assigned MAC — common in phone hotspots.
    Examples of local-admin MACs: B6:xx, DA:xx, FE:xx, 4A:xx, 2E:xx
    """
    try:
        first_octet = int(bssid.replace("-", ":").split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


def _get_peers(network: dict, all_networks: list[dict]) -> list[dict]:
    """Return all networks with the same SSID but different BSSID."""
    ssid       = network.get("ssid", "")
    this_bssid = network.get("bssid", "")
    return [
        n for n in all_networks
        if n.get("ssid") == ssid and n.get("bssid") != this_bssid
    ]


def _majority_oui(peers: list[dict]) -> str | None:
    """
    Find the OUI used by more than half of the peer APs.
    Returns None if no clear majority (mixed hardware deployment).
    """
    ouis = [_get_oui(n.get("bssid", "")) for n in peers]
    ouis = [o for o in ouis if o]
    if not ouis:
        return None
    counts = Counter(ouis)
    top_oui, top_count = counts.most_common(1)[0]
    if top_count >= max(1, len(ouis) / 2):
        return top_oui
    return None


def _majority_security(peers: list[dict]) -> str | None:
    """Find the security type used by more than half of the peer APs."""
    secs = [
        n.get("security", "Unknown") for n in peers
        if n.get("security", "Unknown") not in ("Unknown", "")
    ]
    if not secs:
        return None
    counts = Counter(secs)
    top_sec, top_count = counts.most_common(1)[0]
    if top_count >= max(1, len(secs) / 2):
        return top_sec
    return None


# ---------------------------------------------------------------------------
# Detection checks
# ---------------------------------------------------------------------------

def check_evil_twin_security(network: dict, all_networks: list[dict]) -> tuple[int, str | None]:
    """
    Flag when this AP uses weaker security than the majority of same-SSID peers.

    Example: All SRMIST APs use WPA2-Enterprise. Attacker phone hotspot
    named "SRMIST" uses WPA2-Personal. Gap = 1 level → PHISHING.
    """
    ssid          = network.get("ssid", "")
    this_bssid    = network.get("bssid", "")
    this_security = network.get("security", "Unknown")
    this_rank     = SECURITY_RANK.get(this_security, -1)

    peers = _get_peers(network, all_networks)
    if len(peers) < MIN_PEERS_FOR_MAJORITY:
        return 0, None

    maj_security = _majority_security(peers)
    if not maj_security:
        return 0, None

    maj_rank = SECURITY_RANK.get(maj_security, -1)

    # Flag if this AP is ANY level weaker than the majority
    if this_rank >= 0 and maj_rank > 0 and maj_rank > this_rank:
        gap = maj_rank - this_rank
        reason = (
            f"Evil Twin — security mismatch: '{ssid}' — this AP ({this_bssid}) "
            f"uses '{this_security}' but {len(peers)} other APs with this SSID "
            f"use '{maj_security}' ({gap} security level weaker). "
            f"A phone hotspot or rogue AP impersonating a campus network typically "
            f"cannot replicate enterprise authentication, so it uses weaker security."
        )
        return SCORE_EVIL_TWIN_SECURITY, reason

    return 0, None


def check_evil_twin_oui(network: dict, all_networks: list[dict]) -> tuple[int, str | None]:
    """
    Flag when this AP's manufacturer OUI differs from the majority of same-SSID peers.

    Example: All SRMIST campus APs have OUI 48:B4:C3. Attacker phone hotspot
    has OUI B6:F6:C4 (Qualcomm phone chipset). Different majority OUI → flag.

    Requires MIN_PEERS_FOR_MAJORITY peers to establish the pattern.
    """
    this_bssid = network.get("bssid", "")
    this_oui   = _get_oui(this_bssid)
    ssid       = network.get("ssid", "")

    peers = _get_peers(network, all_networks)
    if len(peers) < MIN_PEERS_FOR_MAJORITY:
        return 0, None

    maj_oui = _majority_oui(peers)
    if not maj_oui:
        return 0, None  # Mixed hardware campus — no clear majority

    if not this_oui or this_oui == maj_oui:
        return 0, None  # Same manufacturer as campus APs

    vendor_this = get_vendor(this_bssid)
    sample_peer = next(
        (n for n in peers if _get_oui(n.get("bssid", "")) == maj_oui),
        peers[0]
    )
    vendor_maj  = get_vendor(sample_peer.get("bssid", ""))
    peer_count  = sum(1 for n in peers if _get_oui(n.get("bssid", "")) == maj_oui)

    reason = (
        f"Evil Twin — different manufacturer: '{ssid}' — this AP "
        f"({this_bssid}, OUI={this_oui}, vendor='{vendor_this}') is from a "
        f"DIFFERENT manufacturer than {peer_count} other APs with this SSID "
        f"(majority OUI={maj_oui}, vendor='{vendor_maj}'). "
        f"Campus deployments use consistent hardware. A rogue phone hotspot "
        f"always has a different OUI from the campus infrastructure."
    )
    return SCORE_EVIL_TWIN_DIFF_OUI, reason


def check_strongest_signal_diff_oui(network: dict, all_networks: list[dict]) -> tuple[int, str | None]:
    """
    Flag when this AP is the STRONGEST signal for its SSID AND has a different OUI.

    Attacker holding a phone hotspot is physically close to the victim, making
    it the strongest signal. Combined with a different OUI, this is reliable.
    """
    this_bssid  = network.get("bssid", "")
    this_oui    = _get_oui(this_bssid)
    this_signal = network.get("signal", -100)
    ssid        = network.get("ssid", "")

    peers = _get_peers(network, all_networks)
    if len(peers) < MIN_PEERS_FOR_MAJORITY:
        return 0, None

    peer_signals = [n.get("signal", -100) for n in peers]
    if this_signal <= max(peer_signals):
        return 0, None  # Not the strongest signal

    maj_oui = _majority_oui(peers)
    if not maj_oui or this_oui == maj_oui:
        return 0, None  # Same manufacturer — just a closer campus AP

    gap = this_signal - max(peer_signals)
    reason = (
        f"Strongest signal + different manufacturer: '{ssid}' — this AP "
        f"({this_bssid}, OUI={this_oui}) has the STRONGEST signal "
        f"({this_signal} dBm, {gap} dBm stronger than next AP) "
        f"AND uses a different OUI than the majority of campus APs (OUI={maj_oui}). "
        f"Attackers place rogue APs or hold phone hotspots close to victims."
    )
    return SCORE_STRONGEST_DIFF_OUI, reason


def check_open_network(network: dict, all_networks: list[dict]) -> tuple[int, str | None]:
    """
    Flag open networks. Higher score if same-SSID peers use encryption.
    """
    security = network.get("security", "")
    ssid     = network.get("ssid", "")

    if security != "Open":
        return 0, None

    peers = _get_peers(network, all_networks)
    encrypted_peers = [
        n for n in peers
        if n.get("security", "Open") not in ("Open", "Unknown")
    ]

    if encrypted_peers:
        reason = (
            f"Open network among encrypted peers: '{ssid}' ({network.get('bssid')}) "
            f"is Open while {len(encrypted_peers)} other AP(s) with this SSID use "
            f"encryption ({', '.join(set(n.get('security','?') for n in encrypted_peers))}). "
            f"Classic Evil Twin: attacker creates an open AP to capture traffic."
        )
        return SCORE_OPEN_WITH_PEERS, reason

    reason = (
        f"Open network: '{ssid}' requires no authentication. "
        f"All traffic is unencrypted and can be intercepted by anyone nearby."
    )
    return SCORE_OPEN_STANDALONE, reason


def check_security_mismatch_known(network: dict, known: dict) -> tuple[int, str | None]:
    """
    Detect downgrade vs the saved known-networks database.

    If the user saved "SRMIST = WPA2-Enterprise" and an AP appears as
    WPA2-Personal or Open, flag it. Gap of >= 1 rank triggers the flag.
    This catches solo renamed hotspots that have no visible peers.
    """
    ssid             = network.get("ssid", "")
    current_security = network.get("security", "Unknown")

    if not is_known_network(ssid, known):
        return 0, None

    expected_security = get_known_security(ssid, known)
    if expected_security in ("Unknown", ""):
        return 0, None

    current_rank  = SECURITY_RANK.get(current_security, -1)
    expected_rank = SECURITY_RANK.get(expected_security, -1)

    if expected_rank > 0 and current_rank >= 0 and expected_rank > current_rank:
        gap = expected_rank - current_rank
        reason = (
            f"Security downgrade vs saved profile: '{ssid}' was saved as "
            f"'{expected_security}' but this AP ({network.get('bssid')}) broadcasts "
            f"'{current_security}' ({gap} security level weaker). "
            f"This strongly suggests an impersonation attempt."
        )
        return SCORE_SECURITY_MISMATCH_KNOWN, reason

    return 0, None


def check_randomized_mac_solo(network: dict, all_networks: list[dict]) -> tuple[int, str | None]:
    """
    Flag locally-administered (randomized) MAC only on SOLO networks.

    Phone hotspots often use randomized MACs. If the SSID appears only once
    (no campus peers) AND the MAC is locally-administered, it's suspicious.

    We do NOT flag this for multi-AP networks because Windows netsh can
    report some enterprise APs with what looks like a local-admin MAC.
    """
    this_bssid = network.get("bssid", "")
    ssid       = network.get("ssid", "")

    if not _is_locally_administered(this_bssid):
        return 0, None

    peers = _get_peers(network, all_networks)
    if peers:
        return 0, None  # Has peers — don't flag for multi-AP networks

    reason = (
        f"Randomized MAC address: '{ssid}' ({this_bssid}) has a "
        f"locally-administered MAC (randomized). Real access points use "
        f"factory-burned globally-assigned MACs. Phone hotspots commonly "
        f"use randomized MACs to avoid tracking."
    )
    return SCORE_RANDOMIZED_MAC_SOLO, reason


def check_untrusted_bssid(network: dict, known: dict) -> tuple[int, str | None]:
    """
    Flag unrecognized BSSID for networks with a small saved BSSID list.
    Skipped for large lists (campus networks where we can't track all APs).
    """
    ssid  = network.get("ssid", "")
    bssid = network.get("bssid", "")

    if not is_known_network(ssid, known):
        return 0, None

    trusted_bssids = get_trusted_bssids(ssid, known)

    # Only meaningful for small networks (home/office — not campus)
    if not trusted_bssids or len(trusted_bssids) > 5:
        return 0, None

    if bssid not in trusted_bssids:
        reason = (
            f"Untrusted BSSID: '{ssid}' is a saved network, but {bssid} is NOT "
            f"in your trusted BSSID list ({', '.join(trusted_bssids)}). "
            f"This could be an Evil Twin impersonating your home or office AP."
        )
        return SCORE_UNTRUSTED_BSSID, reason

    return 0, None


def check_wep_network(network: dict) -> tuple[int, str | None]:
    """Flag WEP-encrypted networks (critically broken since 2001)."""
    security   = network.get("security", "")
    encryption = network.get("encryption", "")

    if "WEP" in security or "WEP" in encryption:
        reason = (
            f"WEP encryption: '{network.get('ssid')}' uses WEP, which was broken "
            f"in 2001 and can be cracked in under 60 seconds."
        )
        return SCORE_WEP_NETWORK, reason

    return 0, None


def check_channel_mismatch(network: dict, known: dict) -> tuple[int, str | None]:
    """
    Detect channel inconsistency vs saved profile.
    Skipped for campus networks with many known channels (>4).
    """
    ssid            = network.get("ssid", "")
    current_channel = network.get("channel", 0)

    if not is_known_network(ssid, known):
        return 0, None

    known_channels = get_known_channels(ssid, known)

    if not known_channels or len(known_channels) > 4 or current_channel == 0:
        return 0, None

    if current_channel not in known_channels:
        reason = (
            f"Channel mismatch: '{ssid}' was saved on channel(s) {known_channels} "
            f"but this AP ({network.get('bssid')}) is on channel {current_channel}."
        )
        return SCORE_CHANNEL_MISMATCH, reason

    return 0, None


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def determine_status(score: int) -> str:
    """Convert risk score to status label."""
    if score >= THRESHOLD_PHISHING:
        return "PHISHING"
    elif score >= THRESHOLD_SUSPICIOUS:
        return "SUSPICIOUS"
    return "SAFE"


def analyze_network(network: dict, all_networks: list[dict], known: dict) -> dict:
    """
    Run all detection checks and compute risk score for a single network.

    Args:
        network:      The network to analyze.
        all_networks: Full scanned list (needed for peer comparisons).
        known:        Trusted network database from known_wifi.json.

    Returns:
        Dict with keys: score, status, reasons, vendor
    """
    total_score = 0
    reasons     = []

    checks = [
        check_evil_twin_security(network, all_networks),
        check_evil_twin_oui(network, all_networks),
        check_strongest_signal_diff_oui(network, all_networks),
        check_open_network(network, all_networks),
        check_security_mismatch_known(network, known),
        check_randomized_mac_solo(network, all_networks),
        check_untrusted_bssid(network, known),
        check_wep_network(network),
        check_channel_mismatch(network, known),
    ]

    for score_delta, reason in checks:
        if score_delta > 0 and reason:
            total_score += score_delta
            reasons.append(reason)

    total_score = min(total_score, 100)

    return {
        "score":   total_score,
        "status":  determine_status(total_score),
        "reasons": reasons,
        "vendor":  get_vendor(network.get("bssid", "")),
    }


def analyze_all_networks(networks: list[dict], known: dict) -> list[dict]:
    """
    Analyze every scanned network and return enriched list with
    score, status, reasons, and vendor added to each dict.
    """
    enriched = []
    for net in networks:
        analysis = analyze_network(net, networks, known)
        merged   = {**net, **analysis}
        enriched.append(merged)
    return enriched
