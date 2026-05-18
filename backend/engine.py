"""
engine.py — Rule-based fraud scoring for suspicious trial signups.

Dataset's feature:
index,Login Timestamp,User ID,Round-Trip Time [ms],IP Address,Country,Region,City,
ASN,User Agent String,Browser Name and Version,OS Name and Version,Device Type,
Login Successful,Is Attack IP,Is Account Takeover
"""

import hashlib
from datetime import datetime

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DISPOSABLE_DOMAINS = {
    "tempmail.com", "mailinator.com", "guerrillamail.com",
    "throwaway.email", "yopmail.com", "trashmail.com",
    "sharklasers.com", "spam4.me", "fakeinbox.com",
}

HIGH_RISK_COUNTRIES = {"RU", "CN", "NG", "KP", "IR"}

# Realistic-looking fake domains so generated emails look plausible
_EMAIL_DOMAINS = [
    "gmail.com", "outlook.com", "yahoo.com",        # legit (index 0-2)
    "hotmail.com", "proton.me", "icloud.com",        # legit (index 3-5)
    "tempmail.com", "mailinator.com", "yopmail.com", # disposable (index 6-8)
]


# ---------------------------------------------------------------------------
# Utility: generate a deterministic fake email from a User ID string
# ---------------------------------------------------------------------------

def make_email(user_id: str) -> str:
    """
    Turns a raw User ID (big integer string) into a fake but consistent email.
    Uses MD5 so the same user_id always gets the same email = no randomness.

    How it works:
      1. Hash the user_id string with MD5 -> gives us a hex digest
      2. Use first 8 chars as the username  (e.g. "a3f9c12b")
      3. Use the numeric value of next 2 chars mod 9 -> pick a domain from the list
         Domains 0-5 are legit; domains 6-8 are disposable.
         That means roughly 1/3 of users get a disposable email.

    You do NOT need to modify this — it's called automatically inside score_user.
    """
    h = hashlib.md5(str(user_id).encode()).hexdigest()
    username = h[:8]
    domain_idx = int(h[8:10], 16) % len(_EMAIL_DOMAINS)
    domain = _EMAIL_DOMAINS[domain_idx]
    return f"{username}@{domain}"


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class FraudEngine:
    """
    Scores a single user row against all fraud rules.

    OOP note: grouping the rules inside a class lets us share constants
    (HIGH_RISK_COUNTRIES etc.) and keeps each rule isolated in its own method
    so they're easy to add, remove, or adjust independently.
    """

    def score_user(self, row: dict, all_rows: list) -> dict:
        """
        Entry point. Runs every rule and aggregates the result.

        Args:
            row      -- one user's data as a dict (column -> value)
            all_rows -- the full dataset as a list of dicts (needed for IP/burst checks)

        Returns:
            {"score": int, "triggers": list[str], "status": str}

        HOW THE DISPATCHER WORKS:
          Each _check_* method returns (points: int, trigger: str).
          If points > 0, we add them to the score and record the trigger label.
          This lets you add a new rule by just adding a method -- no other changes needed.
        """
        # Generate a synthetic email and attach it to the row so rules can use it
        row["email"] = make_email(row.get("User ID", ""))

        score = 0
        triggers = []

        checks = [
            self._check_disposable_email,
            self._check_ip_reuse,
            self._check_high_risk_country,
            self._check_linux_device,
            self._check_fast_session,
            self._check_signup_burst,
        ]

        for check in checks:
            points, trigger = check(row, all_rows)
            score += points
            if trigger:
                triggers.append(trigger)

        status = self._get_status(score)
        return {"score": score, "triggers": triggers, "status": status}

    # ------------------------------------------------------------------
    # Status helper
    # ------------------------------------------------------------------

    def _get_status(self, score: int) -> str:
        """
        Rules:
          score >= 4  -> "blocked"
          score >= 2  -> "flagged"
          else        -> "clean"
        """
        if (score >= 4):
            return "blocked"
        elif (score >= 2):
            return "flagged"
        else:
            return "clean"


    # ------------------------------------------------------------------
    # Individual rule methods
    # ------------------------------------------------------------------
    # Each returns (points: int, trigger: str).
    # Return (0, "") when the rule does NOT fire.
    # Return (N, "short description") when it does.
    # ------------------------------------------------------------------

    def _check_disposable_email(self, row: dict, all_rows: list) -> tuple:
        """
        worth +2 points.

        """
        email = row["email"]
        username, domain = email.split("@")
        if domain in DISPOSABLE_DOMAINS:
            return (2, "Disposable email domain")
        return (0, "")

    def _check_ip_reuse(self, row: dict, all_rows: list) -> tuple:
        """
        worth +2 points.

        An IP address used by more than 3 distinct users is suspicious
        (could be a VPN, proxy, or bot farm).

        """
        ip_address = row["IP Address"]
        diff_user_but_same_ip = set()

        for r in all_rows:
            if r["IP Address"] == ip_address:
                diff_user_but_same_ip.add(r["User ID"])
            if len(diff_user_but_same_ip) > 3:
                return (2, "IP shared by >3 accounts")

        return (0, "")

    def _check_high_risk_country(self, row: dict, all_rows: list) -> tuple:
        """
        worth +1 point.

        Checks against the constant HIGH_RISK_COUNTRIES.
        """
        country = row["Country"]
        if country in HIGH_RISK_COUNTRIES:
            return (1, "High-risk country")
        
        return (0, "")
    
    def _check_linux_device(self, row: dict, all_rows: list) -> tuple:
        """
        worth +1 point.

        Linux desktops with no purchase history are a common bot signal.
        We don't have purchase history in this dataset, so use only Linux
        OS as the flag.

        """

        OSName = row["OS Name and Version"]
        if "linux" in OSName.lower():
            return (1, "Linux device")
        return (0, "")

    def _check_fast_session(self, row: dict, all_rows: list) -> tuple:
        """
        worth +1 point.

        If a user's first and second login are less than 2 minutes apart,
        it looks like a bot that immediately hammers the session endpoint.

        """

        user_id = row["User ID"]
        same_user_rows = [r for r in all_rows if user_id == r["User ID"]]
        
        timestamp = [r["Login Timestamp"] for r in same_user_rows]
        parsed_timestamps = []

        # parse the timestamp
        try: 
            for ts in timestamp:
                parsed_timestamps.append(
                    datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")
                )
        except ValueError:
            pass
        
        sorted_parsed_ts = sorted(parsed_timestamps)
        diff = float('inf')
        if len(sorted_parsed_ts) >= 2:
            diff = (sorted_parsed_ts[1] - sorted_parsed_ts[0]).total_seconds()

        if diff < 120:
            return (1, "Session within 2 min of signup")
        return (0, "")

    def _check_signup_burst(self, row: dict, all_rows: list) -> tuple:
        """
        worth +2 points.

        Multiple *different* users signing up from the same IP within 5 seconds
        of each other = bot farm or account factory.

        """
        IPAddress, timestamp, userID = row["IP Address"], row["Login Timestamp"], row["User ID"]

        try: 
            parsed_timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
            for r in all_rows:
                if IPAddress == r["IP Address"] and userID != r["User ID"]:
                    other_timestamp = datetime.strptime(r["Login Timestamp"], "%Y-%m-%d %H:%M:%S.%f")
                    if abs((other_timestamp - parsed_timestamp).total_seconds()) < 5:
                        return (2, "Signup burst on same IP")
        except ValueError:
            pass
                    
        return (0, "")
