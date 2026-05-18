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

        Steps:
          1. Get row["email"] (already set by score_user).
          2. Split on "@" to get the domain part.
          3. Check if domain is in DISPOSABLE_DOMAINS (the module-level set).
          4. Return (2, "Disposable email domain") if yes, (0, "") if no.

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

        Steps:
          1. Get the IP of this row: row["IP Address"]
          2. Loop through all_rows and count how many rows share this IP
             but have a different User ID. (Use a set to count unique IDs.)
          3. If that count > 3, return (2, "IP shared by >3 accounts").
        """
        ip_address = row["IP Address"]
        diff_user__but_same_ip = set()

        for r in all_rows:
            if r["IP Address"] == ip_address:
                diff_user__but_same_ip.add(r["User ID"])
            if len(diff_user__but_same_ip) > 3:
                return (2, "IP shared by >3 accounts")

        return (0, "")

    def _check_high_risk_country(self, row: dict, all_rows: list) -> tuple:
        """
        TODO -- worth +1 point.

        Steps:
          1. Get row["Country"] (2-letter ISO code, e.g. "RU").
          2. Check against HIGH_RISK_COUNTRIES.
          3. Return (1, "High-risk country") or (0, "").
        """
        raise NotImplementedError("implement _check_high_risk_country")

    def _check_linux_device(self, row: dict, all_rows: list) -> tuple:
        """
        TODO -- worth +1 point.

        Linux desktops with no purchase history are a common bot signal.
        We don't have purchase history in this dataset, so treat any Linux
        OS as the flag (in a real system you'd add a purchase lookup).

        Steps:
          1. Get row["OS Name and Version"] (e.g. "Linux x86_64 5.4").
          2. Check if "Linux" appears in it (case-insensitive).
          3. Return (1, "Linux device") or (0, "").

        Hint: "Linux" in some_string   OR   some_string.lower()
        """
        raise NotImplementedError("implement _check_linux_device")

    def _check_fast_session(self, row: dict, all_rows: list) -> tuple:
        """
        TODO -- worth +1 point.

        If a user's first and second login are less than 2 minutes apart,
        it looks like a bot that immediately hammers the session endpoint.

        Steps:
          1. Filter all_rows for rows with the same User ID as this row.
          2. Parse "Login Timestamp" strings into datetime objects.
             Use: datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")
             Wrap in try/except in case the timestamp is empty.
          3. Sort those datetimes.
          4. If there are at least 2, compute the gap between [0] and [1].
          5. If gap < 120 seconds, return (1, "Session within 2 min of signup").

        Hint: (dt2 - dt1).total_seconds()
        """
        raise NotImplementedError("implement _check_fast_session")

    def _check_signup_burst(self, row: dict, all_rows: list) -> tuple:
        """
        TODO -- worth +2 points.

        Multiple *different* users signing up from the same IP within 5 seconds
        of each other = bot farm or account factory.

        Steps:
          1. Get this row's IP and timestamp (parse the timestamp).
          2. Filter all_rows to same IP, different User ID.
          3. Parse their timestamps too; skip rows with unparseable timestamps.
          4. Check if any of those timestamps is within 5 seconds of this row's timestamp.
             Use abs((other_dt - this_dt).total_seconds()) < 5
          5. If yes, return (2, "Signup burst on same IP").

        Hint: reuse the same datetime.strptime pattern from _check_fast_session.
        """
        raise NotImplementedError("implement _check_signup_burst")
