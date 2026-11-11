"""Plain-language explanations for findings (no model needed).

Every rule is a ``(tool?, keyword, what-it-means, what-to-do)`` tuple matched
against the finding title. Rules are deliberately conservative: when nothing
matches, the severity fallback explains the urgency without inventing facts.
Reports embed one line per finding so a first-time reader knows why it
matters and what the next step is.
"""

from __future__ import annotations

from cyberpowerfull.models import Finding

#: (tool or None, keyword in title, what it means, what to do)
_RULES: tuple[tuple[str | None, str, str, str], ...] = (
    (
        None,
        "certificate expired",
        "the site's TLS certificate is past its expiry date, so browsers distrust the site",
        "renew the certificate and check auto-renewal; treat any outage as user-facing",
    ),
    (
        None,
        "expires soon",
        "the TLS certificate stops being valid within 30 days",
        "renew it now and set an expiry alert so it never lapses silently",
    ),
    (
        None,
        "self-signed",
        "the certificate was signed by the server itself, so nobody can verify who runs it",
        "replace it with a certificate from a trusted authority (or your internal CA)",
    ),
    (
        None,
        "hostname mismatch",
        "the certificate was issued for a different name than the one you connected to",
        "serve the certificate that matches this hostname; a mismatch enables interception",
    ),
    (
        None,
        "weak tls version",
        "the server still negotiates an obsolete TLS version with known attacks",
        "disable everything below TLS 1.2 (ideally 1.3 only) and re-test",
    ),
    (
        None,
        "weak tls cipher",
        "the server accepts a cipher with a broken primitive (RC4/3DES/MD5/NULL)",
        "remove the weak cipher from the server cipher list and re-test",
    ),
    (
        None,
        "open port",
        "a network port answered, which means a service is reachable from the scanner",
        "confirm the service is supposed to be exposed; close or firewall the rest",
    ),
    (
        None,
        "hardcoded secret",
        "a password, token, or key is written directly in the code or config",
        "revoke the secret, delete it from history, and move it to a secret manager",
    ),
    (
        None,
        "possible secret",
        "text that looks like a credential was found; it was not verified",
        "check whether it is real; if yes, revoke it and purge it from history",
    ),
    (
        None,
        "null session",
        "the Windows file-sharing service lets strangers connect without a password",
        "disable null sessions (RestrictAnonymous) and re-test share access",
    ),
    (
        None,
        "writable via",
        "an anonymous user can write files to this network share",
        "remove anonymous write access; shares should be read-only unless needed",
    ),
    (
        None,
        "smbv1",
        "the server speaks SMBv1, the protocol behind WannaCry-era worms",
        "disable SMBv1 on the server; it has no safe use left",
    ),
    (
        None,
        "signing not required",
        "SMB signing is optional, so relay attacks can impersonate users",
        "enforce SMB signing on clients and servers",
    ),
    (
        None,
        "zone transfer",
        "the DNS server hands its full zone to anyone who asks",
        "restrict AXFR to the real secondary servers only",
    ),
    (
        None,
        "internal addresses",
        "public DNS answers reveal private (RFC 1918) addresses",
        "remove the private records from the public zone (split-horizon DNS)",
    ),
    (
        None,
        "subdomain discovered",
        "a new hostname belonging to the target was found and may widen the attack surface",
        "decide whether it is in scope, then probe it like any other target",
    ),
    (
        None,
        "exposed service observed",
        "a search engine has this service indexed as reachable from the internet",
        "confirm it should be public; if not, restrict access and delist it",
    ),
    (
        "nuclei",
        "cve",
        "a template matched a known CVE pattern on the target",
        "verify manually, then patch or mitigate; KEV matches patch first",
    ),
    (
        None,
        "cross site scripting",
        "attacker input is reflected into the page and can run scripts in victims' browsers",
        "encode output and validate input; re-test with the proven payload",
    ),
    (
        None,
        "sql injection",
        "attacker input reaches a database query and may allow data theft",
        "use parameterized queries; never concatenate input into SQL",
    ),
    (
        "prowler",
        "public access",
        "a cloud resource is reachable from the whole internet",
        "block public access and confirm no data was exposed in the meantime",
    ),
    (
        "kubebench",
        "cis",
        "a CIS Kubernetes Benchmark check failed on this node",
        "apply the remediation in the evidence, then re-run the benchmark",
    ),
    (
        "kubescape",
        "[",
        "a Kubernetes posture control failed (RBAC, pod security, or similar)",
        "follow the remediation in the evidence and re-scan the cluster",
    ),
    (
        "semgrep",
        "command",
        "code may pass untrusted input to a system command",
        "avoid shells for user input; use argument lists and strict allowlists",
    ),
    (
        "trivy",
        "cve-",
        "an installed dependency has a published vulnerability",
        "upgrade to the fixed version shown in the evidence",
    ),
    (
        None,
        "misconfig",
        "a configuration violates a security baseline",
        "apply the suggested fix, then re-scan to confirm it stuck",
    ),
)

_SEVERITY_FALLBACK = {
    "critical": "a critical issue: treat it as actively exploitable until proven otherwise",
    "high": "a high-severity issue: fix it before the next release or review",
    "medium": "a medium-severity issue: schedule the fix; it is a real stepping stone",
    "low": "a low-severity issue: fix it when convenient; it mostly helps hygiene",
    "info": "an informational note: no action needed unless it surprises you",
}


def explain_finding(finding: Finding) -> str:
    """Return one plain-language line for ``finding`` (never empty)."""
    title = finding.title.lower()
    for tool, keyword, meaning, action in _RULES:
        if tool is not None and finding.tool != tool:
            continue
        if keyword in title:
            return f"{meaning}; {action}."
    fallback = _SEVERITY_FALLBACK.get(finding.severity.value, _SEVERITY_FALLBACK["info"])
    return f"{fallback}."


__all__ = ["explain_finding"]
