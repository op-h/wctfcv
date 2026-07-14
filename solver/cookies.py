import re
import math
import requests
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class CookieAnalyzer:
    COMMON_SESSION_COOKIES = [
        "session", "sid", "sess", "token", "auth", "jwt", "access_token",
        "refresh_token", "session_id", "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId",
        "connect.sid", "express:sess", "laravel_session", "django_session",
    ]

    JWT_HEADER = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")

    def __init__(self, url: str, timeout: int = 10, headers: Optional[dict] = None):
        self.url = url
        self.timeout = timeout
        self.headers = headers or {}
        self.findings = []
        self.risk_level = "LOW"
        self.confidence = 85
        self.recommendations = []

    def analyze(self) -> dict:
        console.print(Panel("[bold cyan]Cookie Security Analysis[/bold cyan]", border_style="cyan"))
        console.print(f"  [yellow]Target:[/yellow] {self.url}")

        results = {
            "url": self.url, "cookies": [], "security_issues": [],
            "session_cookies": [], "jwt_tokens": [],
            "analysis": {}, "findings": [], "risk_level": "LOW",
            "confidence": 85, "recommendations": [],
        }

        try:
            resp = requests.get(self.url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=True)
            cookie_jar = resp.cookies
            console.print(f"  [yellow]Cookies received:[/yellow] {len(cookie_jar)}")

            set_cookie_headers = resp.headers.get("Set-Cookie", "")
            for cookie in cookie_jar:
                cookie_info = {
                    "name": cookie.name, "value": cookie.value,
                    "domain": cookie.domain, "path": cookie.path,
                    "secure": cookie.secure,
                    "httponly": False, "samesite": "None",
                    "is_session": cookie.expires is None,
                    "is_encoded": self._check_encoding(cookie.value),
                    "entropy": self._calculate_entropy(cookie.value),
                    "is_session_cookie": cookie.name in self.COMMON_SESSION_COOKIES,
                    "is_jwt": False, "jwt_claims": {},
                }
                if "httponly" in set_cookie_headers.lower() and cookie.name in set_cookie_headers:
                    cookie_info["httponly"] = True
                ss_match = re.search(r"samesite\s*=\s*(\w+)", set_cookie_headers, re.IGNORECASE)
                if ss_match:
                    cookie_info["samesite"] = ss_match.group(1)
                if self.JWT_HEADER.match(cookie.value):
                    cookie_info["is_jwt"] = True
                    cookie_info["jwt_claims"] = self._decode_jwt(cookie.value)
                    results["jwt_tokens"].append(cookie_info)
                    if cookie_info["is_session_cookie"]:
                        results["session_cookies"].append(cookie_info["name"])
                issues = self._check_security(cookie_info)
                cookie_info["issues"] = issues
                results["security_issues"].extend(issues)
                results["cookies"].append(cookie_info)
                if cookie_info["is_session_cookie"]:
                    results["session_cookies"].append(cookie_info["name"])
                self._print_cookie(cookie_info)

            results["analysis"] = self._analyze_cookies(results["cookies"])
            results["findings"] = self._generate_findings(results)
            results["risk_level"] = self._calculate_risk(results)
            results["recommendations"] = self._generate_recommendations(results)

            self.findings = results["findings"]
            self.risk_level = results["risk_level"]
            self.recommendations = results["recommendations"]

        except requests.RequestException as e:
            console.print(f"  [red]Error: {e}[/red]")
            results["findings"].append(f"Connection error: {e}")

        return results

    def _check_encoding(self, value: str) -> bool:
        try:
            import base64
            decoded = base64.b64decode(value + "==")
            if decoded != value.encode():
                return True
        except Exception:
            pass
        return False

    def _calculate_entropy(self, value: str) -> float:
        if not value:
            return 0.0
        freq = {}
        for char in value:
            freq[char] = freq.get(char, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(value)
            entropy -= p * math.log2(p)
        return round(entropy, 2)

    def _decode_jwt(self, token: str) -> dict:
        try:
            import base64
            parts = token.split(".")
            if len(parts) != 3:
                return {}
            payload = parts[1]
            payload += "=" * (4 - len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload)
            import json
            return json.loads(decoded)
        except Exception:
            return {}

    def _check_security(self, cookie: dict) -> list:
        issues = []
        if not cookie["secure"]:
            issues.append({"cookie": cookie["name"], "issue": "Missing Secure flag", "severity": "medium", "description": "Cookie transmitted over HTTP - can be intercepted"})
        if not cookie["httponly"]:
            issues.append({"cookie": cookie["name"], "issue": "Missing HttpOnly flag", "severity": "medium", "description": "Cookie accessible via JavaScript (XSS target)"})
        if cookie["samesite"] == "None":
            issues.append({"cookie": cookie["name"], "issue": "SameSite=None", "severity": "low", "description": "Cookie sent with cross-origin requests (CSRF risk)"})
        if cookie["is_session_cookie"] and cookie["expires"] is not None:
            issues.append({"cookie": cookie["name"], "issue": "Session cookie has expiration", "severity": "info", "description": "Session cookies should not have an expiration"})
        if cookie["entropy"] < 3.0 and len(cookie["value"]) > 5:
            issues.append({"cookie": cookie["name"], "issue": "Low entropy value", "severity": "medium", "description": f"Cookie value has low entropy ({cookie['entropy']}) - may be predictable"})
        if cookie["is_jwt"]:
            if cookie["jwt_claims"].get("alg") == "none":
                issues.append({"cookie": cookie["name"], "issue": "JWT algorithm 'none'", "severity": "critical", "description": "JWT uses 'none' algorithm - bypasses signature verification"})
            if "exp" not in cookie["jwt_claims"]:
                issues.append({"cookie": cookie["name"], "issue": "JWT missing expiration", "severity": "medium", "description": "JWT token has no expiration claim"})
            if "iss" not in cookie["jwt_claims"]:
                issues.append({"cookie": cookie["name"], "issue": "JWT missing issuer", "severity": "low", "description": "JWT token has no issuer claim"})
        return issues

    def _print_cookie(self, cookie: dict):
        issues = cookie["issues"]
        if issues:
            color = "red"
            status = f"ISSUES ({len(issues)})"
        else:
            color = "green"
            status = "OK"
        jwt_marker = " [JWT]" if cookie["is_jwt"] else ""
        console.print(f"    [{color}]{cookie['name']}[/{color}]{jwt_marker}: {status} | Entropy: {cookie['entropy']} | Encoded: {cookie['is_encoded']}")

    def _analyze_cookies(self, cookies: list) -> dict:
        session_count = len(set(c["name"] for c in cookies if c["is_session_cookie"]))
        analysis = {
            "total_cookies": len(cookies),
            "session_cookies": session_count,
            "persistent_cookies": len(cookies) - session_count,
            "secure_cookies": sum(1 for c in cookies if c["secure"]),
            "httponly_cookies": sum(1 for c in cookies if c["httponly"]),
            "jwt_cookies": sum(1 for c in cookies if c["is_jwt"]),
            "low_entropy": sum(1 for c in cookies if c["entropy"] < 3.0 and len(c["value"]) > 5),
        }
        return analysis

    def _generate_findings(self, results: dict) -> list:
        findings = []
        if results["jwt_tokens"]:
            findings.append(f"{len(results['jwt_tokens'])} JWT token(s) found")
            for jwt in results["jwt_tokens"]:
                claims = jwt["jwt_claims"]
                findings.append(f"  - {jwt['name']}: alg={claims.get('alg', 'unknown')}, exp={'yes' if 'exp' in claims else 'no'}, sub={claims.get('sub', 'N/A')}")
        if results["security_issues"]:
            critical = sum(1 for i in results["security_issues"] if i["severity"] == "critical")
            high = sum(1 for i in results["security_issues"] if i["severity"] == "high")
            medium = sum(1 for i in results["security_issues"] if i["severity"] == "medium")
            findings.append(f"Security issues: {critical} critical, {high} high, {medium} medium")
        if results["session_cookies"]:
            findings.append(f"Session cookies: {', '.join(results['session_cookies'])}")
        analysis = results["analysis"]
        if analysis.get("low_entropy", 0) > 0:
            findings.append(f"{analysis['low_entropy']} cookies have low entropy - may be predictable")
        return findings

    def _calculate_risk(self, results: dict) -> str:
        score = 0
        for issue in results["security_issues"]:
            if issue["severity"] == "critical":
                score += 30
            elif issue["severity"] == "high":
                score += 15
            elif issue["severity"] == "medium":
                score += 5
        if results["jwt_tokens"]:
            score += 10
        analysis = results["analysis"]
        total = analysis.get("total_cookies", 0)
        secure = analysis.get("secure_cookies", 0)
        if total > 0 and secure < total:
            score += (total - secure) * 3
        if score >= 60:
            return "CRITICAL"
        if score >= 35:
            return "HIGH"
        if score >= 15:
            return "MEDIUM"
        return "LOW"

    def _generate_recommendations(self, results: dict) -> list:
        recs = []
        if results["security_issues"]:
            recs.append("Enable Secure flag on all cookies to prevent HTTP transmission")
            recs.append("Enable HttpOnly flag on session cookies to prevent XSS access")
            recs.append("Set SameSite=Lax or SameSite=Strict on all cookies")
        if results["jwt_tokens"]:
            recs.append("JWT tokens found - ensure strong signing algorithm (RS256, not HS256)")
            recs.append("Set short expiration on JWT tokens (15min-1hr)")
            recs.append("Validate JWT signature server-side")
        if results["session_cookies"]:
            recs.append("Regenerate session ID after login to prevent session fixation")
        analysis = results["analysis"]
        if analysis.get("low_entropy", 0) > 0:
            recs.append("Use cryptographically random values for session/cookie values")
        if not results["cookies"]:
            recs.append("No cookies set - application may not use sessions")
        return recs

    def manipulate_cookie(self, name: str, value: str) -> dict:
        console.print(f"[cyan]Manipulating cookie: {name}={value}[/cyan]")
        return {"name": name, "value": value}

    def generate_payloads(self, cookie_name: str) -> list:
        console.print(f"[cyan]Generating manipulation payloads for: {cookie_name}[/cyan]")
        payloads = [
            {"name": cookie_name, "value": "admin", "description": "Try admin role"},
            {"name": cookie_name, "value": "1", "description": "Try user ID 1 (admin)"},
            {"name": cookie_name, "value": "true", "description": "Try boolean true"},
            {"name": cookie_name, "value": "1337", "description": "Try common CTF value"},
            {"name": cookie_name, "value": "null", "description": "Try null value"},
            {"name": cookie_name, "value": "*", "description": "Try wildcard"},
            {"name": cookie_name, "value": "'", "description": "Try SQL injection"},
            {"name": cookie_name, "value": "<script>alert(1)</script>", "description": "Try XSS"},
            {"name": cookie_name, "value": "${7*7}", "description": "Try template injection"},
            {"name": cookie_name, "value": "{{7*7}}", "description": "Try SSTI"},
            {"name": cookie_name, "value": "../../../etc/passwd", "description": "Try path traversal"},
            {"name": cookie_name, "value": "AAAA" * 100, "description": "Try buffer overflow"},
        ]
        for payload in payloads:
            console.print(f"    [cyan]->[/cyan] {payload['description']}: {payload['name']}={payload['value'][:30]}")
        return payloads

    def print_results(self, results: dict):
        risk_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
        risk_color = risk_colors.get(results["risk_level"], "white")

        table = Table(title="Cookie Security Analysis Results", border_style="cyan")
        table.add_column("Property", style="bold")
        table.add_column("Value")
        table.add_row("URL", results["url"])
        table.add_row("Total Cookies", str(results["analysis"]["total_cookies"]))
        table.add_row("Session Cookies", str(results["analysis"]["session_cookies"]))
        table.add_row("Persistent Cookies", str(results["analysis"]["persistent_cookies"]))
        table.add_row("Secure Cookies", str(results["analysis"]["secure_cookies"]))
        table.add_row("HttpOnly Cookies", str(results["analysis"]["httponly_cookies"]))
        table.add_row("JWT Tokens", str(results["analysis"]["jwt_cookies"]))
        table.add_row("Low Entropy", str(results["analysis"]["low_entropy"]))
        table.add_row("Security Issues", str(len(results["security_issues"])))
        table.add_row("Risk Level", f"[{risk_color}]{results['risk_level']}[/{risk_color}]")
        table.add_row("Confidence", f"{results['confidence']}%")
        console.print(table)

        if results["findings"]:
            console.print("\n[bold]Findings:[/bold]")
            for f in results["findings"]:
                console.print(f"  [cyan]->[/cyan] {f}")

        if results["recommendations"]:
            console.print("\n[bold]Recommendations:[/bold]")
            for i, r in enumerate(results["recommendations"], 1):
                console.print(f"  {i}. {r}")
