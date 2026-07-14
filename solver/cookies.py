import re
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

    def __init__(self, url: str, timeout: int = 10, headers: Optional[dict] = None):
        self.url = url
        self.timeout = timeout
        self.headers = headers or {}

    def analyze(self) -> dict:
        console.print(Panel("[bold cyan]Cookie Analyzer[/bold cyan]", border_style="cyan"))
        console.print(f"  [yellow]Target:[/yellow] {self.url}")

        results = {
            "url": self.url,
            "cookies": [],
            "security_issues": [],
            "session_cookies": [],
            "analysis": {},
        }

        try:
            resp = requests.get(
                self.url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )

            cookie_jar = resp.cookies
            console.print(f"  [yellow]Cookies received:[/yellow] {len(cookie_jar)}")

            for cookie in cookie_jar:
                cookie_info = {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "httponly": self._check_httponly(resp, cookie.name),
                    "samesite": self._check_samesite(resp, cookie.name),
                    "expires": cookie.expires,
                    "max_age": cookie._rest.get("Max-Age", None) if hasattr(cookie, '_rest') else None,
                    "is_session": cookie.expires is None,
                    "is_encoded": self._check_encoding(cookie.value),
                    "entropy": self._calculate_entropy(cookie.value),
                    "is_session_cookie": cookie.name in self.COMMON_SESSION_COOKIES or any(
                        cs.lower() in cookie.name.lower() for cs in self.COMMON_SESSION_COOKIES
                    ),
                }

                issues = self._check_security(cookie_info)
                cookie_info["issues"] = issues
                results["security_issues"].extend(issues)
                results["cookies"].append(cookie_info)

                if cookie_info["is_session_cookie"]:
                    results["session_cookies"].append(cookie_info["name"])

                self._print_cookie(cookie_info)

            results["analysis"] = self._analyze_cookies(results["cookies"])

            if results["analysis"]["recommendations"]:
                console.print(f"\n  [yellow]Recommendations:[/yellow]")
                for rec in results["analysis"]["recommendations"]:
                    console.print(f"    [cyan]->[/cyan] {rec}")

        except requests.RequestException as e:
            console.print(f"  [red]Error: {e}[/red]")

        return results

    def _check_httponly(self, response: requests.Response, cookie_name: str) -> bool:
        for header in ["Set-Cookie", "set-cookie"]:
            if header in response.headers:
                cookies = response.headers.get(header, "")
                if cookie_name in cookies:
                    return "httponly" in cookies.lower()
        return False

    def _check_samesite(self, response: requests.Response, cookie_name: str) -> str:
        for header in ["Set-Cookie", "set-cookie"]:
            if header in response.headers:
                cookies = response.headers.get(header, "")
                if cookie_name in cookies:
                    match = re.search(r"samesite\s*=\s*(\w+)", cookies, re.IGNORECASE)
                    if match:
                        return match.group(1)
        return "None"

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
        import math
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

    def _check_security(self, cookie: dict) -> list:
        issues = []
        if not cookie["secure"]:
            issues.append({
                "cookie": cookie["name"],
                "issue": "Missing Secure flag",
                "severity": "medium",
                "description": "Cookie can be transmitted over HTTP, allowing interception",
            })
        if not cookie["httponly"]:
            issues.append({
                "cookie": cookie["name"],
                "issue": "Missing HttpOnly flag",
                "severity": "medium",
                "description": "Cookie is accessible via JavaScript (XSS target)",
            })
        if cookie["samesite"] == "None":
            issues.append({
                "cookie": cookie["name"],
                "issue": "SameSite=None",
                "severity": "low",
                "description": "Cookie is sent with cross-origin requests (CSRF risk)",
            })
        if cookie["is_session_cookie"] and cookie["expires"] is not None:
            issues.append({
                "cookie": cookie["name"],
                "issue": "Session cookie has expiration",
                "severity": "info",
                "description": "Session cookies should not have an expiration",
            })
        if cookie["entropy"] < 3.0 and len(cookie["value"]) > 5:
            issues.append({
                "cookie": cookie["name"],
                "issue": "Low entropy value",
                "severity": "medium",
                "description": f"Cookie value has low entropy ({cookie['entropy']}), may be predictable",
            })
        return issues

    def _print_cookie(self, cookie: dict):
        issues = cookie["issues"]
        if issues:
            color = "red"
            status = f"ISSUES ({len(issues)})"
        else:
            color = "green"
            status = "OK"
        console.print(f"    [{color}]{cookie['name']}[/{color}]: {status} | Entropy: {cookie['entropy']} | Encoded: {cookie['is_encoded']}")

    def _analyze_cookies(self, cookies: list) -> dict:
        analysis = {
            "total_cookies": len(cookies),
            "session_cookies": 0,
            "persistent_cookies": 0,
            "secure_cookies": 0,
            "httponly_cookies": 0,
            "recommendations": [],
        }
        for cookie in cookies:
            if cookie["is_session_cookie"]:
                analysis["session_cookies"] += 1
            else:
                analysis["persistent_cookies"] += 1
            if cookie["secure"]:
                analysis["secure_cookies"] += 1
            if cookie["httponly"]:
                analysis["httponly_cookies"] += 1

        if analysis["session_cookies"] > 0 and analysis["secure_cookies"] < analysis["session_cookies"]:
            analysis["recommendations"].append("Enable Secure flag on all session cookies")
        if analysis["session_cookies"] > 0 and analysis["httponly_cookies"] < analysis["session_cookies"]:
            analysis["recommendations"].append("Enable HttpOnly flag on all session cookies")
        if analysis["total_cookies"] > 10:
            analysis["recommendations"].append("Consider reducing the number of cookies (current: " + str(analysis["total_cookies"]) + ")")
        return analysis

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
            {"name": cookie_name, "value": "a]a]a]a", "description": "Try array manipulation"},
            {"name": cookie_name, "value": "null", "description": "Try null value"},
            {"name": cookie_name, "value": "undefined", "description": "Try undefined value"},
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
        table = Table(title="Cookie Analysis Results", border_style="cyan")
        table.add_column("Property", style="bold")
        table.add_column("Value")
        table.add_row("URL", results["url"])
        table.add_row("Total Cookies", str(results["analysis"]["total_cookies"]))
        table.add_row("Session Cookies", str(results["analysis"]["session_cookies"]))
        table.add_row("Persistent Cookies", str(results["analysis"]["persistent_cookies"]))
        table.add_row("Secure Cookies", str(results["analysis"]["secure_cookies"]))
        table.add_row("HttpOnly Cookies", str(results["analysis"]["httponly_cookies"]))
        table.add_row("Security Issues", str(len(results["security_issues"])))
        console.print(table)
