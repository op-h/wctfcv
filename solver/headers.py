import re
import requests
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class HeaderAnalyzer:
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "description": "Enforces HTTPS connections",
            "severity": "high",
            "recommendation": "Set max-age to at least 31536000 (1 year)",
        },
        "Content-Security-Policy": {
            "description": "Prevents XSS, clickjacking, and other injection attacks",
            "severity": "high",
            "recommendation": "Define a strict CSP with script-src, style-src, etc.",
        },
        "X-Frame-Options": {
            "description": "Prevents clickjacking attacks",
            "severity": "medium",
            "recommendation": "Set to DENY or SAMEORIGIN",
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME-sniffing attacks",
            "severity": "medium",
            "recommendation": "Set to nosniff",
        },
        "X-XSS-Protection": {
            "description": "Enables browser XSS filter (deprecated but useful for older browsers)",
            "severity": "low",
            "recommendation": "Set to 1; mode=block (deprecated, use CSP instead)",
        },
        "Referrer-Policy": {
            "description": "Controls referrer information leakage",
            "severity": "medium",
            "recommendation": "Set to no-referrer or strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "description": "Controls browser features and APIs",
            "severity": "medium",
            "recommendation": "Restrict unnecessary features like camera, microphone, geolocation",
        },
        "Cross-Origin-Opener-Policy": {
            "description": "Isolates browsing context",
            "severity": "low",
            "recommendation": "Set to same-origin",
        },
        "Cross-Origin-Resource-Policy": {
            "description": "Prevents hotlinking and side-channel attacks",
            "severity": "low",
            "recommendation": "Set to same-origin",
        },
        "Cross-Origin-Embedder-Policy": {
            "description": "Enables cross-origin isolation",
            "severity": "low",
            "recommendation": "Set to require-corp",
        },
    }

    INTERESTING_HEADERS = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Generator",
        "X-Drupal-Cache",
        "X-Varnish",
        "X-Cache",
        "X-Cache-Hits",
        "Via",
        "X-Debug-Token",
        "X-Debug-Token-Link",
        "X-Request-ID",
        "X-Runtime",
        "X-Version",
    ]

    def __init__(self, url: str, timeout: int = 10):
        self.url = url
        self.timeout = timeout

    def analyze(self) -> dict:
        console.print(Panel("[bold cyan]Header Analyzer[/bold cyan]", border_style="cyan"))
        console.print(f"  [yellow]Target:[/yellow] {self.url}")

        results = {
            "url": self.url,
            "status_code": 0,
            "headers": {},
            "security_issues": [],
            "missing_headers": [],
            "info_headers": {},
            "cookies": [],
            "technologies": [],
        }

        try:
            resp = requests.get(self.url, timeout=self.timeout, verify=False, allow_redirects=True)
            results["status_code"] = resp.status_code
            results["headers"] = dict(resp.headers)

            console.print(f"  [yellow]Status:[/yellow] {resp.status_code}")

            for header_name, info in self.SECURITY_HEADERS.items():
                value = resp.headers.get(header_name, resp.headers.get(header_name.lower(), ""))
                if value:
                    console.print(f"    [green]+[/green] {header_name}: {value[:60]}")
                else:
                    results["missing_headers"].append(header_name)
                    severity = info["severity"]
                    color = {"high": "red", "medium": "yellow", "low": "blue"}.get(severity, "white")
                    console.print(f"    [{color}]X[/{color}] Missing: {header_name} ({info['description']})")
                    results["security_issues"].append({
                        "header": header_name,
                        "severity": severity,
                        "description": info["description"],
                        "recommendation": info["recommendation"],
                    })

            for header_name in self.INTERESTING_HEADERS:
                value = resp.headers.get(header_name, resp.headers.get(header_name.lower(), ""))
                if value:
                    results["info_headers"][header_name] = value
                    console.print(f"    [yellow]![/yellow] {header_name}: {value}")

            results["technologies"] = self._detect_technologies(resp)
            if results["technologies"]:
                console.print(f"  [yellow]Technologies detected:[/yellow]")
                for tech in results["technologies"]:
                    console.print(f"    [cyan]->[/cyan] {tech}")

            results["cookies"] = self._analyze_cookies(resp.cookies)
            if results["cookies"]:
                console.print(f"  [yellow]Cookie analysis:[/yellow]")
                for cookie in results["cookies"]:
                    issues = []
                    if not cookie["secure"]:
                        issues.append("Missing Secure flag")
                    if not cookie["httponly"]:
                        issues.append("Missing HttpOnly flag")
                    if cookie["samesite"] == "None":
                        issues.append("SameSite=None")
                    status = ", ".join(issues) if issues else "OK"
                    color = "red" if issues else "green"
                    console.print(f"    [{color}]{cookie['name']}[/{color}]: {status}")

        except requests.RequestException as e:
            console.print(f"  [red]Error: {e}[/red]")

        return results

    def _detect_technologies(self, response: requests.Response) -> list:
        technologies = []
        headers = response.headers
        body = response.text[:5000]

        server = headers.get("Server", headers.get("server", ""))
        if server:
            technologies.append(f"Server: {server}")

        powered_by = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        if powered_by:
            technologies.append(f"Framework: {powered_by}")

        tech_signatures = {
            "WordPress": [r"wp-content", r"wp-includes", r"wp-json", r"wordpress"],
            "Drupal": [r"Drupal", r"drupal\.js", r"sites/default/files"],
            "Joomla": [r"Joomla", r"/components/", r"/modules/"],
            "Laravel": [r"laravel", r"XSRF-TOKEN", r"laravel_session"],
            "Django": [r"csrfmiddlewaretoken", r"__admin__", r"django"],
            "Flask": [r"Flask", r"Werkzeug", r"flask"],
            "Spring": [r"Spring", r"JSESSIONID", r"spring"],
            "ASP.NET": [r"ASP\.NET", r"__VIEWSTATE", r"__VIEWSTATEGENERATOR", r"aspxerrorpath"],
            "PHP": [r"\.php", r"PHPSESSID", r"X-Powered-By.*PHP"],
            "Node.js": [r"Express", r"connect", r"X-Powered-By.*Express"],
            "Apache": [r"Apache"],
            "Nginx": [r"Nginx"],
            "IIS": [r"IIS", r"Microsoft-IIS"],
        }

        check_text = f"{server} {powered_by} {body}".lower()
        for tech, patterns in tech_signatures.items():
            for pattern in patterns:
                if re.search(pattern, check_text, re.IGNORECASE):
                    if tech not in [t.split(": ")[-1] for t in technologies]:
                        technologies.append(tech)
                    break

        return technologies

    def _analyze_cookies(self, cookies) -> list:
        results = []
        for cookie in cookies:
            results.append({
                "name": cookie.name,
                "value": cookie.value[:20] + "..." if len(cookie.value) > 20 else cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": cookie.secure,
                "httponly": cookie._rest.get("HttpOnly", False) if hasattr(cookie, '_rest') else False,
                "samesite": cookie._rest.get("SameSite", "None") if hasattr(cookie, '_rest') else "None",
                "expires": cookie.expires,
            })
        return results

    def print_results(self, results: dict):
        table = Table(title="Header Analysis Results", border_style="cyan")
        table.add_column("Property", style="bold")
        table.add_column("Value")
        table.add_row("URL", results["url"])
        table.add_row("Status Code", str(results["status_code"]))
        table.add_row("Missing Security Headers", str(len(results["missing_headers"])))
        table.add_row("Security Issues", str(len(results["security_issues"])))
        table.add_row("Technologies", ", ".join(results["technologies"]) or "Unknown")
        if results["missing_headers"]:
            table.add_row("Missing Headers", "\n".join(results["missing_headers"]))
        console.print(table)

        if results["security_issues"]:
            issue_table = Table(title="Security Issues", border_style="red")
            issue_table.add_column("Header", style="bold")
            issue_table.add_column("Severity")
            issue_table.add_column("Description")
            issue_table.add_column("Recommendation")
            for issue in results["security_issues"]:
                severity_color = {"high": "red", "medium": "yellow", "low": "blue"}.get(issue["severity"], "white")
                issue_table.add_row(
                    issue["header"],
                    f"[{severity_color}]{issue['severity'].upper()}[/{severity_color}]",
                    issue["description"],
                    issue["recommendation"],
                )
            console.print(issue_table)
