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
            "category": "Transport Security",
            "recommendation": "Set max-age to at least 31536000 (1 year), includeSubDomains, preload",
            "compliance": ["PCI-DSS", "OWASP", "NIST"],
        },
        "Content-Security-Policy": {
            "description": "Prevents XSS, clickjacking, and other injection attacks",
            "severity": "high",
            "category": "Injection Prevention",
            "recommendation": "Define strict CSP with script-src, style-src, etc. Use nonces instead of unsafe-inline",
            "compliance": ["OWASP", "NIST"],
        },
        "X-Frame-Options": {
            "description": "Prevents clickjacking attacks",
            "severity": "medium",
            "category": "Clickjacking",
            "recommendation": "Set to DENY or SAMEORIGIN",
            "compliance": ["OWASP"],
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME-sniffing attacks",
            "severity": "medium",
            "category": "MIME Security",
            "recommendation": "Set to nosniff",
            "compliance": ["OWASP"],
        },
        "X-XSS-Protection": {
            "description": "Enables browser XSS filter (deprecated but useful for older browsers)",
            "severity": "low",
            "category": "XSS Protection",
            "recommendation": "Set to 1; mode=block (deprecated, use CSP instead)",
            "compliance": [],
        },
        "Referrer-Policy": {
            "description": "Controls referrer information leakage",
            "severity": "medium",
            "category": "Information Leakage",
            "recommendation": "Set to no-referrer or strict-origin-when-cross-origin",
            "compliance": ["OWASP"],
        },
        "Permissions-Policy": {
            "description": "Controls browser features and APIs",
            "severity": "medium",
            "category": "Feature Control",
            "recommendation": "Restrict unnecessary features: camera, microphone, geolocation, payment",
            "compliance": ["OWASP"],
        },
        "Cross-Origin-Opener-Policy": {
            "description": "Isolates browsing context to prevent cross-origin attacks",
            "severity": "low",
            "category": "Cross-Origin Isolation",
            "recommendation": "Set to same-origin",
            "compliance": [],
        },
        "Cross-Origin-Resource-Policy": {
            "description": "Prevents hotlinking and side-channel attacks",
            "severity": "low",
            "category": "Cross-Origin Isolation",
            "recommendation": "Set to same-origin",
            "compliance": [],
        },
        "Cross-Origin-Embedder-Policy": {
            "description": "Enables cross-origin isolation for high-resolution timers",
            "severity": "low",
            "category": "Cross-Origin Isolation",
            "recommendation": "Set to require-corp",
            "compliance": [],
        },
    }

    INTERESTING_HEADERS = [
        "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
        "X-Generator", "X-Drupal-Cache", "X-Varnish", "X-Cache", "X-Cache-Hits",
        "Via", "X-Debug-Token", "X-Debug-Token-Link", "X-Request-ID", "X-Runtime",
        "X-Version", "X-AspNet-Version", "X-AspNetMvc-Version",
    ]

    def __init__(self, url: str, timeout: int = 10):
        self.url = url
        self.timeout = timeout
        self.findings = []
        self.risk_level = "LOW"
        self.confidence = 90
        self.recommendations = []

    def analyze(self) -> dict:
        console.print(Panel("[bold cyan]Header Security Audit[/bold cyan]", border_style="cyan"))
        console.print(f"  [yellow]Target:[/yellow] {self.url}")

        results = {
            "url": self.url, "status_code": 0, "headers": {},
            "security_headers_present": [], "security_headers_missing": [],
            "security_issues": [], "info_headers": {},
            "cookies": [], "technologies": [], "findings": [],
            "risk_level": "LOW", "confidence": 90, "recommendations": [],
            "compliance_score": 0, "categories": {},
        }

        try:
            resp = requests.get(self.url, timeout=self.timeout, verify=False, allow_redirects=True)
            results["status_code"] = resp.status_code
            results["headers"] = dict(resp.headers)
            console.print(f"  [yellow]Status:[/yellow] {resp.status_code}")

            categories = {}
            for header_name, info in self.SECURITY_HEADERS.items():
                value = resp.headers.get(header_name, resp.headers.get(header_name.lower(), ""))
                cat = info["category"]
                if cat not in categories:
                    categories[cat] = {"total": 0, "present": 0, "headers": []}
                categories[cat]["total"] += 1

                if value:
                    results["security_headers_present"].append(header_name)
                    categories[cat]["present"] += 1
                    categories[cat]["headers"].append(header_name)
                    console.print(f"    [green]+[/green] {header_name}: {value[:60]}")
                else:
                    results["security_headers_missing"].append(header_name)
                    severity = info["severity"]
                    color = {"high": "red", "medium": "yellow", "low": "blue"}.get(severity, "white")
                    console.print(f"    [{color}]X[/{color}] Missing: {header_name} ({info['description']})")
                    results["security_issues"].append({
                        "header": header_name, "severity": severity,
                        "description": info["description"],
                        "recommendation": info["recommendation"],
                        "category": cat, "compliance": info["compliance"],
                    })

            results["categories"] = categories

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

            results["cookies"] = self._analyze_cookies(resp)
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

            hsts = resp.headers.get("Strict-Transport-Security", "")
            if hsts:
                max_age_match = re.search(r"max-age=(\d+)", hsts)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 31536000:
                        results["findings"].append(f"HSTS max-age too short: {max_age}s (recommend >= 31536000s)")
                    if "includeSubDomains" not in hsts:
                        results["findings"].append("HSTS missing includeSubDomains directive")
                    if "preload" not in hsts:
                        results["findings"].append("HSTS missing preload directive")

            csp = resp.headers.get("Content-Security-Policy", "")
            if csp:
                if "unsafe-inline" in csp:
                    results["findings"].append("CSP allows unsafe-inline - XSS risk")
                if "unsafe-eval" in csp:
                    results["findings"].append("CSP allows unsafe-eval - code injection risk")
                if "*" in csp:
                    results["findings"].append("CSP uses wildcard (*) - too permissive")

        except requests.RequestException as e:
            console.print(f"  [red]Error: {e}[/red]")
            results["findings"].append(f"Connection error: {e}")

        results["findings"].extend(self._generate_findings(results))
        results["risk_level"] = self._calculate_risk(results)
        results["recommendations"] = self._generate_recommendations(results)
        results["compliance_score"] = self._calculate_compliance(results)

        self.findings = results["findings"]
        self.risk_level = results["risk_level"]
        self.recommendations = results["recommendations"]
        return results

    def _detect_technologies(self, response: requests.Response) -> list:
        technologies = []
        headers = response.headers
        body = response.text[:5000]
        server = headers.get("Server", "")
        if server:
            technologies.append(f"Server: {server}")
        powered_by = headers.get("X-Powered-By", "")
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
            "ASP.NET": [r"ASP\.NET", r"__VIEWSTATE", r"aspxerrorpath"],
            "PHP": [r"\.php", r"PHPSESSID", r"X-Powered-By.*PHP"],
            "Node.js": [r"Express", r"X-Powered-By.*Express"],
        }
        check_text = f"{server} {powered_by} {body}".lower()
        for tech, patterns in tech_signatures.items():
            for pattern in patterns:
                if re.search(pattern, check_text, re.IGNORECASE):
                    if tech not in [t.split(": ")[-1] for t in technologies]:
                        technologies.append(tech)
                    break
        return technologies

    def _analyze_cookies(self, response: requests.Response) -> list:
        results = []
        for cookie in response.cookies:
            results.append({
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": "httponly" in str(response.headers.get("Set-Cookie", "")).lower() if cookie.name in str(response.headers.get("Set-Cookie", "")) else False,
                "samesite": "None",
                "domain": cookie.domain,
            })
        return results

    def _generate_findings(self, results: dict) -> list:
        findings = []
        total = len(self.SECURITY_HEADERS)
        present = len(results["security_headers_present"])
        missing = len(results["security_headers_missing"])
        findings.append(f"Security headers: {present}/{total} present, {missing} missing")
        if missing > 0:
            findings.append(f"Missing {missing} security headers increases attack surface")
        if "Server" in results["info_headers"]:
            findings.append(f"Server header exposed: {results['info_headers']['Server']} - information leakage")
        if "X-Powered-By" in results["info_headers"]:
            findings.append(f"X-Powered-By exposed: {results['info_headers']['X-Powered-By']} - technology disclosure")
        if results["status_code"] == 200:
            findings.append("Application is accessible and responding")
        if any(h in results["headers"].get("X-Frame-Options", "").upper() for h in ["ALLOW-FROM"]):
            findings.append("X-Frame-Options ALLOW-FROM is deprecated")
        return findings

    def _calculate_risk(self, results: dict) -> str:
        score = 0
        if not results["security_headers_present"]:
            score += 40
        else:
            score += max(0, 40 - len(results["security_headers_present"]) * 8)
        high_missing = sum(1 for i in results["security_issues"] if i["severity"] == "high")
        score += high_missing * 15
        medium_missing = sum(1 for i in results["security_issues"] if i["severity"] == "medium")
        score += medium_missing * 5
        if "Server" in results["info_headers"]:
            score += 5
        if "X-Powered-By" in results["info_headers"]:
            score += 5
        if any("unsafe" in str(results["headers"].get("Content-Security-Policy", "")).lower()):
            score += 10
        if score >= 70:
            return "CRITICAL"
        if score >= 40:
            return "HIGH"
        if score >= 20:
            return "MEDIUM"
        return "LOW"

    def _calculate_compliance(self, results: dict) -> int:
        total = len(self.SECURITY_HEADERS)
        present = len(results["security_headers_present"])
        return int((present / total) * 100) if total > 0 else 0

    def _generate_recommendations(self, results: dict) -> list:
        recs = []
        for issue in results["security_issues"]:
            recs.append(f"[{issue['severity'].upper()}] {issue['header']}: {issue['recommendation']}")
        if "Server" in results["info_headers"]:
            recs.append("Remove or obscure the Server header to prevent technology fingerprinting")
        if "X-Powered-By" in results["info_headers"]:
            recs.append("Remove the X-Powered-By header to prevent technology disclosure")
        if results["compliance_score"] < 50:
            recs.append(f"Compliance score is {results['compliance_score']}% - implement missing security headers")
        return recs

    def print_results(self, results: dict):
        risk_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
        risk_color = risk_colors.get(results["risk_level"], "white")

        table = Table(title="Header Security Audit Results", border_style="cyan")
        table.add_column("Property", style="bold")
        table.add_column("Value")
        table.add_row("URL", results["url"])
        table.add_row("Status Code", str(results["status_code"]))
        table.add_row("Security Headers Present", f"{len(results['security_headers_present'])}/{len(self.SECURITY_HEADERS)}")
        table.add_row("Security Headers Missing", str(len(results["security_headers_missing"])))
        table.add_row("Security Issues", str(len(results["security_issues"])))
        table.add_row("Technologies", ", ".join(results["technologies"]) or "Unknown")
        table.add_row("Compliance Score", f"{results['compliance_score']}%")
        table.add_row("Risk Level", f"[{risk_color}]{results['risk_level']}[/{risk_color}]")
        table.add_row("Confidence", f"{results['confidence']}%")
        console.print(table)

        if results["categories"]:
            cat_table = Table(title="Category Breakdown", border_style="cyan")
            cat_table.add_column("Category", style="bold")
            cat_table.add_column("Score")
            cat_table.add_column("Headers")
            for cat, data in results["categories"].items():
                score = f"{data['present']}/{data['total']}"
                cat_table.add_row(cat, score, ", ".join(data["headers"]) or "None")
            console.print(cat_table)

        if results["security_issues"]:
            issue_table = Table(title="Security Issues", border_style="red")
            issue_table.add_column("Header", style="bold")
            issue_table.add_column("Severity")
            issue_table.add_column("Description")
            issue_table.add_column("Recommendation")
            issue_table.add_column("Compliance")
            for issue in results["security_issues"]:
                severity_color = {"high": "red", "medium": "yellow", "low": "blue"}.get(issue["severity"], "white")
                issue_table.add_row(
                    issue["header"],
                    f"[{severity_color}]{issue['severity'].upper()}[/{severity_color}]",
                    issue["description"],
                    issue["recommendation"][:60],
                    ", ".join(issue["compliance"]) or "-",
                )
            console.print(issue_table)

        if results["findings"]:
            console.print("\n[bold]Findings:[/bold]")
            for f in results["findings"]:
                console.print(f"  [cyan]->[/cyan] {f}")

        if results["recommendations"]:
            console.print("\n[bold]Recommendations:[/bold]")
            for i, r in enumerate(results["recommendations"], 1):
                console.print(f"  {i}. {r}")
