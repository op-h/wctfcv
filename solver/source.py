import re
import requests
from typing import Optional
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class SourceAnalyzer:
    HIGH_RISK_PATTERNS = [
        (r"(?:flag|ctf)\s*[=:]\s*['\"]([^'\"]+)['\"]", "CTF Flag found"),
        (r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]+)['\"]", "Hardcoded password"),
        (r"(?:secret|api[_-]?key|auth[_-]?token)\s*[=:]\s*['\"]([^'\"]+)['\"]", "Secret/API key exposed"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        (r"ghp_[0-9a-zA-Z]{36}", "GitHub Token"),
        (r"sk-[0-9a-zA-Z]{48}", "OpenAI API Key"),
        (r"(?:jwt|bearer)\s*[=:]\s*['\"]([^'\"]+)['\"]", "JWT/Bearer token exposed"),
        (r"(?:admin|root)\s*[=:]\s*(?:true|1|'1'|\"1\")", "Admin flag enabled"),
        (r"eval\s*\(", "eval() call - code execution risk"),
        (r"Function\s*\(", "Function constructor - code execution risk"),
        (r"document\.cookie", "Cookie access - potential XSS exfil target"),
        (r"innerHTML\s*=", "innerHTML assignment - XSS risk"),
        (r"outerHTML\s*=", "outerHTML assignment - XSS risk"),
        (r"\.html\s*\(", "jQuery HTML injection risk"),
        (r"exec\s*\(", "exec() call - code execution risk"),
    ]

    MEDIUM_RISK_PATTERNS = [
        (r"TODO[:\s]*(.+?)$", "TODO comment"),
        (r"FIXME[:\s]*(.+?)$", "FIXME comment"),
        (r"HACK[:\s]*(.+?)$", "HACK comment"),
        (r"XXX[:\s]*(.+?)$", "XXX comment"),
        (r"debug\s*[=:]\s*(true|1|on)", "Debug mode enabled"),
        (r"console\.(log|warn|error)\s*\(", "Console logging in production"),
        (r"XMLHttpRequest|fetch\s*\(", "AJAX requests"),
        (r"localStorage|sessionStorage", "Browser storage access"),
        (r"navigator\.userAgent", "User-Agent sniffing"),
        (r"window\.open\s*\(", "Window popup"),
        (r"document\.write\s*\(", "document.write - potential XSS"),
    ]

    def __init__(self, url: str, timeout: int = 10, headers: Optional[dict] = None, cookies: Optional[dict] = None):
        self.url = url
        self.timeout = timeout
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.findings = []
        self.risk_level = "LOW"
        self.confidence = 85
        self.recommendations = []

    def analyze(self) -> dict:
        console.print(Panel("[bold cyan]Source Code Analyzer[/bold cyan]", border_style="cyan"))
        console.print(f"  [yellow]Target:[/yellow] {self.url}")

        results = {
            "url": self.url, "comments": [], "hidden_fields": [], "links": [],
            "scripts": [], "forms": [], "emails": [], "ips": [], "api_keys": [],
            "interesting_strings": [], "meta_tags": [], "high_risk": [],
            "medium_risk": [], "attack_surface": [],
            "findings": [], "risk_level": "LOW", "confidence": 85, "recommendations": [],
        }

        try:
            resp = requests.get(self.url, headers=self.headers, cookies=self.cookies, timeout=self.timeout, verify=False)
            html = resp.text
            soup = BeautifulSoup(html, "html.parser")

            results["comments"] = self._extract_comments(html)
            console.print(f"  [yellow]Comments found:[/yellow] {len(results['comments'])}")
            for comment in results["comments"][:5]:
                console.print(f"    [cyan]->[/cyan] {comment[:80]}")

            results["hidden_fields"] = self._extract_hidden_fields(soup)
            console.print(f"  [yellow]Hidden fields found:[/yellow] {len(results['hidden_fields'])}")
            for field in results["hidden_fields"]:
                console.print(f"    [cyan]->[/cyan] {field['name']}={field['value'][:50]}")

            results["forms"] = self._extract_forms(soup)
            console.print(f"  [yellow]Forms found:[/yellow] {len(results['forms'])}")

            results["links"] = self._extract_links(soup)
            console.print(f"  [yellow]Links found:[/yellow] {len(results['links'])}")

            results["scripts"] = self._extract_scripts(soup, html)
            console.print(f"  [yellow]Scripts found:[/yellow] {len(results['scripts'])}")

            results["emails"] = self._extract_emails(html)
            console.print(f"  [yellow]Emails found:[/yellow] {len(results['emails'])}")

            results["ips"] = self._extract_ips(html)
            console.print(f"  [yellow]IP addresses found:[/yellow] {len(results['ips'])}")

            results["api_keys"] = self._extract_api_keys(html)
            console.print(f"  [yellow]Potential secrets found:[/yellow] {len(results['api_keys'])}")

            results["high_risk"], results["medium_risk"] = self._scan_risks(html)
            console.print(f"  [yellow]High-risk patterns:[/yellow] {len(results['high_risk'])}")
            console.print(f"  [yellow]Medium-risk patterns:[/yellow] {len(results['medium_risk'])}")

            results["attack_surface"] = self._map_attack_surface(results)

            results["meta_tags"] = self._extract_meta_tags(soup)
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

    def _extract_comments(self, html: str) -> list:
        comments = []
        html_comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
        for comment in html_comments:
            clean = comment.strip()
            if clean and len(clean) > 2:
                comments.append(clean)
        js_comments = re.findall(r"//(.+?)$", html, re.MULTILINE)
        for comment in js_comments:
            clean = comment.strip()
            if clean and len(clean) > 5:
                comments.append(f"// {clean}")
        return comments

    def _extract_hidden_fields(self, soup: BeautifulSoup) -> list:
        fields = []
        for field in soup.find_all("input", {"type": "hidden"}):
            fields.append({"name": field.get("name", "unknown"), "value": field.get("value", ""), "id": field.get("id", "")})
        return fields

    def _extract_forms(self, soup: BeautifulSoup) -> list:
        forms = []
        for form in soup.find_all("form"):
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({"type": inp.get("type", "text"), "name": inp.get("name", ""), "value": inp.get("value", "")[:50]})
            forms.append({"action": form.get("action", self.url), "method": form.get("method", "GET").upper(), "inputs": inputs})
        return forms

    def _extract_links(self, soup: BeautifulSoup) -> list:
        links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith(("http://", "https://", "/")):
                links.add(href)
        return list(links)[:50]

    def _extract_scripts(self, soup: BeautifulSoup, html: str) -> list:
        scripts = []
        for script in soup.find_all("script", src=True):
            scripts.append({"type": "external", "src": script["src"]})
        inline_scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL)
        for i, script in enumerate(inline_scripts):
            clean = script.strip()
            if clean:
                interesting = []
                if "eval(" in clean:
                    interesting.append("eval() - code execution")
                if "document.cookie" in clean:
                    interesting.append("cookie access")
                if "XMLHttpRequest" in clean or "fetch(" in clean:
                    interesting.append("AJAX request")
                if "innerHTML" in clean:
                    interesting.append("innerHTML - XSS risk")
                scripts.append({"type": "inline", "index": i, "length": len(clean), "interesting": interesting, "preview": clean[:100]})
        return scripts

    def _extract_emails(self, html: str) -> list:
        return list(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", html)))

    def _extract_ips(self, html: str) -> list:
        ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", html))
        return [ip for ip in ips if not ip.startswith("0.") and ip != "0.0.0.0"]

    def _extract_api_keys(self, html: str) -> list:
        patterns = [
            (r"api[_-]?key\s*[=:]\s*['\"]([^'\"]+)['\"]", "API Key"),
            (r"secret[_-]?key\s*[=:]\s*['\"]([^'\"]+)['\"]", "Secret Key"),
            (r"access[_-]?token\s*[=:]\s*['\"]([^'\"]+)['\"]", "Access Token"),
            (r"auth[_-]?token\s*[=:]\s*['\"]([^'\"]+)['\"]", "Auth Token"),
            (r"password\s*[=:]\s*['\"]([^'\"]+)['\"]", "Password"),
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        ]
        keys = []
        for pattern, key_type in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if len(match) > 5:
                    keys.append({"type": key_type, "value": match})
        return keys

    def _scan_risks(self, html: str) -> tuple:
        high_risk = []
        medium_risk = []
        for pattern, desc in self.HIGH_RISK_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                if isinstance(match, str) and len(match) > 2:
                    high_risk.append(f"{desc}: {match[:80]}")
        for pattern, desc in self.MEDIUM_RISK_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE | re.MULTILINE)
            if matches:
                medium_risk.append(desc)
        return high_risk, medium_risk

    def _map_attack_surface(self, results: dict) -> list:
        surface = []
        if results["forms"]:
            surface.append(f"{len(results['forms'])} forms - test for SQLi, XSS, CSRF")
        if results["scripts"]:
            inline = [s for s in results["scripts"] if s["type"] == "inline"]
            if inline:
                surface.append(f"{len(inline)} inline scripts - audit for XSS, DOM vulnerabilities")
        if results["api_keys"]:
            surface.append(f"{len(results['api_keys'])} secrets exposed - immediate risk")
        if results["emails"]:
            surface.append(f"{len(results['emails'])} emails - phishing/recon target")
        if results["hidden_fields"]:
            surface.append(f"{len(results['hidden_fields'])} hidden fields - test for manipulation")
        if results["links"]:
            surface.append(f"{len(results['links'])} links - test for open redirects, IDOR")
        return surface

    def _generate_findings(self, results: dict) -> list:
        findings = []
        if results["high_risk"]:
            findings.append(f"HIGH RISK: {len(results['high_risk'])} critical patterns found")
            for r in results["high_risk"][:5]:
                findings.append(f"  - {r}")
        if results["medium_risk"]:
            findings.append(f"MEDIUM RISK: {len(results['medium_risk'])} warning patterns")
        if results["comments"]:
            findings.append(f"{len(results['comments'])} HTML/JS comments found - may leak info")
        if results["hidden_fields"]:
            findings.append(f"{len(results['hidden_fields'])} hidden fields - potential for manipulation")
        if results["api_keys"]:
            findings.append(f"CRITICAL: {len(results['api_keys'])} secrets/API keys exposed in source")
        if results["emails"]:
            findings.append(f"{len(results['emails'])} email addresses exposed - recon/phishing risk")
        return findings

    def _calculate_risk(self, results: dict) -> str:
        score = 0
        score += len(results["high_risk"]) * 20
        score += len(results["medium_risk"]) * 5
        score += len(results["api_keys"]) * 25
        score += len(results["comments"]) * 2
        if len(results["high_risk"]) > 5:
            score += 20
        if score >= 70:
            return "CRITICAL"
        if score >= 40:
            return "HIGH"
        if score >= 20:
            return "MEDIUM"
        return "LOW"

    def _generate_recommendations(self, results: dict) -> list:
        recs = []
        if results["api_keys"]:
            recs.append("CRITICAL: Remove exposed secrets from source code - use environment variables")
        if results["high_risk"]:
            recs.append("Review high-risk patterns: eval(), innerHTML, hardcoded credentials")
        if results["comments"]:
            recs.append("Remove HTML comments containing sensitive information")
        if results["hidden_fields"]:
            recs.append("Validate hidden field values server-side - they can be tampered with")
        if results["emails"]:
            recs.append("Consider using contact forms instead of exposing email addresses")
        if not results["forms"] and not results["scripts"]:
            recs.append("Limited attack surface detected - may be a static page")
        return recs

    def print_results(self, results: dict):
        risk_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
        risk_color = risk_colors.get(results["risk_level"], "white")

        table = Table(title="Source Code Analysis Results", border_style="cyan")
        table.add_column("Property", style="bold")
        table.add_column("Value")
        table.add_row("URL", results["url"])
        table.add_row("Comments", str(len(results["comments"])))
        table.add_row("Hidden Fields", str(len(results["hidden_fields"])))
        table.add_row("Forms", str(len(results["forms"])))
        table.add_row("Links", str(len(results["links"])))
        table.add_row("Scripts", str(len(results["scripts"])))
        table.add_row("Emails", str(len(results["emails"])))
        table.add_row("Secrets/API Keys", str(len(results["api_keys"])))
        table.add_row("High-Risk Patterns", str(len(results["high_risk"])))
        table.add_row("Medium-Risk Patterns", str(len(results["medium_risk"])))
        table.add_row("Attack Surface Items", str(len(results["attack_surface"])))
        table.add_row("Risk Level", f"[{risk_color}]{results['risk_level']}[/{risk_color}]")
        table.add_row("Confidence", f"{results['confidence']}%")
        console.print(table)

        if results["attack_surface"]:
            console.print("\n[bold]Attack Surface:[/bold]")
            for a in results["attack_surface"]:
                console.print(f"  [cyan]->[/cyan] {a}")

        if results["findings"]:
            console.print("\n[bold]Findings:[/bold]")
            for f in results["findings"]:
                console.print(f"  [cyan]->[/cyan] {f}")

        if results["recommendations"]:
            console.print("\n[bold]Recommendations:[/bold]")
            for i, r in enumerate(results["recommendations"], 1):
                console.print(f"  {i}. {r}")
