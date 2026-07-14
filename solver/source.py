import re
import requests
from typing import Optional
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class SourceAnalyzer:
    def __init__(self, url: str, timeout: int = 10, headers: Optional[dict] = None, cookies: Optional[dict] = None):
        self.url = url
        self.timeout = timeout
        self.headers = headers or {}
        self.cookies = cookies or {}

    def analyze(self) -> dict:
        console.print(Panel("[bold cyan]Source Code Analyzer[/bold cyan]", border_style="cyan"))
        console.print(f"  [yellow]Target:[/yellow] {self.url}")

        results = {
            "url": self.url,
            "comments": [],
            "hidden_fields": [],
            "links": [],
            "scripts": [],
            "forms": [],
            "emails": [],
            "ips": [],
            "api_keys": [],
            "interesting_strings": [],
            "meta_tags": [],
        }

        try:
            resp = requests.get(
                self.url,
                headers=self.headers,
                cookies=self.cookies,
                timeout=self.timeout,
                verify=False,
            )
            html = resp.text
            soup = BeautifulSoup(html, "html.parser")

            results["comments"] = self._extract_comments(html)
            console.print(f"  [yellow]Comments found:[/yellow] {len(results['comments'])}")
            for comment in results["comments"]:
                console.print(f"    [cyan]->[/cyan] {comment[:80]}")

            results["hidden_fields"] = self._extract_hidden_fields(soup)
            console.print(f"  [yellow]Hidden fields found:[/yellow] {len(results['hidden_fields'])}")
            for field in results["hidden_fields"]:
                console.print(f"    [cyan]->[/cyan] {field['name']}={field['value'][:50]}")

            results["forms"] = self._extract_forms(soup)
            console.print(f"  [yellow]Forms found:[/yellow] {len(results['forms'])}")
            for form in results["forms"]:
                console.print(f"    [cyan]->[/cyan] {form['action']} ({form['method']}) - {len(form['inputs'])} inputs")

            results["links"] = self._extract_links(soup)
            console.print(f"  [yellow]Links found:[/yellow] {len(results['links'])}")

            results["scripts"] = self._extract_scripts(soup, html)
            console.print(f"  [yellow]Scripts found:[/yellow] {len(results['scripts'])}")

            results["emails"] = self._extract_emails(html)
            console.print(f"  [yellow]Emails found:[/yellow] {len(results['emails'])}")
            for email in results["emails"]:
                console.print(f"    [cyan]->[/cyan] {email}")

            results["ips"] = self._extract_ips(html)
            console.print(f"  [yellow]IP addresses found:[/yellow] {len(results['ips'])}")
            for ip in results["ips"]:
                console.print(f"    [cyan]->[/cyan] {ip}")

            results["api_keys"] = self._extract_api_keys(html)
            console.print(f"  [yellow]Potential API keys found:[/yellow] {len(results['api_keys'])}")
            for key in results["api_keys"]:
                console.print(f"    [red]![/red] {key['type']}: {key['value'][:40]}...")

            results["interesting_strings"] = self._extract_interesting_strings(html)
            console.print(f"  [yellow]Interesting strings:[/yellow] {len(results['interesting_strings'])}")
            for s in results["interesting_strings"]:
                console.print(f"    [yellow]~[/yellow] {s[:80]}")

            results["meta_tags"] = self._extract_meta_tags(soup)

        except requests.RequestException as e:
            console.print(f"  [red]Error: {e}[/red]")

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
            fields.append({
                "name": field.get("name", "unknown"),
                "value": field.get("value", ""),
                "id": field.get("id", ""),
            })
        for field in soup.find_all("input", {"type": "text"}):
            value = field.get("value", "")
            if value and len(value) > 10:
                fields.append({
                    "name": field.get("name", "unknown"),
                    "value": value,
                    "id": field.get("id", ""),
                })
        return fields

    def _extract_forms(self, soup: BeautifulSoup) -> list:
        forms = []
        for form in soup.find_all("form"):
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "type": inp.get("type", "text"),
                    "name": inp.get("name", ""),
                    "value": inp.get("value", "")[:50],
                })
            forms.append({
                "action": form.get("action", self.url),
                "method": form.get("method", "GET").upper(),
                "inputs": inputs,
                "id": form.get("id", ""),
                "name": form.get("name", ""),
            })
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
                    interesting.append("eval() call")
                if "document.cookie" in clean:
                    interesting.append("cookie access")
                if "XMLHttpRequest" in clean or "fetch(" in clean:
                    interesting.append("AJAX request")
                if "localStorage" in clean or "sessionStorage" in clean:
                    interesting.append("storage access")
                if "eval(" in clean or "Function(" in clean:
                    interesting.append("code execution")
                scripts.append({
                    "type": "inline",
                    "index": i,
                    "length": len(clean),
                    "interesting": interesting,
                    "preview": clean[:100],
                })
        return scripts

    def _extract_emails(self, html: str) -> list:
        emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", html))
        return list(emails)

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
            (r"aws[_-]?(?:access|secret)[_-]?key\s*[=:]\s*['\"]([^'\"]+)['\"]", "AWS Key"),
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        ]
        keys = []
        for pattern, key_type in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if len(match) > 5:
                    keys.append({"type": key_type, "value": match})
        return keys

    def _extract_interesting_strings(self, html: str) -> list:
        strings = []
        patterns = [
            (r"(?:flag|ctf|key|token|secret|password|admin)\s*[=:]\s*['\"]([^'\"]+)['\"]", "Sensitive value"),
            (r"TODO[:\s]*(.+?)$", "TODO comment"),
            (r"FIXME[:\s]*(.+?)$", "FIXME comment"),
            (r"HACK[:\s]*(.+?)$", "HACK comment"),
            (r"XXX[:\s]*(.+?)$", "XXX comment"),
            (r"debug\s*[=:]\s*(true|1|on)", "Debug mode"),
            (r"admin\s*[=:]\s*(true|1|on)", "Admin mode"),
        ]
        for pattern, desc in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                if isinstance(match, str) and len(match) > 2:
                    strings.append(f"{desc}: {match}")
        return strings[:20]

    def _extract_meta_tags(self, soup: BeautifulSoup) -> list:
        metas = []
        for meta in soup.find_all("meta"):
            name = meta.get("name", meta.get("property", ""))
            content = meta.get("content", "")
            if name and content:
                metas.append({"name": name, "content": content})
        return metas

    def print_results(self, results: dict):
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
        table.add_row("IP Addresses", str(len(results["ips"])))
        table.add_row("API Keys", str(len(results["api_keys"])))
        table.add_row("Interesting Strings", str(len(results["interesting_strings"])))
        console.print(table)
