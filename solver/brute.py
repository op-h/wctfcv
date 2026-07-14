import os
import re
import requests
from typing import Optional
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel

console = Console()


class DirectoryBruter:
    COMMON_EXTENSIONS = ["", ".php", ".html", ".txt", ".js", ".json", ".xml"]

    SENSITIVE_PATTERNS = [
        (r"(?:flag|ctf|key|secret|password|token|admin|root)\s*[=:]\s*['\"]([^'\"]+)['\"]", "Sensitive value exposed"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token"),
        (r"sk-[0-9a-zA-Z]{48}", "OpenAI API Key"),
        (r"(?:api|secret|auth)[_-]?key\s*[=:]\s*['\"]([^'\"]+)['\"]", "API key exposed"),
        (r"<title>.*(?:Admin|Login|Dashboard|Panel).*?</title>", "Admin interface found"),
        (r"index of /", "Directory listing enabled"),
        (r"SQLSTATE\[", "Database error exposed"),
        (r"Stack Trace", "Error details exposed"),
        (r"Debug mode", "Debug mode enabled"),
    ]

    def __init__(self, url: str, wordlist: Optional[str] = None, extensions: Optional[list] = None, threads: int = 10, timeout: int = 10, headers: Optional[dict] = None, cookies: Optional[dict] = None):
        self.url = url.rstrip("/")
        self.wordlist = wordlist
        self.extensions = extensions or self.COMMON_EXTENSIONS
        self.threads = threads
        self.timeout = timeout
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.found = []
        self.findings = []
        self.confidence = 0
        self.risk_level = "LOW"
        self.recommendations = []

    def _load_wordlist(self) -> list:
        words = []
        default_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", "directories.txt")
        list_path = self.wordlist or default_path
        try:
            with open(list_path, "r") as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            console.print(f"[red]Wordlist not found: {list_path}[/red]")
            words = ["admin", "login", "api", "test", "dev", "backup", "config", "uploads", "flag", "robots.txt"]
        return words

    def _check_path(self, path: str) -> Optional[dict]:
        url = f"{self.url}/{path}"
        try:
            resp = requests.get(
                url, headers=self.headers, cookies=self.cookies,
                timeout=self.timeout, allow_redirects=False, verify=False,
            )
            if resp.status_code not in [404, 403, 500, 502, 503, 504]:
                result = {
                    "url": url, "status": resp.status_code,
                    "size": len(resp.text), "path": path,
                    "redirect": resp.headers.get("Location", ""),
                    "server": resp.headers.get("Server", ""),
                    "content_type": resp.headers.get("Content-Type", ""),
                    "sensitive_patterns": [],
                }
                for pattern, desc in self.SENSITIVE_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        result["sensitive_patterns"].append(desc)
                return result
        except requests.RequestException:
            pass
        return None

    def scan(self) -> dict:
        console.print(Panel("[bold cyan]Directory Brute-Force Scanner[/bold cyan]", border_style="cyan"))
        words = self._load_wordlist()
        paths = []
        for word in words:
            for ext in self.extensions:
                paths.append(f"{word}{ext}" if ext else word)

        console.print(f"  [yellow]Target:[/yellow] {self.url}")
        console.print(f"  [yellow]Wordlist:[/yellow] {len(words)} words")
        console.print(f"  [yellow]Total paths:[/yellow] {len(paths)}")
        console.print(f"  [yellow]Threads:[/yellow] {self.threads}")

        results = {"url": self.url, "found": [], "sensitive": [], "tech": set(), "findings": [], "risk_level": "LOW", "confidence": 0, "recommendations": []}

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("  Bruting...", total=len(paths))
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._check_path, path): path for path in paths}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results["found"].append(result)
                        self.found.append(result)
                        if result["server"]:
                            results["tech"].add(result["server"])
                        if result["sensitive_patterns"]:
                            results["sensitive"].extend(result["sensitive_patterns"])
                            for sp in result["sensitive_patterns"]:
                                console.print(f"    [bold red]![/bold red] {result['status']} {result['url']} - {sp}")
                        else:
                            console.print(f"    [green]+[/green] {result['status']} {result['url']} ({result['size']} bytes)")
                    progress.update(task, advance=1)

        results["tech"] = list(results["tech"])
        results["findings"] = self._analyze_results(results)
        results["risk_level"] = self._calculate_risk(results)
        results["confidence"] = 85 if results["found"] else 30
        results["recommendations"] = self._generate_recommendations(results)

        self.findings = results["findings"]
        self.risk_level = results["risk_level"]
        self.recommendations = results["recommendations"]
        return results

    def _analyze_results(self, results: dict) -> list:
        findings = []
        if results["found"]:
            findings.append(f"Found {len(results['found'])} accessible paths")
        if results["sensitive"]:
            findings.append(f"Sensitive data exposed in {len(results['sensitive'])} locations")
            for s in results["sensitive"]:
                findings.append(f"  - {s}")
        if results["tech"]:
            findings.append(f"Technologies detected: {', '.join(results['tech'])}")
        status_counts = {}
        for r in results["found"]:
            s = r["status"]
            status_counts[s] = status_counts.get(s, 0) + 1
        if 200 in status_counts:
            findings.append(f"{status_counts[200]} paths return 200 OK")
        if 301 in status_counts or 302 in status_counts:
            redirect_count = status_counts.get(301, 0) + status_counts.get(302, 0)
            findings.append(f"{redirect_count} redirects detected")
        if 403 in status_counts:
            findings.append(f"{status_counts[403]} paths forbidden (403) - may exist but access restricted")
        sensitive_paths = [r for r in results["found"] if any(k in r["path"].lower() for k in ["backup", "config", "env", "git", "svn", "log", "debug", "admin", "flag"])]
        if sensitive_paths:
            findings.append(f"Potentially sensitive paths found: {len(sensitive_paths)}")
            for sp in sensitive_paths[:5]:
                findings.append(f"  - {sp['path']} ({sp['status']})")
        return findings

    def _calculate_risk(self, results: dict) -> str:
        score = 0
        if results["sensitive"]:
            score += 40
        if any(r["path"] in ["flag", "flag.txt", "flag.php", ".env", ".git/config"] for r in results["found"]):
            score += 30
        if any("admin" in r["path"].lower() for r in results["found"]):
            score += 15
        if any("backup" in r["path"].lower() for r in results["found"]):
            score += 15
        if len(results["found"]) > 20:
            score += 10
        if score >= 70:
            return "CRITICAL"
        if score >= 40:
            return "HIGH"
        if score >= 20:
            return "MEDIUM"
        return "LOW"

    def _generate_recommendations(self, results: dict) -> list:
        recs = []
        if results["sensitive"]:
            recs.append("Remove or restrict access to sensitive files (backup, config, env)")
        if any(r["path"] in [".git", ".git/config", ".git/HEAD"] for r in results["found"]):
            recs.append("CRITICAL: .git directory exposed - attacker can recover full source code")
        if any(r["path"] in [".env", ".env.local"] for r in results["found"]):
            recs.append("CRITICAL: .env file exposed - contains secrets and credentials")
        if any("admin" in r["path"].lower() for r in results["found"]):
            recs.append("Admin interface found - ensure strong authentication and IP restrictions")
        if any(r["path"] in ["robots.txt"] for r in results["found"]):
            recs.append("robots.txt may reveal hidden paths - review disallowed entries")
        if not results["found"]:
            recs.append("No paths found with current wordlist - try a more comprehensive wordlist")
        if any("backup" in r["path"].lower() for r in results["found"]):
            recs.append("Backup files found - remove from production environment")
        return recs

    def scan_custom(self, paths: list) -> list:
        console.print(Panel("[bold cyan]Custom Path Scanner[/bold cyan]", border_style="cyan"))
        results = []
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("  Scanning...", total=len(paths))
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._check_path, path): path for path in paths}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
                        self.found.append(result)
                        console.print(f"    [green]+[/green] {result['status']} {result['url']} ({result['size']} bytes)")
                    progress.update(task, advance=1)
        return results

    def print_results(self, results: dict):
        risk_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
        risk_color = risk_colors.get(results["risk_level"], "white")

        table = Table(title="Directory Brute-Force Results", border_style="cyan")
        table.add_column("Property", style="bold")
        table.add_column("Value")
        table.add_row("URL", results["url"])
        table.add_row("Paths Found", str(len(results["found"])))
        table.add_row("Sensitive Data", str(len(results["sensitive"])))
        table.add_row("Technologies", ", ".join(results["tech"]) or "Unknown")
        table.add_row("Risk Level", f"[{risk_color}]{results['risk_level']}[/{risk_color}]")
        table.add_row("Confidence", f"{results['confidence']}%")
        console.print(table)

        if results["found"]:
            found_table = Table(title="Found Paths", border_style="cyan")
            found_table.add_column("URL", style="cyan")
            found_table.add_column("Status", style="bold")
            found_table.add_column("Size")
            found_table.add_column("Sensitive")
            for r in sorted(results["found"], key=lambda x: x["status"])[:30]:
                sensitive = ", ".join(r.get("sensitive_patterns", [])) or "-"
                found_table.add_row(r["url"], str(r["status"]), f"{r['size']} bytes", sensitive)
            console.print(found_table)

        if results["findings"]:
            console.print("\n[bold]Findings:[/bold]")
            for f in results["findings"]:
                console.print(f"  [cyan]->[/cyan] {f}")

        if results["recommendations"]:
            console.print("\n[bold]Recommendations:[/bold]")
            for i, r in enumerate(results["recommendations"], 1):
                console.print(f"  {i}. {r}")
