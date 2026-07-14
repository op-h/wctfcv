import os
import socket
import requests
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel

console = Console()


class SubdomainEnumerator:
    def __init__(self, domain: str, threads: int = 20, timeout: int = 5, wordlist: Optional[str] = None):
        self.domain = domain.lower().strip()
        self.threads = threads
        self.timeout = timeout
        self.wordlist = wordlist
        self.found = []

    def _load_wordlist(self) -> list:
        words = []
        default_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", "subdomains.txt")
        list_path = self.wordlist or default_path
        try:
            with open(list_path, "r") as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            console.print(f"[red]Wordlist not found: {list_path}[/red]")
            words = ["www", "mail", "ftp", "api", "dev", "test", "admin", "blog", "shop"]
        return words

    def _check_subdomain(self, subdomain: str) -> Optional[dict]:
        fqdn = f"{subdomain}.{self.domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return {"subdomain": fqdn, "ip": ip}
        except socket.gaierror:
            pass
        return None

    def _check_subdomain_http(self, subdomain: str) -> Optional[dict]:
        fqdn = f"{subdomain}.{self.domain}"
        result = self._check_subdomain(subdomain)
        if result:
            for scheme in ["https", "http"]:
                try:
                    url = f"{scheme}://{fqdn}"
                    resp = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                    result["status"] = resp.status_code
                    result["title"] = self._extract_title(resp.text)
                    result["url"] = url
                    result["server"] = resp.headers.get("Server", "")
                    break
                except requests.RequestException:
                    continue
            if "status" not in result:
                result["status"] = "DNS-only"
                result["title"] = ""
                result["url"] = f"http://{fqdn}"
                result["server"] = ""
        return result

    def _extract_title(self, html: str) -> str:
        import re
        match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def enumerate(self, http_check: bool = True) -> list:
        console.print(Panel("[bold cyan]Subdomain Enumeration[/bold cyan]", border_style="cyan"))
        words = self._load_wordlist()
        console.print(f"  [yellow]Domain:[/yellow] {self.domain}")
        console.print(f"  [yellow]Wordlist:[/yellow] {len(words)} subdomains")
        console.print(f"  [yellow]Threads:[/yellow] {self.threads}")

        results = []
        check_fn = self._check_subdomain_http if http_check else self._check_subdomain

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("  Enumerating...", total=len(words))
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(check_fn, word): word for word in words}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
                        self.found.append(result)
                        status = result.get("status", "DNS")
                        title = result.get("title", "")
                        console.print(f"    [green]+[/green] {result['subdomain']} -> {result['ip']} [{status}] {title[:40]}")
                    progress.update(task, advance=1)

        return results

    def enumerate_crtsh(self) -> list:
        console.print("[cyan]Querying crt.sh for certificate transparency logs...[/cyan]")
        results = []
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = requests.get(url, timeout=30, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                seen = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub and sub.endswith(f".{self.domain}") and sub not in seen:
                            seen.add(sub)
                            try:
                                ip = socket.gethostbyname(sub)
                                results.append({"subdomain": sub, "ip": ip, "source": "crt.sh"})
                                console.print(f"    [green]+[/green] {sub} -> {ip}")
                            except socket.gaierror:
                                pass
        except Exception as e:
            console.print(f"[red]crt.sh query failed: {e}[/red]")
        return results

    def print_results(self, results: list):
        table = Table(title="Subdomain Enumeration Results", border_style="cyan")
        table.add_column("Subdomain", style="cyan")
        table.add_column("IP", style="bold")
        table.add_column("Status")
        table.add_column("Title")
        table.add_column("Server")
        for r in sorted(results, key=lambda x: x["subdomain"]):
            table.add_row(
                r["subdomain"],
                r["ip"],
                str(r.get("status", "DNS")),
                (r.get("title", "") or "-")[:40],
                r.get("server", "") or "-",
            )
        console.print(table)
