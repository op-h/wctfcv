import os
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
    COMMON_EXTENSIONS = ["", ".php", ".html", ".txt", ".js", ".json", ".xml", ".asp", ".aspx", ".jsp", ".py", ".rb"]

    def __init__(self, url: str, wordlist: Optional[str] = None, extensions: Optional[list] = None, threads: int = 10, timeout: int = 10, headers: Optional[dict] = None, cookies: Optional[dict] = None):
        self.url = url.rstrip("/")
        self.wordlist = wordlist
        self.extensions = extensions or self.COMMON_EXTENSIONS
        self.threads = threads
        self.timeout = timeout
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.found = []

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
                url,
                headers=self.headers,
                cookies=self.cookies,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
            )
            if resp.status_code not in [404, 403, 500, 502, 503, 504]:
                return {
                    "url": url,
                    "status": resp.status_code,
                    "size": len(resp.text),
                    "redirect": resp.headers.get("Location", ""),
                }
        except requests.RequestException:
            pass
        return None

    def scan(self) -> list:
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

        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("  Bruting...", total=len(paths))
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

    def scan_custom(self, paths: list) -> list:
        console.print(Panel("[bold cyan]Custom Path Scanner[/bold cyan]", border_style="cyan"))
        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
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

    def print_results(self, results: list):
        table = Table(title="Directory Brute-Force Results", border_style="cyan")
        table.add_column("URL", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Size")
        table.add_column("Redirect")
        for r in sorted(results, key=lambda x: x["status"]):
            table.add_row(
                r["url"],
                str(r["status"]),
                f"{r['size']} bytes",
                r["redirect"] or "-",
            )
        console.print(table)
