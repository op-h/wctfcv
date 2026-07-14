import os
import re
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
    TAKEOVER_SIGNATURES = {
        "GitHub Pages": ["There isn't a GitHub Pages site here."],
        "Heroku": ["No such app"],
        "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
        "Azure": ["Azure Web App - Your web app is running and waiting for your content"],
        "Shopify": ["Sorry, this shop is currently unavailable."],
        "Fastly": ["Fastly error: unknown domain"],
        "Pantheon": ["404 error unknown site"],
        "Tumblr": ["Whatever you were looking for doesn't currently exist at this address"],
        "WordPress.com": ["Do you want to register"],
        "Zendesk": ["Help Center Closed"],
        "Surge.sh": ["project not found"],
        "Intercom": ["This page is reserved for artistic dogs"],
        "Webflow": ["The link you followed might be broken"],
        "Kajabi": ["The page you were looking for doesn't exist"],
        "Thinkific": ["You may have typed the address incorrectly"],
        "Tave": ["<h1>Error</h1>"],
        "Helpjuice": ["We could not find what you're looking for."],
        "Helpscout": ["No settings were found for this company:"],
        "Cargo": ["If you're moving your domain away from Cargo you must make this configuration change"],
        "Statuspage": ["Better StatusPage"],
        "UserVoice": ["This UserVoice subdomain is currently available!"],
        "Intercom": ["This page is reserved for artistic dogs"],
        "Ngrok": ["Tunnel *.ngrok.io not found"],
        "Ngrok": ["ngrok.com/dns-others"],
    }

    def __init__(self, domain: str, threads: int = 20, timeout: int = 5, wordlist: Optional[str] = None):
        self.domain = domain.lower().strip()
        self.threads = threads
        self.timeout = timeout
        self.wordlist = wordlist
        self.found = []
        self.findings = []
        self.risk_level = "LOW"
        self.recommendations = []

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

    def _check_takeover(self, subdomain: str, url: str) -> Optional[str]:
        try:
            resp = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            for service, signatures in self.TAKEOVER_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in resp.text.lower():
                        return service
        except requests.RequestException:
            pass
        return None

    def _check_subdomain_http(self, subdomain: str) -> Optional[dict]:
        fqdn = f"{subdomain}.{self.domain}"
        result = self._check_subdomain(subdomain)
        if result:
            result["takeover"] = None
            result["status"] = "DNS-only"
            result["title"] = ""
            result["url"] = f"http://{fqdn}"
            result["server"] = ""
            result["technologies"] = []
            for scheme in ["https", "http"]:
                try:
                    url = f"{scheme}://{fqdn}"
                    resp = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                    result["status"] = resp.status_code
                    result["title"] = self._extract_title(resp.text)
                    result["url"] = url
                    result["server"] = resp.headers.get("Server", "")
                    result["technologies"] = self._detect_tech(resp)
                    takeover = self._check_takeover(subdomain, url)
                    if takeover:
                        result["takeover"] = takeover
                    break
                except requests.RequestException:
                    continue
        return result

    def _extract_title(self, html: str) -> str:
        match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def _detect_tech(self, response: requests.Response) -> list:
        techs = []
        headers = response.headers
        body = response.text[:5000].lower()
        server = headers.get("Server", "")
        if server:
            techs.append(f"Server: {server}")
        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            techs.append(f"Framework: {powered_by}")
        tech_signs = {
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Drupal": ["drupal", "sites/default/files"],
            "Joomla": ["joomla", "/components/"],
            "Laravel": ["laravel", "laravel_session"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "Spring": ["JSESSIONID", "spring"],
            "ASP.NET": ["__VIEWSTATE", "aspxerrorpath"],
            "PHP": [".php", "PHPSESSID"],
            "Node.js": ["express", "X-Powered-By: Express"],
        }
        for tech, signs in tech_signs.items():
            for sign in signs:
                if sign.lower() in body:
                    techs.append(tech)
                    break
        return techs

    def enumerate(self, http_check: bool = True) -> dict:
        console.print(Panel("[bold cyan]Subdomain Enumeration[/bold cyan]", border_style="cyan"))
        words = self._load_wordlist()
        console.print(f"  [yellow]Domain:[/yellow] {self.domain}")
        console.print(f"  [yellow]Wordlist:[/yellow] {len(words)} subdomains")
        console.print(f"  [yellow]Threads:[/yellow] {self.threads}")

        results = {"domain": self.domain, "found": [], "takeover": [], "tech": set(), "findings": [], "risk_level": "LOW", "confidence": 0, "recommendations": []}
        check_fn = self._check_subdomain_http if http_check else self._check_subdomain

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("  Enumerating...", total=len(words))
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(check_fn, word): word for word in words}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results["found"].append(result)
                        self.found.append(result)
                        if result.get("takeover"):
                            results["takeover"].append(result)
                            console.print(f"    [bold red]TAKEOVER![/bold red] {result['subdomain']} -> {result['takeover']}")
                        elif result.get("technologies"):
                            results["tech"].update(result["technologies"])
                            console.print(f"    [green]+[/green] {result['subdomain']} -> {result['ip']} [{result.get('status', 'DNS')}] {result.get('title', '')[:40]}")
                        else:
                            console.print(f"    [green]+[/green] {result['subdomain']} -> {result['ip']}")
                    progress.update(task, advance=1)

        results["tech"] = list(results["tech"])
        results["findings"] = self._analyze_results(results)
        results["risk_level"] = self._calculate_risk(results)
        results["confidence"] = 80 if results["found"] else 30
        results["recommendations"] = self._generate_recommendations(results)

        self.findings = results["findings"]
        self.risk_level = results["risk_level"]
        self.recommendations = results["recommendations"]
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

    def _analyze_results(self, results: dict) -> list:
        findings = []
        if results["found"]:
            findings.append(f"Found {len(results['found'])} subdomains")
        if results["takeover"]:
            findings.append(f"CRITICAL: {len(results['takeover'])} subdomain takeover opportunities!")
            for t in results["takeover"]:
                findings.append(f"  - {t['subdomain']} ({t['takeover']})")
        if results["tech"]:
            findings.append(f"Technologies detected: {', '.join(results['tech'][:5])}")
        wildcard = [r for r in results["found"] if r["ip"] == results["found"][0].get("ip") and len(results["found"]) > 5]
        if wildcard:
            findings.append("Possible wildcard DNS record detected")
        return findings

    def _calculate_risk(self, results: dict) -> str:
        score = 0
        if results["takeover"]:
            score += 50
        if len(results["found"]) > 20:
            score += 15
        if any("admin" in r.get("subdomain", "").lower() for r in results["found"]):
            score += 10
        if any("dev" in r.get("subdomain", "").lower() or "test" in r.get("subdomain", "").lower() for r in results["found"]):
            score += 10
        if any("staging" in r.get("subdomain", "").lower() for r in results["found"]):
            score += 10
        if score >= 50:
            return "CRITICAL"
        if score >= 30:
            return "HIGH"
        if score >= 15:
            return "MEDIUM"
        return "LOW"

    def _generate_recommendations(self, results: dict) -> list:
        recs = []
        if results["takeover"]:
            recs.append("CRITICAL: Subdomain takeover possible - claim these subdomains or remove DNS records")
        if len(results["found"]) > 20:
            recs.append("Large attack surface - review and remove unnecessary subdomains")
        if any("dev" in r.get("subdomain", "").lower() for r in results["found"]):
            recs.append("Development subdomains found - ensure they are not publicly accessible")
        if any("staging" in r.get("subdomain", "").lower() for r in results["found"]):
            recs.append("Staging subdomains found - restrict access to internal network")
        if any("test" in r.get("subdomain", "").lower() for r in results["found"]):
            recs.append("Test subdomains found - remove or restrict access")
        if not results["found"]:
            recs.append("No subdomains found - domain may use different naming convention")
        return recs

    def print_results(self, results: dict):
        risk_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
        risk_color = risk_colors.get(results["risk_level"], "white")

        table = Table(title="Subdomain Enumeration Results", border_style="cyan")
        table.add_column("Property", style="bold")
        table.add_column("Value")
        table.add_row("Domain", results["domain"])
        table.add_row("Subdomains Found", str(len(results["found"])))
        table.add_row("Takeover Opportunities", str(len(results["takeover"])))
        table.add_row("Technologies", ", ".join(results["tech"][:5]) or "Unknown")
        table.add_row("Risk Level", f"[{risk_color}]{results['risk_level']}[/{risk_color}]")
        table.add_row("Confidence", f"{results['confidence']}%")
        console.print(table)

        if results["found"]:
            sub_table = Table(title="Found Subdomains", border_style="cyan")
            sub_table.add_column("Subdomain", style="cyan")
            sub_table.add_column("IP", style="bold")
            sub_table.add_column("Status")
            sub_table.add_column("Title")
            sub_table.add_column("Tech")
            sub_table.add_column("Takeover")
            for r in sorted(results["found"], key=lambda x: x["subdomain"]):
                sub_table.add_row(
                    r["subdomain"], r["ip"],
                    str(r.get("status", "DNS")),
                    (r.get("title", "") or "-")[:30],
                    ", ".join(r.get("technologies", [])[:2]) or "-",
                    r.get("takeover") or "-",
                )
            console.print(sub_table)

        if results["findings"]:
            console.print("\n[bold]Findings:[/bold]")
            for f in results["findings"]:
                console.print(f"  [cyan]->[/cyan] {f}")

        if results["recommendations"]:
            console.print("\n[bold]Recommendations:[/bold]")
            for i, r in enumerate(results["recommendations"], 1):
                console.print(f"  {i}. {r}")
