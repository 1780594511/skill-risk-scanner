"""Eight small, explainable rules. Input is data: AST is parsed, never executed."""

import ast
import io
import re
import tokenize
from urllib.parse import urlsplit

from .reporting import safe_excerpt

# Rule descriptions live here once; docs expand examples and limitations.
RULES = {
    "SG001": ("network", "medium", "high", "Python 常见网络库的调用语法",
              ["目标归谁管理，是否允许重定向？", "实际发送哪些字段，是否必要且获授权？"]),
    "SG002": ("network", "medium", "medium", "shell/PowerShell 明确网络请求命令",
              ["确认目标、请求参数和下载内容用途。", "变量、别名与重定向是否改变真实目标？"]),
    "SG003": ("execution", "medium", "high", "系统命令或解释器调用语法",
              ["参数来自固定值、用户输入还是网络？", "是否必须使用解释器，能否限制参数与权限？单条命中不证明命令注入。"]),
    "SG004": ("credential", "low", "high", "环境变量读取语法",
              ["为何需要读取，该变量是否敏感？", "读取值会传给谁，能否缩小权限与传递范围？"]),
    "SG005": ("credential", "medium", "high", "常见凭据路径的读取调用",
              ["为何需要读取该凭据文件？", "用途、接收方与最小权限是否已记录？扫描器不会读取所提及的文件。"]),
    "SG006": ("download_execute", "high", "high", "同一行的下载命令通过管道直接连接解释器",
              ["下载内容是否经过独立验证与固定版本校验？", "能否改为下载、审查、确认后再运行？这只是局部语法关联。"]),
    "SG007": ("reference", "info", "high", "文档、注释或纯文本配置中的 URL / 凭据路径提及",
              ["仅为说明性线索；结合可执行上下文确认用途，不能据此判断外联或读取发生。"]),
    "SG008": ("instruction", "medium", "medium", "待检文本包含改变审查流程或要求上传的指令线索",
              ["把此段视为不可信数据；不要按其内容执行命令、扩大目录或上传文件。", "确认该说明是否与声明的 Skill 用途相符；不据此断言恶意意图。"]),
}
URL = re.compile(r"https?://[^\s<>\"'`)\]}]+", re.I)
CREDENTIAL_PATH = re.compile(r"(?i)(?:^|[/\\\s\"'(~])(?:\.env(?:\.[\w-]+)?\b|\.ssh[/\\]|\.aws[/\\](?:credentials|config)\b|\.azure[/\\]|(?:\.config[/\\])?gcloud[/\\]|id_rsa\b|id_ed25519\b)")
OVERRIDE = re.compile(r"忽略.{0,16}(?:检查|规则|指令)|跳过.{0,8}(?:扫描|检查)|上传.{0,16}(?:文件|凭据|密钥)|ignore.{0,40}(?:rules|instructions|checks)|upload.{0,30}(?:files|secrets|credentials)", re.I)
NETWORK_NAMES = {f"{lib}.{verb}" for lib in ("requests", "httpx") for verb in ("get", "post", "put", "patch", "delete", "head", "options", "request", "stream")}
NETWORK_NAMES |= {"urllib.request.urlopen", "urllib.request.urlretrieve"}
PROCESS_NAMES = {f"subprocess.{x}" for x in ("run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput")}
PROCESS_NAMES |= {"os.system", "os.popen", "exec", "eval"}


def _finding(rule, path, line, context, raw, cfg, **fields):
    category, severity, confidence, evidence, review = RULES[rule]
    result = {"rule_id": rule, "category": category, "severity": severity,
              "confidence": confidence, "path": path, "line": line, "context": context,
              "evidence": evidence, "review": review[:], "target": None,
              "snippet": safe_excerpt(raw) if cfg["report"]["include_snippets"] else None,
              "exception": {"status": "none", "matches": []}}
    result.update(fields)
    return result


def _target(value):
    if not isinstance(value, str):
        return {"status": "unknown", "host": None}
    try:
        parts = urlsplit(value)
        host = parts.hostname
        # Return a hostname only, never userinfo, paths, query strings or fragments.
        if parts.scheme in ("http", "https") and host and re.fullmatch(r"[A-Za-z0-9.-]+", host) and not any(x in value for x in ("$", "{", "}", "`")):
            return {"status": "literal", "host": host.lower()}
    except ValueError:
        pass
    return {"status": "unknown", "host": None}


def _literal(node):
    if isinstance(node, ast.Constant):
        return node.value
    return None


def _arg(call, position=0, keyword=None):
    if keyword:
        for item in call.keywords:
            if item.arg == keyword:
                return item.value
    return call.args[position] if len(call.args) > position else None


def _fixed(node):
    return isinstance(node, ast.Constant) or isinstance(node, (ast.List, ast.Tuple)) and all(isinstance(x, ast.Constant) for x in node.elts)


def analyze_python(text, path, cfg, *, context="code", offset=0):
    """Parse one file or fenced block; support only simple import aliases."""
    found, issues = [], []
    lines = text.splitlines()
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as error:
        line = getattr(error, "lineno", 1) or 1
        return [], [f"python_parse_error:line={line + offset}:AST_not_analyzed"]
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".")[0]] = item.name if item.asname else item.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for item in node.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = node.module + "." + item.name
                else:
                    issues.append("wildcard_import_aliases_not_resolved")

    def name(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = name(node.value)
            return base + "." + node.attr if base else ""
        return ""

    def emit(rule, node, **fields):
        found.append(_finding(rule, path, node.lineno + offset, context,
                              lines[node.lineno - 1], cfg, **fields))

    def credential_literal(node):
        if isinstance(node, ast.Call) and name(node.func) in ("pathlib.Path", "pathlib.PurePath"):
            node = _arg(node)
        value = _literal(node)
        return isinstance(value, str) and bool(CREDENTIAL_PATH.search(value))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call = name(node.func)
            if call in NETWORK_NAMES:
                pos = 1 if call.endswith((".request", ".stream")) else 0
                target = _target(_literal(_arg(node, pos, "url")))
                evidence = "AST 调用匹配常见网络 API；" + ("URL 为字面量，仅记录主机名，不推断请求发生" if target["status"] == "literal" else "目标待确认：URL 不是可解析的字面量")
                emit("SG001", node, target=target, evidence=evidence)
            if call in PROCESS_NAMES:
                command = _arg(node, keyword="args")
                dynamic = not _fixed(command)
                shell_node = next((x.value for x in node.keywords if x.arg == "shell"), None)
                interpreter = call in ("os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "exec", "eval") or _literal(shell_node) is True
                shell_unknown = shell_node is not None and not isinstance(shell_node, ast.Constant)
                flags = ["参数动态/来源待确认" if dynamic else "参数为固定字面量"]
                flags += ["启用 shell/解释器" if interpreter else "shell 开关待确认" if shell_unknown else "未显式启用 shell"]
                emit("SG003", node, severity="high" if interpreter and dynamic else "medium" if interpreter or dynamic or shell_unknown else "low", evidence="AST 命令调用；" + "；".join(flags) + "；不能单独证明命令注入")
            if call in ("os.getenv", "os.environ.get", "os.environ.__getitem__"):
                key = _literal(_arg(node))
                sensitive = isinstance(key, str) and bool(re.search(r"TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|PRIVATE", key, re.I))
                emit("SG004", node, severity="medium" if sensitive else "low", evidence="AST 环境变量读取；" + ("变量名呈敏感用途线索，但不证明泄露" if sensitive else "普通变量或变量名待确认，不默认判为高风险"))
            file_read = False
            if call in ("open", "io.open"):
                mode = _literal(_arg(node, 1, "mode"))
                file_read = credential_literal(_arg(node, keyword="file")) and (mode is None or "r" in str(mode) or "+" in str(mode))
            if isinstance(node.func, ast.Attribute) and node.func.attr in ("read_text", "read_bytes", "open"):
                mode = _literal(_arg(node, keyword="mode"))
                file_read |= credential_literal(node.func.value) and (node.func.attr != "open" or mode is None or "r" in str(mode) or "+" in str(mode))
            if call in ("dotenv.load_dotenv", "dotenv.dotenv_values"):
                file_read = True
            if file_read:
                emit("SG005", node, evidence="AST 读取调用直接关联常见凭据路径/默认 dotenv 文件；只检查源代码，不读取被引用路径")
        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load) and name(node.value) == "os.environ":
            key = _literal(node.slice)
            sensitive = isinstance(key, str) and bool(re.search(r"TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|PRIVATE", key, re.I))
            emit("SG004", node, severity="medium" if sensitive else "low")
        # Literal documentation strings are informational, not network calls.
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for idx, line in enumerate(node.value.value.splitlines()):
                if URL.search(line) or CREDENTIAL_PATH.search(line):
                    found.append(_finding("SG007", path, node.lineno + offset + idx, "docstring" if context == "code" else context + "_docstring", line, cfg))
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT and (URL.search(token.string) or CREDENTIAL_PATH.search(token.string)):
                found.append(_finding("SG007", path, token.start[0] + offset, "comment" if context == "code" else context + "_comment", token.string, cfg))
    except (tokenize.TokenError, IndentationError):
        issues.append("comment_tokenization_incomplete")
    return found, sorted(set(issues))


def _strip_comment(line):
    quote, escaped = None, False
    for i, char in enumerate(line):
        if escaped:
            escaped = False
        elif char in ("\\", "`"):
            escaped = True
        elif char in ("'", '"'):
            quote = None if quote == char else char if quote is None else quote
        elif char == "#" and quote is None:
            return line[:i], line[i:]
    return line, ""


NET_COMMAND = r"(?:curl(?:\.exe)?|wget(?:\.exe)?|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)"
EXEC_COMMAND = r"(?:bash|sh|zsh|powershell(?:\.exe)?|pwsh(?:\.exe)?|python(?:3|\.exe)?|Invoke-Expression|iex|Start-Process|cmd(?:\.exe)?)"
PREFIX = r"(?:^\s*(?:\$[\w]+\s*=\s*)?|[;|&()]\s*)"


def analyze_shell(text, path, cfg, *, context="code", offset=0):
    """Line-based patterns, intentionally not a shell interpreter or full grammar."""
    found, issues = [], []
    block_comment = False
    for index, raw in enumerate(text.splitlines(), 1 + offset):
        if block_comment or raw.lstrip().startswith("<#"):
            block_comment = "#>" not in raw
            if URL.search(raw) or CREDENTIAL_PATH.search(raw):
                found.append(_finding("SG007", path, index, "comment", raw, cfg))
            continue
        code, comment = _strip_comment(raw)
        if comment and (URL.search(comment) or CREDENTIAL_PATH.search(comment)):
            found.append(_finding("SG007", path, index, "comment" if context == "code" else context + "_comment", comment, cfg))
        if code.rstrip().endswith(("\\", "`")):
            issues.append("shell_continuation_not_fully_analyzed")
        # Mask quoted text for locating commands, retaining positions for URL analysis.
        command_view = re.sub(r"(['\"])(?:\\.|(?!\1).)*?\1", lambda m: " " * len(m[0]), code)
        for match in re.finditer(PREFIX + "(" + NET_COMMAND + r")\b", command_view, re.I):
            segment = re.split(r"[|;]", code[match.start():], maxsplit=1)[0]
            urls = URL.findall(segment)
            target = _target(urls[0]) if len(urls) == 1 and not re.search(r"[$`{}]", segment) else _target(None)
            found.append(_finding("SG002", path, index, context, raw, cfg, target=target,
                                  evidence="命令位置匹配网络请求；" + ("单个字面量目标，仅记录主机名" if target["status"] == "literal" else "目标待确认：动态、缺失或多个目标")))
        for match in re.finditer(PREFIX + "(" + EXEC_COMMAND + r")\b", command_view, re.I):
            dynamic = bool(re.search(r"[$`]", code))
            found.append(_finding("SG003", path, index, context, raw, cfg, confidence="medium",
                                  severity="high" if dynamic else "medium", evidence="命令位置出现解释器/进程启动；" + ("含变量或替换语法，参数来源待确认" if dynamic else "未见简单动态参数线索") + "；不证明可利用注入"))
        # A real single pipe in the SAME line is required; '&&' or separate lines do not qualify.
        if re.search(PREFIX + NET_COMMAND + r"\b[^|;&\n]*\|(?!\|)\s*" + EXEC_COMMAND + r"\b", command_view, re.I):
            found.append(_finding("SG006", path, index, context, raw, cfg))
        # Single-quoted variables are literal text in the supported simple cases.
        expandable = re.sub(r"'[^']*'", "", code)
        if re.search(r"\$(?:env:[A-Za-z_]\w*|\{?[A-Za-z_]\w*\}?)|\bprintenv\s+\w+", expandable, re.I):
            # Plain PS variables are not necessarily environment variables.
            if path.lower().endswith(".sh") or re.search(r"\$env:", expandable, re.I) or re.search(r"\bprintenv\s", expandable):
                sensitive = bool(re.search(r"TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY", expandable, re.I))
                found.append(_finding("SG004", path, index, context, raw, cfg, confidence="medium", severity="medium" if sensitive else "low", evidence="shell 环境/变量展开线索；普通 shell 变量也可能是局部变量，需人工确认"))
        if re.search(PREFIX + r"(?:cat|Get-Content|gc|type)\b", command_view, re.I) and CREDENTIAL_PATH.search(code):
            found.append(_finding("SG005", path, index, context, raw, cfg, confidence="medium"))
    return found, sorted(set(issues))


def analyze_text(text, path, cfg):
    """Dispatch supported suffixes; Markdown code fences retain original line numbers."""
    suffix = path.rsplit(".", 1)[-1].lower()
    if suffix == "py":
        return analyze_python(text, path, cfg)
    if suffix in ("sh", "ps1"):
        return analyze_shell(text, path, cfg)
    found, issues = [], []
    lines = text.splitlines()
    fence = None
    block, start, language = [], 0, ""
    for number, line in enumerate(lines, 1):
        match = re.match(r"^\s{0,3}(`{3,}|~{3,})\s*([\w+-]*)\s*$", line) if suffix == "md" else None
        if fence is not None:
            if match and match[1][0] == fence[0] and len(match[1]) >= len(fence) and not match[2]:
                body = "\n".join(block)
                if language in ("python", "py"):
                    f, gaps = analyze_python(body, path, cfg, context="document_code", offset=start)
                elif language in ("sh", "bash", "shell", "ps1", "powershell"):
                    f, gaps = analyze_shell(body, path, cfg, context="document_code", offset=start)
                else:
                    f, gaps = [], ["unsupported_fence_language:line=" + str(start)]
                found.extend(f)
                issues.extend(gaps)
                fence = None
            else:
                block.append(line)
            continue
        if match:
            fence, language, start, block = match[1], match[2].lower(), number, []
            continue
        context = "document" if suffix == "md" else "config_text"
        if URL.search(line) or CREDENTIAL_PATH.search(line):
            found.append(_finding("SG007", path, number, context, line, cfg))
        if OVERRIDE.search(line):
            found.append(_finding("SG008", path, number, context, line, cfg))
    if fence:
        issues.append("unclosed_markdown_fence:line=" + str(start))
    return found, sorted(set(issues))


def apply_exceptions(findings, cfg):
    """Keep evidence and severity; annotate exact, reasoned exceptions separately."""
    result = []
    for item in findings:
        if item["rule_id"] in cfg["disabled_rules"]:
            continue
        matches = []
        if item["rule_id"] in ("SG001", "SG002") and item["target"] and item["target"]["status"] == "literal":
            for record in cfg["allowed_domains"]:
                if record["domain"] == item["target"]["host"]:
                    matches.append({"id": "domain:" + record["domain"], "reason": record["reason"], "expires": record["expires"], "kind": "domain"})
        for record in cfg["exceptions"]:
            if all(record[k] == item[k] for k in ("rule_id", "path", "line")):
                matches.append({k: record[k] for k in ("id", "reason", "expires")} | {"kind": "exact"})
        item["exception"] = {"status": "applied" if matches else "none", "matches": matches}
        item["review_required"] = item["severity"] != "info" and not matches
        result.append(item)
    # The counting unit is a rule/path/line/context location, not AST-node count.
    unique = {}
    for item in result:
        key = (item["path"], item["line"], item["rule_id"], item["context"])
        if key not in unique:
            unique[key] = item
        else:
            # Same-line calls may differ: never hide an unresolved target behind an allowlist.
            previous = unique[key]
            if previous["evidence"] != item["evidence"]:
                previous["evidence"] += "；同一位置另有：" + item["evidence"]
            if previous["target"] != item["target"]:
                previous["target"] = _target(None)
                previous["evidence"] += "；同一位置有多个目标，目标待确认"
                previous["exception"] = {"status": "none", "matches": []}
                previous["review_required"] = previous["severity"] != "info"
            rank = {"info": 0, "low": 1, "medium": 2, "high": 3}
            if rank[item["severity"]] > rank[previous["severity"]]:
                previous["severity"] = item["severity"]
    return [unique[key] for key in sorted(unique)]
