import re
from collections.abc import Iterable

from argo.extract.archive import PackageFiles
from argo.extract.profile import is_binary
from argo.schema import Hit

CATEGORY_ORDER: tuple[str, ...] = (
    "runtime_download",
    "propagation",
    "credentials",
    "exec",
    "obfuscation",
    "network",
)
_ALLOWED_HOSTS = (
    r"(?:registry\.npmjs\.org|registry\.yarnpkg\.com|(?:www\.)?npmjs\.(?:com|org)|github\.com"
    r"|nodejs\.org|(?:www\.)?w3\.org|json-schema\.org|localhost|127\.0\.0\.1|example\.(?:com|org))"
)
PATTERNS: dict[str, re.Pattern[str]] = {
    "runtime_download": re.compile(
        r"bun\.sh/install|oven-sh/bun|curl\s[^\n|]{0,200}\|\s*(?:ba)?sh|wget\s+https?://"
        r"|Invoke-WebRequest|\bbun\s+run\b"
    ),
    "propagation": re.compile(
        r"npm\s+publish|api\.github\.com|\.github/workflows|npm\s+(?:whoami|token)\b"
        r"|/-/whoami|/-/npm/v1/tokens"
    ),
    "credentials": re.compile(
        r"process\.env(?!\.NODE_ENV\b)|\.npmrc|NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_ACCESS_KEY_ID"
        r"|AWS_SECRET_ACCESS_KEY|\.ssh/|id_rsa|trufflehog|\.aws/credentials|/etc/passwd"
    ),
    "exec": re.compile(
        r"child_process|\bexecSync\b|\bspawnSync?\(|\beval\(|new\s+Function\(|vm\.runIn"
    ),
    "obfuscation": re.compile(
        r"String\.fromCharCode|\batob\(|Buffer\.from\([^)]{0,200}base64|(?:\\x[0-9a-fA-F]{2}){16,}"
    ),
    "network": re.compile(
        rf"https?://(?!{_ALLOWED_HOSTS}\b)[\w-]+(?:\.[\w-]+)+|\bfetch\(|\bhttps?\.(?:request|get)\("
        r"|XMLHttpRequest|\bnet\.connect\(|\bdns\.resolve|webhook\.site"
        r"|discord(?:app)?\.com/api/webhooks|\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b"
    ),
}
HEX_ID = re.compile(r"_0x[0-9a-fA-F]{4,}")
MAX_SCAN_CHARS = 5_000_000
MAX_HITS_PER_CATEGORY = 3
CODE_EXTENSIONS = (
    ".js",
    ".cjs",
    ".mjs",
    ".jsx",
    ".ts",
    ".tsx",
    ".sh",
    ".py",
    ".ps1",
    ".bat",
    ".cmd",
)
_TYPE_DECLARATIONS = (".d.ts", ".d.cts", ".d.mts")


def is_code(path: str) -> bool:
    low = path.lower()
    return low.endswith(CODE_EXTENSIONS) and not low.endswith(_TYPE_DECLARATIONS)


def _snippet(text: str, start: int, end: int) -> str:
    return " ".join(text[max(0, start - 60) : end + 60].split())[:200]


def scan_text(path: str, text: str) -> list[Hit]:
    text = text[:MAX_SCAN_CHARS]
    hits: list[Hit] = []
    for category in CATEGORY_ORDER:
        for i, m in enumerate(PATTERNS[category].finditer(text)):
            if i >= MAX_HITS_PER_CATEGORY:
                break
            hits.append(
                Hit(
                    category=category,
                    path=path,
                    line=text.count("\n", 0, m.start()) + 1,
                    snippet=_snippet(text, m.start(), m.end()),
                )
            )
    n_hex = len(HEX_ID.findall(text))
    if n_hex >= 20:
        hits.append(
            Hit(
                category="obfuscation",
                path=path,
                line=1,
                snippet=f"{n_hex} obfuscator-style identifiers (_0x...)",
            )
        )
    return hits


def scan_package(pkg: PackageFiles, paths: Iterable[str]) -> list[Hit]:
    hits: list[Hit] = []
    for p in paths:
        data = pkg.files.get(p)
        if data is not None and is_code(p) and not is_binary(data):
            hits += scan_text(p, pkg.text(p))
    return hits
