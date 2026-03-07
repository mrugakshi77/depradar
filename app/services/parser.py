import re
from typing import List, Tuple, Optional

_COMMENT_RE = re.compile(r"\s*#.*$")
_VERSION_SPEC_RE = re.compile(r"^([A-Za-z0-9_.\-]+(?:\[[A-Za-z0-9_,\s]+\])?)\s*([><=!~^,\s0-9.*]+)?")
_SKIP_PREFIXES = ("-r", "-c", "-e", "--", "git+", "http://", "https://")


def parse_requirements(content: str) -> List[Tuple[str, Optional[str]]]:
    """
    Parse a requirements.txt string.
    Returns list of (package_name, pinned_version_or_None).
    pinned_version is only set for exact ==X.Y.Z pins.
    Strips extras: requests[security]==2.31.0 → ('requests', '2.31.0')
    """
    results = []
    for raw_line in content.splitlines():
        line = _COMMENT_RE.sub("", raw_line).strip()
        if not line:
            continue
        if any(line.startswith(p) for p in _SKIP_PREFIXES):
            continue
        m = _VERSION_SPEC_RE.match(line)
        if not m:
            continue
        name_raw = m.group(1).strip()
        # Strip extras e.g. requests[security] → requests
        name = re.sub(r"\[.*?\]", "", name_raw).strip()
        spec = (m.group(2) or "").strip()
        pinned = None
        if spec:
            exact = re.match(r"^==\s*([^\s,]+)$", spec)
            if exact:
                pinned = exact.group(1).strip()
        if name:
            results.append((name, pinned))
    return results
