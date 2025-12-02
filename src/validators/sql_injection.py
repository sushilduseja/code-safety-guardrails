import re
from typing import Any, Dict, List

SQL_DANGEROUS_PATTERN = re.compile(
    r"(DROP|DELETE|TRUNCATE|INSERT|UPDATE)\s+.+WHERE.+=.+",
    re.IGNORECASE | re.DOTALL,
)

SQL_STRING_CONCAT_PATTERN = re.compile(
    r"SELECT.+[\"']\s*\+\s*\w+\s*\+\s*[\"']",
    re.IGNORECASE | re.DOTALL,
)

SQL_FSTRING_PATTERN = re.compile(
    r"f\"\s*SELECT.+FROM.+\"|f'\s*SELECT.+FROM.+'",
    re.IGNORECASE | re.DOTALL,
)


def validate_sql_injection(code: str) -> Dict[str, Any]:
    """Detect basic SQL injection-prone patterns.

    Returns a dict with `passed` and `issues` list.
    """

    issues: List[str] = []

    if SQL_DANGEROUS_PATTERN.search(code):
        issues.append("Potentially dangerous SQL modification with WHERE clause.")

    if SQL_STRING_CONCAT_PATTERN.search(code):
        issues.append("SQL query appears to use string concatenation.")

    if SQL_FSTRING_PATTERN.search(code):
        issues.append("SQL query appears to be constructed via f-string.")

    return {"passed": len(issues) == 0, "issues": issues}
