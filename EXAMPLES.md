# Code Safety Guardrails - Real-World Examples

This guide shows practical usage patterns and demonstrates how each validator works.

Note: the API currently accepts Python requests only. Examples for other languages are illustrative, not part of the supported API contract.

## 1. Safe Code Generation

### Example 1a: Python Function (Basic)
```bash
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Write a Python function to calculate the sum of a list of numbers",
    "language": "python"
  }'
```

**Expected Response:**
```json
{
  "code": "def sum_list(numbers):\n    return sum(numbers)",
  "passed": true,
  "issues": []
}
```

**Validators Report:** All pass
- SQL Injection: PASS (no SQL)
- Command Execution: PASS (no system calls)
- Secrets: PASS (no credentials)
- Malicious Imports: PASS (uses only builtins)

---

### Example 1b: API Contract Guard
```bash
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Write JavaScript to filter even numbers from an array",
    "language": "javascript"
  }'
```

**Expected Response:**
```json
{
  "detail": [
    {
      "type": "literal_error",
      "loc": ["body", "language"],
      "msg": "Input should be 'python'"
    }
  ]
}
```

**Why it fails:** the hardened API only accepts Python until non-Python validators are implemented.

---

## 2. SQL Injection Detection

### Example 2a: Unsafe SQL (F-string)
```python
# Code that WOULD fail validation:
user_id = "1 OR 1=1"
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
```

**Validator Output:**
```
FAILED: SQL injection risk
Issue: Unsafe pattern: f-string SQL
Suggestion: Use parameterized queries instead
Fix: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### Example 2b: Safe SQL (Parameterized)
```python
# Code that PASSES validation:
user_id = input()
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

**Validator Output:**
```
PASSED: SQL injection detector
No unsafe patterns detected
```

---

## 3. Command Execution Detection

### Example 3a: Unsafe Command Execution
```python
# Code that WOULD fail validation:
import os
username = input()
os.system(f"echo {username}")  # Dangerous: shell injection
```

**Validator Output:**
```
FAILED: Dangerous command execution detected
Issues:
- os.system: Arbitrary shell command
- shell injection vulnerability
Note: shell=True is rewritten conservatively when possible, but os.system stays a hard failure.
```

### Example 3b: Safe Process Execution
```python
# Code that PASSES validation:
import subprocess
result = subprocess.run(["ls", "-la"], shell=False, check=True)
```

**Validator Output:**
```
PASSED: Command execution detector
No dangerous patterns detected
```

---

## 4. Secrets Detection & Auto-Redaction

### Example 4a: Hardcoded AWS Key
```python
# Code that WOULD fail validation:
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

**Validator Output:**
```
FAILED: Secrets detected
Issues:
- AWS Access Key detected
- AWS Secret Key pattern detected

Auto-Fixed Code:
AWS_ACCESS_KEY = "AKIA****"
AWS_SECRET = "wJal****"
```

### Example 4b: Safe Credential Handling
```python
# Code that PASSES validation:
import os
from dotenv import load_dotenv

load_dotenv()
aws_key = os.environ.get("AWS_ACCESS_KEY")
```

**Validator Output:**
```
PASSED: Secrets scanner
No hardcoded credentials found
Correctly using environment variables
```

---

## 5. Malicious Imports Detection

### Example 5a: Blocked Pickle (Deserialization)
```python
# Code that WOULD fail validation:
import pickle
user_data = input()
obj = pickle.loads(user_data)  # Dangerous: arbitrary code execution
```

**Validator Output:**
```
FAILED: Malicious imports detected
Issues:
- Blocked: pickle (arbitrary code execution via deserialization)
Recommendation: Use json.loads() instead for untrusted data
```

### Example 5b: Dynamic Import Detection
```python
# Code that WOULD fail validation:
module_name = input()
mod = __import__(module_name)  # Dangerous: dynamic module loading
```

**Validator Output:**
```
FAILED: Malicious imports detected
Issues:
- Dynamic __import__() call detected
Recommendation: Use importlib with validation
```

### Example 5c: Safe Imports
```python
# Code that PASSES validation:
import json
import typing
from pathlib import Path

data = json.loads(user_input)
```

**Validator Output:**
```
PASSED: Malicious imports detector
All imports are safe
```

---

## 6. Real-World Scenarios

### Scenario A: Web API Endpoint Code Generation

**Prompt:**
```
Write a Python function to fetch user data from a database and return as JSON
```

**Generated Code (Safe):**
```python
import json
from typing import Dict, Any

def get_user(user_id: int) -> Dict[str, Any]:
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    return json.dumps(user) if user else "{}"
```

**Validation Report:**
```
SQL Injection: PASSED
- Uses parameterized queries

Command Execution: PASSED
- No system calls

Secrets: PASSED
- No hardcoded credentials

Malicious Imports: PASSED
- Only uses safe standard-library imports

OVERALL: PASSED
```

---

### Scenario B: File Processing Script

**Prompt:**
```
Write Python code to process CSV files and generate a report
```

**Generated Code (Safe):**
```python
import csv
from pathlib import Path

def process_csv(filepath: str) -> list:
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    with open(path, "r") as f:
        reader = csv.DictReader(f)
        return [row for row in reader]
```

**Validation Report:**
```
All Validators: PASSED
- Safe file I/O with pathlib
- Uses csv module
- No subprocess calls
```

---

### Scenario C: Data Validation Function

**Prompt:**
```
Write a function to validate email addresses and return True/False
```

**Generated Code (Safe):**
```python
import re
from typing import Optional

def validate_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password(pwd: str) -> dict:
    return {
        "length": len(pwd) >= 8,
        "has_upper": any(c.isupper() for c in pwd),
        "has_digit": any(c.isdigit() for c in pwd),
    }
```

**Validation Report:**
```
All Validators: PASSED
- No SQL usage
- No command execution
- No hardcoded secrets
- No malicious imports
```

---

## 7. Testing Validators Directly

### Running the Unit Tests

```bash
# Run all tests
pytest tests -v

# Current result:
# 36 passed in ~5s
```

### Interactive Testing with Web UI

1. Start the server:
```bash
uvicorn src.main:app --reload
```

2. Open browser: **http://localhost:8000/static/demo_ui.html**

3. Try these prompts:

**Safe Prompts (Will Pass)**
- "Write a Python function to check if a number is prime"
- "Write a Python function to merge two sorted lists"
- "Create a function to calculate factorial recursively"

**Prompts that Exercise Validators**
- "Write Python code to list directory contents" (might trigger imports check)
- "Create a function to execute a shell command safely" (tests subprocess handling)
- "Write code to query a database" (tests SQL patterns)

If your deployment is secured, fill in the optional API key field before clicking **Generate Code**.

---

## 8. How to Use in Your Application

### Python Integration

```python
from src.validators.factory import create_code_guard

# Create a guard with all validators
guard = create_code_guard()

# Validate generated code
code = """
def add(a, b):
    return a + b
"""

result = guard.validate(code)

print(f"Valid: {result.validation_passed}")
print(f"Output: {result.validated_output}")
```

### API Integration

```python
import requests

response = requests.post(
    "http://localhost:8000/generate",
    headers={"X-API-Key": "change-me-for-shared-access"},  # Optional in local dev
    json={
        "prompt": "Write a function to calculate average",
        "language": "python",
        "strict": False
    }
)

data = response.json()
print(f"Code: {data['code']}")
print(f"Passed: {data['passed']}")
print(f"Issues: {data['issues']}")
```

---

## 9. Validator Configuration

### Strict Mode (Block Network Imports)

```bash
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Write code to fetch data from an API",
    "language": "python",
    "strict": true
  }'
```

With `strict: true`, the validator will reject imports like:
- `import requests`
- `import socket`
- `import urllib`

---

## 10. Common Questions

### Q: Will the validator reject my safe code?

**A:** The validators are conservative, but not perfect. The current tests cover safe parameterized SQL, dangerous command execution, secrets redaction, and strict import blocking. Treat the output as a guardrail, not a proof of production safety.

### Q: Can I disable validators?

**A:** Currently validators run for all generated code. You can modify `src/main.py` to make them optional via request parameters.

### Q: What if my code uses a blocked module safely?

**A:** The validators use a whitelist/blacklist approach. Modules like `pickle` are always blocked due to inherent risks. For legitimate use of `socket` or `requests`, use `strict=false` mode.

### Q: How are secrets redacted?

**A:** Regex patterns match known formats (AWS key format, GitHub token pattern, etc.) and replace them with placeholders in the validated output.

---

## 11. Performance Notes

- Average validation time: lightweight enough for interactive demo usage
- Validators run locally as part of the Guard validation pipeline
- No external API calls for validation
- Suitable for real-time feedback in development tools

---

## Quick Reference

| Validator | Blocks | Allows | Auto-Fix |
|-----------|--------|--------|----------|
| **SQL** | f-strings, concat in SQL | parameterized queries | Suggests safe patterns |
| **Command** | os.system, eval, subprocess with shell=True | subprocess.run(..., shell=False) | Converts `shell=True` to `shell=False` when safe |
| **Secrets** | Hardcoded AWS keys, tokens, passwords | os.environ, .env files | Auto-redacts |
| **Imports** | pickle, ctypes, socket, __import__ | json, typing, pathlib | Suggests safe alternatives |

---

**Last Updated:** March 29, 2026
