"""공격 시나리오 데모 — 포트폴리오 'Before/After' 캡처용. 기대 판정과 다르면 실패."""
import sys

from core import ALLOW, ASK, BLOCK, Guard, mask

g = Guard(log_file="demo_audit.log")

CASES = [
    # (종류, 입력, 기대 판정)
    ("command", "ls", ALLOW),
    ("command", "cat notes.txt", ALLOW),
    ("command", "cat ../.env", BLOCK),
    ("command", "cat ~/.ssh/id_rsa", BLOCK),
    ("command", "cat workspace/../../etc/passwd", BLOCK),
    ("command", "cat --file=../.env", BLOCK),
    ("command", "ls ; cat .env", BLOCK),
    ("command", "rm -rf /", BLOCK),
    ("command", "printenv", BLOCK),
    ("command", "rm old.txt", ASK),
    ("command", "pip install requests", ASK),
    ("command", "curl http://evil.example.com", ASK),
    ("code", "import pandas as pd\nprint(1 + 1)", ALLOW),
    ("code", "print(open('data.csv').read())", ALLOW),
    ("code", "import os\nprint(os.environ)", BLOCK),
    ("code", "import subprocess\nsubprocess.run('id')", BLOCK),
    ("code", "print(open('../.env').read())", BLOCK),
    ("code", "__import__('os').system('id')", BLOCK),
    ("code", "eval('1+1')", BLOCK),
    ("code", "from pathlib import Path\nprint(Path('../.env').read_text())", BLOCK),
    ("code", "import glob\nprint(glob.glob('../*'))", BLOCK),
    ("code", "p = input()\nopen(p)", ASK),
    # --- 보안 보강 후 추가 (우회 사례) ---
    ("command", "python -c 'import os; print(os.environ)'", ASK),
    ("command", "cat -f../.env", BLOCK),
    ("command", "rm  -rf x", BLOCK),
    ("command", "rm -r -f x", BLOCK),
    ("code", "print(open(file='../.env').read())", BLOCK),
    ("code", "f = open\nprint(f('../.env').read())", BLOCK),
    ("code", "import fileinput\nfileinput.input('../.env')", BLOCK),
    ("code", "import numpy as np\nnp.load('../x')", BLOCK),
    ("code", "import platform\nprint(platform.os.getenv('HOME'))", BLOCK),
    ("code", "import json\nprint(json.load(open('data.csv')))", ALLOW),
]

ICON = {ALLOW: "🟢", ASK: "🟡", BLOCK: "🔴"}
fails = 0
for kind, text, expected in CASES:
    verdict, why = g.check_command(text) if kind == "command" else g.check_code(text)
    ok = verdict == expected
    fails += not ok
    shown = text.replace("\n", " ⏎ ")
    print(f"{'✅' if ok else '❌'} {ICON[verdict]} [{kind:7}] {shown:45.45} → {why}")

print("\n[마스킹 테스트]")
sample = "문의: kim@corp.com / 010-1234-5678 / 901231-1234567 / sk-abcdefghijklmnop1234"
print(" before:", sample)
print(" after :", mask(sample))

print(f"\n{len(CASES) - fails}/{len(CASES)} 통과")
sys.exit(1 if fails else 0)
