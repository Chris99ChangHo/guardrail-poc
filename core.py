"""Guardrail Core — CLI / 웹 UI가 공유하는 정책 엔진.

판정은 항상 (verdict, reason). verdict ∈ {ALLOW, ASK, BLOCK}
모든 판정은 audit.log(JSON Lines)에 기록된다.
"""
import ast
import json
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

import yaml

ALLOW, ASK, BLOCK = "allow", "ask", "block"
PATHY = re.compile(r"[/\\]|^[.~]")  # 경로처럼 보이는 토큰

# ---------- 출력 마스킹 (DLP) ----------
MASKS = [
    (re.compile(r"\b\d{6}-[1-4]\d{6}\b"), "******-*******"),            # 주민등록번호
    (re.compile(r"\b01[016789]-?\d{3,4}-?\d{4}\b"), "***-****-****"),   # 휴대폰
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "***@***"),               # 이메일
    (re.compile(r"(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})"), "[API_KEY]"),
]


def mask(text: str) -> str:
    for pat, rep in MASKS:
        text = pat.sub(rep, text)
    return text


class Guard:
    def __init__(self, policy_file="policy.yaml", log_file="audit.log"):
        pf = Path(policy_file).resolve()
        self.p = yaml.safe_load(pf.read_text(encoding="utf-8"))
        self.root = (pf.parent / self.p["workspace"]).resolve()
        self.root.mkdir(exist_ok=True)
        self.log_file = pf.parent / log_file

    # ---------- 감사 로그 ----------
    def log(self, kind, target, verdict, reason):
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "kind": kind,
            "target": target[:200],
            "verdict": verdict,
            "reason": reason,
        }
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return verdict, reason

    # ---------- 경로 ----------
    def _path(self, raw):
        q = Path(raw).expanduser()
        p = (q if q.is_absolute() else self.root / q).resolve()  # ../ 정규화
        for part in p.parts:
            if part in self.p["blocked_names"] or part.startswith(".env"):
                return BLOCK, f"민감 경로 접근 시도: {raw}"
        if not p.is_relative_to(self.root):
            return BLOCK, f"workspace 밖 접근(경로 우회 의심): {raw}"
        return ALLOW, "workspace 내부 경로"

    def check_path(self, raw):
        return self.log("path", raw, *self._path(raw))

    # ---------- 셸 명령어 ----------
    def _cmd(self, cmd):
        low = " ".join(cmd.lower().split())   # 공백 정규화
        for pat in self.p["blocked_commands"]:
            if pat in low:
                return BLOCK, f"파괴적/위험 명령어 패턴: {pat}"
        try:
            toks = shlex.split(cmd)
        except ValueError:
            return BLOCK, "명령어 파싱 실패"
        if not toks:
            return ALLOW, "빈 명령"

        if toks[0] == "rm":                          # 플래그를 토큰 단위로 합쳐 판정
            fl = "".join(t.lstrip("-").lower() for t in toks[1:] if t.startswith("-") and not t.startswith("--"))
            longs = [t for t in toks[1:] if t.startswith("--")]
            if ("r" in fl and "f" in fl) or ("--recursive" in longs and ("--force" in longs or "f" in fl)):
                return BLOCK, "파괴적 명령어: rm 재귀+강제 플래그"

        for t in toks[1:]:
            if t.startswith("--") and "=" in t:      # --file=../.env 우회 방지
                t = t.split("=", 1)[1]
            elif t.startswith("-") and len(t) > 2:   # -f../.env (단문 옵션에 붙은 값)
                rest = t[2:]
                if PATHY.search(rest) or rest in self.p["blocked_names"]:
                    t = rest
                else:
                    continue
            if t.startswith("-"):
                continue
            if PATHY.search(t) or t in self.p["blocked_names"]:
                v, why = self._path(t)
                if v == BLOCK:
                    return v, why

        head, two = toks[0], " ".join(toks[:2])
        for key in (two, head):
            if key in self.p["ask_commands"]:
                return ASK, f"승인 필요 명령어: {key}"
        if head in self.p["auto_commands"]:
            return ALLOW, "자율 허용 명령어"
        return ASK, f"미등록 명령어 → 승인 필요: {head}"

    def check_command(self, cmd):
        return self.log("command", cmd, *self._cmd(cmd))

    # ---------- 파이썬 코드 (AST) ----------
    def _code(self, src):
        try:
            tree = ast.parse(src)
        except SyntaxError as e:
            return BLOCK, f"문법 오류: {e.msg}"
        pol, ask_reason = self.p, None
        allowed = set(pol["allowed_modules"])
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                n.func._is_func = True
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.name.split(".")[0] not in allowed:
                        return BLOCK, f"허용 목록 밖 모듈 import: {a.name}"
            elif isinstance(n, ast.ImportFrom):
                if n.level or (n.module or "").split(".")[0] not in allowed:
                    return BLOCK, f"허용 목록 밖 모듈 import: {n.module}"
            elif isinstance(n, ast.Attribute) and n.attr in pol["blocked_attrs"]:
                return BLOCK, f"금지 속성 접근: .{n.attr}"
            elif isinstance(n, ast.Name) and n.id in pol["blocked_values"] and isinstance(n.ctx, ast.Load):
                parent_call = getattr(n, "_is_func", False)
                if not parent_call:
                    return BLOCK, f"금지 함수를 값으로 참조(별칭 우회 의심): {n.id}"
            elif isinstance(n, ast.Call):
                f = n.func
                name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
                if name in pol["blocked_calls"]:
                    return BLOCK, f"금지 함수 호출: {name}()"
                is_json_load = name == "load" and isinstance(f, ast.Attribute) and getattr(f.value, "id", "") == "json"
                if name in pol["file_readers"] and not is_json_load:
                    cands = list(n.args[:1]) + [k.value for k in n.keywords if k.arg in pol["path_kwargs"]]
                    if not cands:
                        # to_csv, to_excel, to_json은 경로 인자가 없으면 파일 쓰기가 아니라 메모리 문자열/객체 반환이므로 허용
                        if name not in ("to_csv", "to_excel", "to_json"):
                            ask_reason = f"{name}() 경로를 코드만으로 확인 불가"
                    for a0 in cands:
                        if isinstance(a0, ast.Constant) and a0.value is None:
                            continue  # path_or_buf=None은 문자열 반환이므로 안전
                        if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                            if "://" in a0.value:
                                return BLOCK, f"외부 네트워크 URL 접근 차단: {a0.value}"
                            v, why = self._path(a0.value)
                            if v == BLOCK:
                                return v, why
                        else:  # 경로를 정적으로 알 수 없음 → 정적 분석의 한계
                            ask_reason = f"{name}() 경로를 코드만으로 확인 불가"
        return (ASK, ask_reason) if ask_reason else (ALLOW, "금지 패턴 없음")

    def check_code(self, src):
        return self.log("code", src, *self._code(src))

    # ---------- 코드 실행 (웹 UI용) ----------
    def run_code(self, src, approved=False):
        verdict, why = self.check_code(src)
        if verdict == BLOCK or (verdict == ASK and not approved):
            return {"verdict": verdict, "reason": why, "output": ""}
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}   # 최소 환경변수
        try:
            r = subprocess.run(
                [sys.executable, "-I", "-c", src],   # -I: 격리 모드
                cwd=self.root, capture_output=True, text=True, timeout=10, env=env,
            )
        except subprocess.TimeoutExpired:
            self.log("code", src, "timeout", "10초 초과로 중단")
            return {"verdict": verdict, "reason": "10초 초과로 중단", "output": ""}
        return {"verdict": verdict, "reason": why, "output": mask(r.stdout + r.stderr)}
