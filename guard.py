"""개발자용 CLI 래퍼.

  python guard.py run "cat notes.txt"
  python guard.py log 10
에이전트의 셸 도구가 직접 실행하는 대신 이 래퍼를 거치게 만든다.
(shell=False로 실행하므로 ; | && 같은 체이닝은 해석되지 않는다)
"""
import shlex
import subprocess
import sys

from core import ASK, BLOCK, Guard, mask

RED, YEL, GRN, END = "\033[91m", "\033[93m", "\033[92m", "\033[0m"


def main(argv):
    g = Guard()
    if argv[:1] == ["log"]:
        n = int(argv[1]) if len(argv) > 1 else 10
        if g.log_file.exists():
            print("\n".join(g.log_file.read_text(encoding="utf-8").splitlines()[-n:]))
        return 0
    if argv[:1] != ["run"] or len(argv) < 2:
        print('사용법: python guard.py run "<명령어>" | python guard.py log [N]')
        return 1

    cmd = argv[1] if len(argv) == 2 else shlex.join(argv[1:])
    verdict, why = g.check_command(cmd)

    if verdict == BLOCK:
        print(f"{RED}🔴 차단: {why}{END}")
        return 2
    if verdict == ASK:
        ans = input(f"{YEL}🟡 {why}\n실행할까요? [y/N] {END}").strip().lower()
        if ans != "y":
            g.log("command", cmd, "denied", "사용자 거부")
            print("취소됨")
            return 3
        g.log("command", cmd, "approved", "사용자 승인")
    else:
        print(f"{GRN}🟢 허용{END}")

    try:
        r = subprocess.run(shlex.split(cmd), cwd=g.root, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        print("명령어를 찾을 수 없음")
        return 127
    print(mask(r.stdout + r.stderr), end="")
    return r.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
