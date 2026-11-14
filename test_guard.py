"""pytest: 우회 사례 회귀 테스트. 못 막는 건 xfail = 알려진 한계."""
import pytest

from core import ALLOW, ASK, BLOCK, Guard

g = Guard(log_file="test_audit.log")


@pytest.mark.parametrize("cmd,exp", [
    ("python -c 'import os'", ASK),
    ("cat -f../.env", BLOCK),
    ("rm  -rf x", BLOCK),
    ("rm -r -f x", BLOCK),
    ("rm old.txt", ASK),
])
def test_command(cmd, exp):
    assert g._cmd(cmd)[0] == exp


@pytest.mark.parametrize("src,exp", [
    ("import os", BLOCK),
    ("open(file='../.env')", BLOCK),
    ("f = open\nf('../.env')", BLOCK),
    ("import fileinput", BLOCK),
    ("import numpy as np\nnp.load('../x')", BLOCK),
    ("import platform\nplatform.os.getenv('HOME')", BLOCK),
    ("import pandas as pd\nprint(1)", ALLOW),
])
def test_code(src, exp):
    assert g._code(src)[0] == exp


@pytest.mark.xfail(reason="알려진 한계: 문자열 조합으로 만든 경로는 정적 분석 불가(ask로 떨어지나 allow 아님을 보장 못함)", strict=False)
def test_known_limit_obfuscated_path():
    assert g._code("import pandas as pd\nn='..'+'/.env'\npd.read_csv(n)")[0] == BLOCK


@pytest.mark.xfail(reason="알려진 한계: 출력 인코딩(base64 등)은 정규식 마스킹이 못 막음")
def test_known_limit_mask_base64():
    from core import mask
    import base64
    s = base64.b64encode(b"901231-1234567").decode()
    assert "901231" not in base64.b64decode(mask(s)).decode()


def test_timeout_handled():
    r = g.run_code("while True: pass")
    assert "10초" in r["reason"]
