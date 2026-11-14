# guardrail-poc 핸드오프

## 무엇인가
기술유출에 민감한 기업(예: 반도체)이 AI 에이전트/바이브 코딩을 도입한다는 가정의 PoC.
에이전트의 행동을 위험도에 따라 자율(allow) / 승인(ask) / 차단(block)으로 통제하고,
출력은 마스킹(DLP), 모든 판정은 audit.log(JSON Lines)에 기록한다. 마감 2026-11-15.

## 구조
- policy.yaml : 규칙 (workspace, 차단 이름/명령어, 승인/자율 명령어, 금지 모듈/호출/속성)
- core.py     : Guard 판정 엔진 (check_path / check_command / check_code / run_code), mask()
- guard.py    : 개발자용 CLI  (`python guard.py run "<cmd>"`, `python guard.py log N`)
- app.py      : 비개발자용 Streamlit UI (`streamlit run app.py`, 샘플 코드 6종, LLM 미연동)
- demo_attacks.py : 시나리오 22개 + 마스킹 테스트, 기대 판정과 다르면 실패
- README.md   : 상세 설명, 사용 가이드, 판정 로직, 한계, 로드맵 (먼저 읽을 것)
- workspace/  : 에이전트가 접근 가능한 유일한 폴더 (notes.txt, data.csv, yield.csv 샘플)

## 현재 상태
완료: 코어, CLI, 웹 UI. demo_attacks.py 22/22 통과, UI 6개 흐름 + 승인 흐름 자동 테스트 통과.
미완료(우선순위 순):
1. 입력(프롬프트) 마스킹: mask_prompt() + UI 미리보기
2. 폴더별 읽기/쓰기 권한 모델 + 대량 출력 승인 (policy.yaml paths / export)
3. 에이전트 Hook 연동 1종 (실행 직전 check_command 호출) — 막히면 설계/한계 서술로 대체
4. 보안 보강: pathlib/glob은 차단 완료. fileinput/zipfile 등 목록 밖 모듈은 여전히 allow로 통과 (README 9장). 허용 목록(필요 모듈만 허용) 방식 병행 검토
5. 캡처(정상 vs 공격), 아키텍처 도식 1장, 한계점 서술

## 알려진 한계 (포트폴리오에 명시할 것)
- 정적 분석은 난독화/동적 코드를 못 막음, run_code의 -I 모드는 진짜 샌드박스가 아님
- 에이전트가 이 가드를 우회하는 경로(내장 도구 등)는 못 막음 → 실제 강제는 훅 + OS/컨테이너 격리 필요

## 작업 규칙
- 기존 함수 시그니처와 demo_attacks.py의 기존 기대 판정은 수정 금지 (추가만)
- 변경 후 `python demo_attacks.py` 전부 통과해야 함
- push/merge 금지 (사람 승인)
- 보고는 변경 파일과 요지만, 서론 없이
