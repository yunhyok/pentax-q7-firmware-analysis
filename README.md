# PENTAX Q7 firmware analysis

[HTML 분석 보고서](https://yunhyok.github.io/pentax-q7-firmware-analysis/) · [HTML 원본](index.html) · [측정 근거](analysis/evidence.json)

[렌즈 수신자·ISP 레지스터·출력 경계 후속 보고서](https://yunhyok.github.io/pentax-q7-firmware-analysis/routing-report.html): AF 콜백 바인딩과 네 구동 모드, 색 행렬의 캐시·필터·vtable 연결, 통계 감마 포트, JPEG 저장 경계를 추적했습니다. ISP 기록 함수 10조건·164검사와 렌즈 분기를 원본 MIPS 명령으로 재실행했습니다. K-3 Mark III의 고정한 참조 커밋과 대조하며 실제 픽셀 출력의 미확정 범위를 명시합니다. [근거·재현](routing-report.html#validation)

[ThreadX·AF·셔터·JPEG·색 처리 후속 보고서](https://yunhyok.github.io/pentax-q7-firmware-analysis/deep-report.html)에는 압축 448블록 복원, 300개 선별 함수의 디컴파일 기록, 호출 관계도, MIPS 행렬 연산 6개 재실행 검사와 K-3 Mark III의 18개 항목 대조가 있습니다. 간접 호출·하드웨어 연결의 미확정 범위를 구분했습니다. [재현 절차](deep-report.html#reproduce) · [코드 근거](analysis/deep-evidence.json)

Q7 v1.01의 파일 구조와 내장 ELF를 조사하는 공개 연구 저장소입니다. 제공받은 `fwdc603p.bin`은 리코 공식 배포 ZIP의 파일과 바이트 단위로 일치했습니다. 문서는 HTML을 기본으로 하며 구조도, 파일 위치 지도, 엔트로피 곡선과 출처를 포함합니다.

```powershell
python -m unittest discover -s tests -v
python tools/pentax_lz.py --self-test
python tools/inspect_q7.py "path/to/fwdc603p.bin" --output .private/recheck.json --private-dir .private/recheck-elf
python tools/verify_report.py
```

구조·복원·전이 도구는 Python 3.10 이상과 표준 라이브러리만 사용합니다. 선택적인 디컴파일에는 Ghidra 12.1 / JDK 21, 계산 재실행에는 angr 10.0.5가 필요합니다. 출력 경로는 새 경로여야 합니다. 원본 BIN·추출 ELF·전체 심볼 목록·디컴파일 원문은 공개하지 않습니다. 파일 오프셋과 ELF 주소를 구분하며, 정적 분석 결과를 카메라 실행 결과로 해석하지 않습니다.

재현 절차·출처·확인 범위·후속 분석 항목은 [HTML 보고서](index.html)에 있습니다. 기존 [K-3 Mark III 분석](https://github.com/yunhyok/pentax-k3iii-firmware-analysis)의 해시 고정 → 구조 검증 → 코드 분석 → 재현 검사 절차를 이어갑니다.
