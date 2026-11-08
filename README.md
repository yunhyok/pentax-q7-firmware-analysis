# PENTAX Q7 firmware analysis

[HTML 분석 보고서](https://yunhyok.github.io/pentax-q7-firmware-analysis/) · [HTML 원본](index.html) · [측정 근거](analysis/evidence.json)

[재패킹 검증·AF·UI 기반 연구](https://yunhyok.github.io/pentax-q7-firmware-analysis/implementation-report.html): 압축 448블록을 원본과 바이트 단위로 재생성하고 한 명령을 변경한 코드의 반환값을 검증했습니다. 앱 업데이트 검사 13사례, burn header 5사례, AF·UI 14사례와 K-3 Mark III 구현 차이를 정리했습니다. AF는 향후 변경을 위한 기반 연구이며, 카메라 기록·부팅은 실행하지 않았습니다. [네 목표의 상태](analysis/hq-status.json)

[FC1 비트·HDR task 생성·제출·완료 보고서](https://yunhyok.github.io/pentax-q7-firmware-analysis/hdr-task-report.html): FC1 입력 유형과 직접 제어 워드 경로, 공통 C12 task 생성과 큐 제출, IRQ·하위 이미지·processor·PathWait 완료 조건을 추적했습니다. K-3 Mark III 자료와 대조하며 원본 명령 재실행과 실기 미관측 범위를 구분했습니다. [근거·한계](hdr-task-report.html#validation)

[HDR FC1 활성화·최종 제출 패스 보고서](https://yunhyok.github.io/pentax-q7-firmware-analysis/hdr-control-report.html): HDR 보조 설정에 따른 패스 구성과 전체 범위 선택을 연결했습니다. FC1 활성화와 별도 제어 워드, 클래스별 분기 조건을 원본 명령으로 검증하고 K-3 Mark III 자료와 대조했습니다. [검증·한계](hdr-control-report.html#validation)

[HDR 제출 분기·최종 FC 계수 보고서](https://yunhyok.github.io/pentax-q7-firmware-analysis/final-color-report.html): 새 HDR 경로의 IpuSubmit 출력 선택과 FIPLIB FC 계수 생성·내보내기를 추적했습니다. 출력 선택 2사례와 FC 구성→Export→FC1 setter·writer 6사례, MMIO 쓰기 72회를 원본 명령으로 검증했습니다. 계수 보존과 패스별 활성화·실제 픽셀의 한계는 구분했습니다. [근거·한계](final-color-report.html#validation)

[HDR 버퍼·색 처리 패스 후속 보고서](https://yunhyok.github.io/pentax-q7-firmware-analysis/pixel-report.html): HDR IPU 출력 할당에서 LDC를 거쳐 JPEG 입력으로 전달되는 조건부 주소 연결, 실제 DirectCompress 압축 위치, 패스 선택과 CM·FC1의 FIPLIB 덮어쓰기를 추적했습니다. 두 setter·writer 구간에서 객체 바이트와 MMIO 28회를 대조했습니다. [근거·한계](pixel-report.html#validation)

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
