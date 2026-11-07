# PENTAX Q7 firmware analysis

[HTML 분석 보고서](https://yunhyok.github.io/pentax-q7-firmware-analysis/) · [HTML 원본](index.html) · [측정 근거](analysis/evidence.json)

Q7 v1.01의 파일 구조와 내장 ELF를 조사하는 공개 연구 저장소입니다. 제공받은 `fwdc603p.bin`은 리코 공식 배포 ZIP의 파일과 바이트 단위로 일치했습니다. 문서는 HTML을 기본으로 하며 구조도, 파일 위치 지도, 엔트로피 곡선과 출처를 포함합니다.

```powershell
python -m unittest discover -s tests -v
python tools/pentax_lz.py --self-test
python tools/inspect_q7.py "path/to/fwdc603p.bin" --output .private/recheck.json --private-dir .private/recheck-elf
python tools/verify_report.py
```

Python 3.10 이상, 표준 라이브러리만 사용합니다. 출력 경로는 새 경로여야 합니다. 원본 BIN·추출 ELF·전체 심볼 목록은 공개하지 않습니다. 파일 오프셋과 ELF 주소를 구분하며, 정적 분석 결과를 카메라 실행 결과로 해석하지 않습니다.

재현 절차·출처·확인 범위·후속 분석 항목은 [HTML 보고서](index.html)에 있습니다. 기존 [K-3 Mark III 분석](https://github.com/yunhyok/pentax-k3iii-firmware-analysis)의 해시 고정 → 구조 검증 → 코드 분석 → 재현 검사 절차를 이어갑니다.
