# Q7 펌웨어·렌즈·색 엔진 검증 기록 (2026-11)

## 검증 대상과 해시

| 파일 | 역할 | 크기 (바이트) | SHA-256 |
|---|---|---:|---|
| `fwdc603p.bin` | PENTAX Q7 본체 펌웨어 1.01 | 18,743,520 | `8a928b574623c28624127501526d8496a98a42eac3d843def6d3b5ceb074ff3b` |
| `fwlq101.bin` | 01 STANDARD PRIME 렌즈 펌웨어 | 262,288 | `0484d7718ff3ebf705a2d7c57c6c2babffa394aef883b1096749b271935cce3b` |
| `fwlq102.bin` | 02 STANDARD ZOOM 렌즈 펌웨어 | 262,288 | `ffd125bb12c7b60716bf497185cfab21c99be44ee8d1d9caa9c5761247a53b62` |

## 수행한 검증과 결과

1. **본체 펌웨어 압축 해제·재패킹·인벤토리 검증**
   - `tools/pentax_lz.py --self-test`: 13 checks passed
   - `tools/decode_segments.py fwdc603p.bin --output-dir .private/decoded` + `tools/build_analysis_elf.py`: `.private/main-expanded.elf` 생성 (`a973912dbce5c8e09422c0009892dd47e1d7088e8bd8c9020f2a9c8804149796`)
   - `tools/verify_report.py --firmware fwdc603p.bin`: 원본 펌웨어 인벤토리, 공개 근거, 결정적 HTML 생성, 이미지 `alt` 텍스트 및 로컬 링크 전체 PASS
   - `tools/export_color_tables.py fwdc603p.bin`: `analysis/color-engine-tables.json` 12개 범주 123건과 바이트 단위 일치(`Color tables exact match: True`)

2. **Q 마운트 렌즈 펌웨어 업데이트 검증 (신규)**
   - `tools/check_lens_firmware_update.py`로 본체 `LensFirmwareUpdateService_GetCrc_BYTE`(`0x807dceec`)와 `UserLensFirmwareUpdateExecutionCheck`(`0x807dcf48`)를 Unicorn MIPS32LE로 직접 실행했습니다.
   - `fwlq101.bin`: `LENS_ID=1`, `01 STANDARD PRIME`, 버전 `[1, 1, 14, 0]`(`0049000.02`), `Oct 19 2011`, LOM CRC `0x2668`, 파일 CRC `0x1ca0` 모두 에뮬레이터 계산과 일치
   - `fwlq102.bin`: `LENS_ID=2`, `02 STANDARD ZOOM`, 버전 `[1, 1, 14, 0]`(`0049010.00`), `Oct 19 2011`, LOM CRC `0xfea2`, 파일 CRC `0x1f20` 모두 에뮬레이터 계산과 일치
   - 실행 검사 6사례(정상 2건 `1`, 렌즈 ID 불일치·파일 CRC 1비트 손상·체크 바이트 0 아님·파일 열기 실패 4건 `0`) 및 `Printf_B` 로그 검증 완료 (`reports/lens-firmware-update.html`)

3. **HTML 사이트 통합 및 단위 테스트**
   - `docs/color-engine-tables.md`와 `analysis/color-engine-tables.json` 내용을 정적 HTML 보고서 `reports/color-engine-tables.html`로 통합하고, `site-map.json`·`build_all.py`·`verify_report.py`·안내 문서·`hq-status.json`을 동기화했습니다.
   - `analysis/hq-status.json`의 `stable_evidence` 역사적 SHA-256 값은 기존 고정 계약을 지키기 위해 변경하지 않았으며 `documentation_revision`에 `v0.5.0` 갱신 메모를 적었습니다.
