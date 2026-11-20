# Q7 색 엔진의 표: 위치, 값, K-3 Mark III와의 대응

Q7 펌웨어 1.01에서 Custom Image의 색을 만드는 **숫자 표**를 이름으로 찾아 값을 꺼낸 기록입니다. K-3 Mark III 연구에서 정리한 색 엔진과 같은 계열의 표가 Q7에도 있습니다. 이 문서는 표의 위치와 값, 그리고 행렬 곱 루틴 두 개의 산술까지만 다룹니다.

> **확실성.** 표의 값은 복원한 프로그램에서 주소로 직접 읽었습니다(**정적 분석**). 표의 뜻은 이름과 값의 모양으로 판단했습니다. 행렬 곱 루틴은 기계어를 읽어 적었습니다(**정적 분석**). 표들을 조합해 영상 처리 회로의 레지스터 값을 만드는 전체 계산, 실제 픽셀, 카메라 JPEG과의 일치는 **미확인**입니다. 실물 카메라에서 실행한 것은 없습니다.

## 재현 방법

```bash
python tools/export_color_tables.py fwdc603p.bin --output .private/color-engine-tables.json
```

결과는 [`analysis/color-engine-tables.json`](../analysis/color-engine-tables.json)과 같아야 합니다. 이 도구는 `decode_segments.py`로 E04 세그먼트를 복원하고 `q7_symbols.py`가 읽는 주소·이름 표에서 아래 이름의 주소를 찾아 값을 읽습니다. 같은 표를 별도로 작성한 디코더([firmware-color-studio의 `tools/q7/`](https://github.com/yunhyok/firmware-color-studio/tree/main/tools/q7))로도 꺼냈고 두 결과는 바이트 단위로 같았습니다. 그 디코더가 복원한 네 세그먼트의 SHA-256은 [`analysis/segment-decode.json`](../analysis/segment-decode.json)의 값과 같습니다.

## 찾은 표

모두 E04(시작 주소 `0x8012da80`)에 있습니다. 주소와 값 전체는 JSON에 있습니다.

| 이름 | 내용 | 단위 | K-3 Mark III 엔진의 대응 항목 |
|---|---|---|---|
| `cnsCameraBasicMatrix` (`0x804add38`) | 센서 기본 행렬. `11243 -3459 408 / -2736 12937 -2009 / -2 -4343 12537`. 각 행의 합이 8192 | 1.0 = 8192 | 공통 센서 행렬 |
| `cnsMakeUpMatrix<모드>` 11개 | Custom Image별 행렬. Natural, Vivid, Portrait, Landscape, Miyabi, Monotone, Flat, Honoka, Reversal, BleachBypass, PopTune. 각 행의 합이 8192 | 1.0 = 8192 | 모드별 행렬 |
| `cnsMakeUpMatrix<모드>6` 11개 | 모드마다 행렬 여섯 개. 쓰임새는 아직 모름 | 1.0 = 8192 | 없음 |
| `cnarsSatCtlMatrix00`–`08` | 채도 −4…+4. `04`가 단위행렬 | 1.0 = 8192 | 채도 행렬 묶음 |
| `cnarsFilterEffectMatrix00`–`08` | 모노톤 필터 효과 | 1.0 = 8192 | 모노톤용 행렬 묶음 |
| `cnsHueShiftMatrix00`–`08` | 색상 −4…+4. Cb·Cr 평면의 회전. `04`가 단위행렬 | **1.0 = 256** | 색상 행렬 묶음(K-3 Mark III는 1.0 = 8192) |
| `arcnwYCbCrConversionMatrixDefault` | `77 150 29 / -43 -85 128 / 128 -107 -21` | 1.0 = 256 | YC 변환 행렬(값이 같음) |
| `cnarwBasicTone{128,256,512,1024,2048}{Low,Middle,High}` 15개 | 톤 곡선. 256점, 부호 없는 16비트. 대비 계열 세 개 × 열 **다섯** 개 | – | 감마 계열(K-3 Mark III는 열 여섯 개) |
| `cnarwReversalTone{128,181,256,362,512,724,1024}` 7개 | 리버설 필름 곡선 | – | 리버설 곡선(K-3 Mark III는 아홉 개) |
| `arcnlDNGColorMatrix1`, `2` | (분자, 65536) 아홉 쌍씩. DNG에 기록하는 색 행렬의 원본 | – | DNG 색 행렬 표 |

이름에 붙은 숫자가 뜻하는 바(예: 톤 곡선의 128…2048, 리버설의 181·362·724)는 K-3 Mark III에서는 노출 이득 단계였습니다. Q7에서도 같은지는 톤 계산 루틴을 읽어야 알 수 있습니다.

## 행렬 곱 루틴 두 개

| 루틴 | 주소 | 산술 | K-3 Mark III의 같은 연산 |
|---|---|---|---|
| `ColorMatchingService_MatrixMultiplication` | `0x8041bc90` | 16비트 × 16비트 곱을 세 개 더하고 `+0x1000`, 논리 오른쪽 시프트 13, 아래 16비트 저장 | 같음 ([재구성한 C 코드](../source/reconstructed/q7_numeric.c)와도 일치) |
| `ColorMatchingService_MatrixMultiplicationForWBGain` | `0x8041bd7c` | 16비트 × 32비트 곱을 세 개 더한 뒤 0 쪽으로 반올림해 13비트 내림(`+0x1000`, 음수면 `+0x2fff`), 결과를 ±`0x7fff`로 제한 | 반올림은 같음. ±`0x7fff` 제한은 Q7 코드에서 읽은 것 |

## 아직 읽지 않은 루틴

표를 조합하는 코드는 같은 구역에 이름으로 남아 있습니다. 다음 순서로 읽으면 Custom Image 설정에서 레지스터 값까지 이을 수 있습니다.

- `ColorMatchingService_MakeColorMatrix` (`0x8041c180`), `ColorMatchingService_HueShift` (`0x8041be94`), `ColorMatchingService_SRGBtoAdobeRGB` (`0x8041bb9c`), `ColorMatchingService_GetMakeUpMatrix` (`0x8041bfac`)
- `GammaCorrectionService_CalcGammaCorrectionTable` (`0x8041d058`), `GammaCorrectionService_CalcGammaCorrectionTableReversal` (`0x8041cd28`)
- 톤 곡선 목록 `cnarpwBasicToneListLow/Middle/High`, `cnarpwReversalToneList`와 Custom Image 기록 `cntCustomImageUnit<모드>`

## 한계

- 표의 뜻은 이름과 값에서 추정했습니다. 코드가 실제로 그 표를 그 용도로 읽는지는 위 루틴을 읽어야 확정됩니다.
- K-3 Mark III와 표의 모양이 다른 곳이 있습니다(톤 열의 수, 색상 행렬의 단위). K-3 Mark III의 계산식을 그대로 적용할 수 있다고 볼 근거는 아직 없습니다.
- RAW 현상, Lightroom 출력, 카메라 JPEG과의 비교는 하지 않았습니다.
