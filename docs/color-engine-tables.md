# Q7 색 엔진: 표, 계산식, K-3 Mark III와의 대응

Q7 펌웨어 1.01에서 Custom Image의 색을 만드는 **숫자 표**를 이름으로 찾아 값을 꺼내고, 그 표를 조합하는 루틴 세 개의 계산을 읽어 파이썬으로 옮긴 기록입니다. K-3 Mark III 연구에서 정리한 색 엔진과 같은 계열이며, Q7 쪽이 더 오래된 형태입니다.

> **확실성.** 표의 값은 복원한 프로그램에서 주소로 직접 읽었습니다(**정적 분석**). 아래 "계산식"의 세 루틴은 기계어를 읽어 옮긴 뒤, 원본 루틴을 CPU 에뮬레이터에서 실행한 출력과 모든 값을 비교했습니다(**모델**: 에뮬레이터 실행이며 실물 카메라 실행이 아닙니다). 3차원 표를 만드는 루틴은 기계어를 읽기만 했습니다(**정적 분석**). 표를 받은 영상 처리 회로가 픽셀을 어떻게 보간하는지, 실제 사진, 카메라 JPEG·Lightroom과의 일치는 **미확인**입니다.

## 재현 방법

```bash
python tools/export_color_tables.py fwdc603p.bin --output .private/color-engine-tables.json
```

결과는 [`analysis/color-engine-tables.json`](../analysis/color-engine-tables.json)과 같아야 합니다. 이 도구는 `decode_segments.py`로 E04 세그먼트를 복원하고 `q7_symbols.py`가 읽는 주소·이름 표에서 아래 이름의 주소를 찾아 값을 읽습니다. 같은 표를 별도로 작성한 디코더로도 꺼냈고 두 결과는 바이트 단위로 같았습니다. 그 디코더가 복원한 네 세그먼트의 SHA-256은 [`analysis/segment-decode.json`](../analysis/segment-decode.json)의 값과 같습니다.

계산식의 에뮬레이터 대조는 [firmware-color-studio의 `tools/q7/check_port.py`](https://github.com/yunhyok/firmware-color-studio/pull/9)에 있습니다(unicorn 사용, 펌웨어 필요). 결과는 다음과 같습니다.

```text
MakeColorMatrix (six colour matrices, CM, FC1, chroma offsets): 276/276 settings identical
CalcGammaCorrectionTable and ...Reversal (4096 entries each): 906/906 settings identical
```

## 찾은 표

모두 E04(시작 주소 `0x8012da80`)에 있습니다. 주소와 값 전체는 JSON에 있습니다.

| 이름 | 내용 | 단위 |
|---|---|---|
| `cnsCameraBasicMatrix` (`0x804add38`) | 센서 기본 행렬. `11243 -3459 408 / -2736 12937 -2009 / -2 -4343 12537` | 1.0 = 8192 |
| `cnsMakeUpMatrix<모드>` 11개 | Custom Image별 행렬 | 1.0 = 8192 |
| `cnsMakeUpMatrix<모드>6` 11개 | 모드마다 행렬 여섯 개. 3차원 표의 색상 구역(R·G·B 크기 순서 여섯 가지)마다 하나씩 쓰임. 1.01에서는 여섯 개가 모두 단일 행렬과 같음 | 1.0 = 8192 |
| `cnarsSatCtlMatrix00`–`08` | 채도 −4…+4. `04`가 단위행렬 | 1.0 = 8192 |
| `cnarsFilterEffectMatrix00`–`08` | 모노톤 필터 효과(모노톤에서 채도 행렬 자리에 들어감) | 1.0 = 8192 |
| `cnsHueShiftMatrix00`–`08` | 색상 −4…+4. Cb·Cr 평면의 회전 | **1.0 = 256** |
| `arcnwYCbCrConversionMatrixDefault` | `77 150 29 / -43 -85 128 / 128 -107 -21` | 1.0 = 256 |
| `arcnsSRGBAdobeRGB` | `5857 2334 0 / 0 8192 0 / 0 335 7856`. AdobeRGB일 때 YC 행렬에 곱함 | 1.0 = 8192 |
| `cnarwBasicTone{128,256,512,1024,2048}{Low,Middle,High}` 15개 | 톤 곡선. 256점, 부호 없는 16비트. 대비 계열 세 개 × 열 다섯 개 | 16130에서 포화 |
| `cnarwReversalTone{128,181,256,362,512,724,1024}` 7개 | 리버설 필름 곡선 | 같음 |
| `cnwBasicToneSaturationPointMin`, `…Output`, `cnwBasicToneBaseNumber` | 16130, 4095, 64 | – |
| `cnarsCbAddition`, `cnarsCrAddition` (+`AdobeRGB`) | 조색 색 0…8의 Cb·Cr 오프셋(Muted, Bleach Bypass) | 4096 = 전체 범위 |
| `cnarsCbOffset`, `cnarsCrOffset` (+`AdobeRGB`) | 모노톤 조색 −4…+4의 Cb·Cr 오프셋 | 같음 |
| `arwCChromaSuppressionRatioLut` | 암부 채도 억제 비율 2048개 | 1.0 = 8192 |
| `cntCustomImageUnit<모드>` 23개 | Custom Image와 장면 모드의 기본값 기록(28바이트) | – |
| `arcnlDNGColorMatrix1`, `2` | (분자, 65536) 아홉 쌍씩. DNG의 ColorMatrix1(표준광 A), ColorMatrix2(D65) | – |

이름이 따로 없는 정적 표 넷은 앞 이름과 오프셋으로 기록했습니다(JSON의 `anonymous`): 키 표 `512 431 362 304 256 215 181 152 128`, 리버설 경계 `128 181 256 362 512 724 1024`, CM 기본 행렬(256 × 단위행렬), 3차원 표의 격자 기준값 `0 512 … 3584 4095`.

`arcnlDNGColorMatrix2`는 LibRaw `colordata.cpp`에 Q-S1(Q7과 같은 센서)의 D65 행렬로 실린 값 `12995 -5593 -1107 / -1879 10139 2027 / -64 1233 4919`(×10⁻⁴)와 같습니다.

## 계산식

### `ColorMatchingService_MakeColorMatrix` (`0x8041c180`)

인자는 설정 구조체, 화이트밸런스 자료(또는 0), 서술자 A, 서술자 B, 행렬 여섯 개의 출력 버퍼입니다. 설정에서 읽는 필드는 `+0x34` 모드 번호, `+0x35` 채도, `+0x39` 색상, `+0x3a` 필터 효과, `+0x3b` 모노톤 조색, `+0x3c` 조색 색, `+0x178` 이득, `+0x1fc` 색 공간, `+0x200` 현상 감도(0…4 → 128, 181, 256, 362, 512)입니다.

- **모드 번호** (`GetMakeUpMatrix`의 분기표): 0 Natural, 1 Vivid, 2 Portrait, 3 Landscape, 4 Miyabi, 5 Honoka, 6 Reversal, 7 BleachBypass, 8 PopTune, 9 Vivid(다시), 10 Monotone.
- **행렬 곱** `MatrixMultiplication(out, A, B)`는 `A × B`이고 `(합 + 0x1000) >> 13`(논리 시프트)의 아래 16비트입니다. [재구성한 C 코드](../source/reconstructed/q7_numeric.c)와 같습니다.
- **색 행렬 여섯 개:** `채도[n] × MakeUp6[i] × CameraBasic`을 구하고(모노톤은 채도 자리에 `FilterEffect[n]`), 각 값을 0 쪽으로 32로 나눈 다음 대각 성분을 "256 − 같은 행의 나머지 둘"로 바꿉니다. 결과는 **1.0 = 256**이고 각 행의 합이 256입니다.
- **서술자 A(`+0x18`, 기존 경로 분석의 CM 레지스터)는 색 행렬이 아닙니다.** `256 × 단위행렬 × 이득 / 8192`에 화이트밸런스 이득을 곱해 ±`0x7ff`로 제한한 값입니다. 루틴이 스택에 따로 계산하는 단일 행렬(`채도 × MakeUp × CameraBasic × 이득`)은 어떤 출력에도 쓰이지 않습니다.
- **서술자 B(`+0x18`, FC1):** `HueShift[색상] × YCbCr`를 `(합 + 0x80) >> 8`로 구하고(1.0 = 256), AdobeRGB이면 `arcnsSRGBAdobeRGB`를 곱한 뒤, 왼쪽으로 3비트 밀어(1.0 = 2048) 씁니다. 모드 5와 7은 색상을 항상 가운데 값으로 씁니다.
- **Cb·Cr 오프셋(B의 `+0x2a`, `+0x2c`, `0x800`을 더해 저장):** 모드 10은 `cnarsCbOffset/CrOffset[모노톤 조색]`, 모드 5·7은 `cnarsCbAddition/CrAddition[조색 색]`, 나머지는 0입니다.

### `GammaCorrectionService_CalcGammaCorrectionTable` (`0x8041d058`)

출력은 16비트 4096개입니다. K-3 Mark III의 감마 계산과 같은 구조이고 다음이 다릅니다.

- 하이라이트·섀도 조정이 없습니다(오프셋 세 개가 상수 0).
- 열이 다섯 개(128, 256, 512, 1024, 2048)이고 `v`를 128…2048로 제한합니다.
- `v = (키 표[키] × 비율 / 256 × 노출 이득) >> 13`. 비율은 `0x400000 / (+0x174의 값)`이고 그 값이 0이면 256, 노출 이득은 `+0x164`(0x2000 = 1.0)입니다.
- 대비: `t = 2 × 대비`를 ±12로 제한하고, `t > 0`이면 High·Middle을 `t × 512 / 12`로, 아니면 Middle·Low를 `(t + 12) × 512 / 12`로 섞습니다. 이웃한 두 열은 `v / 16`번째 점이 `64 × 118 = 7552`가 되도록 섞습니다.
- 톤 곡선은 0…128번 점만 씁니다. `4095 / 16130`을 곱해 4095로 제한하고, 출력 0…2047번에 16칸씩 직선으로 채웁니다. 출력 2048…4095번은 2048번 값에서 4095까지의 직선입니다.

### `GammaCorrectionService_CalcGammaCorrectionTableReversal` (`0x8041cd28`)

같은 형태에 곡선 일곱 개를 씁니다. `v`를 128…1024로 제한하고, 키는 0으로 고정이며 대비는 쓰지 않습니다.

## 결과가 가는 곳: 9 × 9 × 9 3차원 표

`ImageQualityService_SetupGammaCorrectionAndColorMatchingService` (`0x804289b8`)가 감마 표 넷과 서술자를 할당하고 다음을 부릅니다.

- `GammaCorrectionService_SetupGammaCorrectionData` (`0x8041e27c`): 표 A는 위 감마 루틴의 출력(모드 6이면 리버설), 표 B·C는 Cross Processing일 때만 채웁니다. 표 D는 `CalcBasicGammaCorrectionTable`의 출력이고, 하드웨어 감마 블록(서술자 ID 10)에는 이 표 D가 들어갑니다.
- `ColorMatchingService_MakeColorReproductionLutParam` (`0x8041c7dc`, 서술자 ID `0x13`, `0x19c0`바이트): 9 × 9 × 9개의 RGB 값을 만듭니다. 축마다 격자 아홉 개는 표 D가 처음으로 `0, 512, …, 3584, 4095`에 이르는 입력 위치입니다. 격자점마다 ① R·G·B의 크기 순서로 여섯 행렬 중 하나를 고르고 ② `행렬 × RGB >> 8` ③ Y·Cb·Cr로 바꾸고(`306 601 117 / -173 -339 512 / 512 -429 -83`, `>> 10`) ④ 행렬 출력의 G가 256 이하이면 Cb·Cr에 `arwCChromaSuppressionRatioLut[min(2 × (256 − G), 2047)] / 8192`를 곱하고(검정에서 0.875) ⑤ RGB로 되돌려(`1436`, `-352 -731`, `1815`, `>> 10`) 0…4095로 제한한 뒤 ⑥ 채널마다 표 A에서 값을 읽습니다.

따라서 Q7은 색 행렬과 감마를 따로 적용하지 않고, 기본 감마(표 D)를 거친 값으로 이 3차원 표를 찾아 보간합니다. 격자점에서는 `감마(암부 채도 억제(행렬 × RGB))`와 같고, 격자점 사이는 회로의 보간에 따릅니다. 감마 루틴들은 색 공간 설정을 읽지 않습니다.

## Custom Image 기본값 기록

`cntCustomImageUnit<모드>`의 바이트 0은 모드 번호, 1 채도, 2 대비, 3 샤프니스, 4 키, 5 색상, 6 모노톤 필터 효과, 7 모노톤 조색, 8 조색 색입니다(설정은 0…8로 저장, 4가 0). 설정 구조체의 `+0x34`부터와 순서가 같습니다. Q7과 K-3 Mark III에 모두 있는 Custom Image는 기본값이 서로 같습니다(Bright 대비 +1, Radiant 키 +2·대비 +3, Muted 키 +4·대비 −3, Bleach Bypass 키 −4·대비 +4·조색 Green). 조색 오프셋도 4로 나누면 K-3 Mark III의 값과 같습니다.

## 한계

- 에뮬레이터 대조는 루틴 세 개의 정수 계산에 한합니다. 3차원 표 생성과 `CalcBasicGammaCorrectionTable`은 실행해 대조하지 않았습니다.
- 회로가 3차원 표를 보간하는 방식, 실행 중 이득 값(`+0x164`, `+0x174`, `+0x178`)의 실제 크기, 센서 포화 수준과 감마 입력 0…4095의 관계는 모릅니다. 그래서 카메라 JPEG의 절대 밝기는 이 자료만으로 정할 수 없습니다.
- Q7로 찍은 RAW·JPEG, Lightroom 출력과의 비교는 하지 않았습니다.
