"""Render NAND retry and indexed shape raster follow-up reports."""
from build_deep_report import ROOT, read, esc
from build_routing_report import graph
from verify_routing import witnesses


def build_burn():
    data=read('burn-continuation.json')
    v={k:esc(t) for k,t in read('continuation-copy.json').items()}
    v['retry_graph']=graph('burn-retry','기록 실패는 물리 후보만 진행한다',{
        'input':(20,10,'현재 128 KiB 데이터','논리 블록 · 카드 커서'),
        'program':(350,10,'기록 함수 0x80011da8','결과 · 실패 맵 효과는 모델'),
        'success':(700,10,'성공 결과 1','논리 블록 진행'),
        'next':(700,150,'다음 카드 청크 읽기','정상 섹션 끝은 카운터 판정'),
        'mark':(350,150,'실패 결과 0 → 불량 표시','원본 op 7 요청'),
        'retry':(20,150,'다음 물리 후보','같은 논리 블록 · 같은 데이터')},
        [('input','program',False),('program','success',True),('success','next',False),('program','mark',True),('mark','retry',False),('retry','input',False)],250,
        '점선은 모델이 공급한 기록 결과입니다. 호출자의 재시도와 입력 진행 분기는 원본 코드가 수행합니다.','burn-continuation.json')
    # The shared diagram helper assumes downward vertical edges; keep this return arrow between boxes.
    v['retry_graph']=v['retry_graph'].replace('d="M155 222 L155 10"','d="M155 150 L155 82"')
    v['protect_graph']=graph('burn-protect','후보 소진 사례의 원본 판정',{
        'fail':(20,10,'블록 0 기록 실패','합성 결과 0 · 맵 x'),
        'bad':(350,10,'블록 1~639 불량','spare +5 = 0 → 맵 B'),
        'protect':(700,10,'블록 640~1023 보호','원본 반환 1 × 384'),
        'return':(350,150,'BurnNand 반환 1','추가 기록 호출 없음'),
        'exhaust':(700,150,'후보 1024 / 소진','0x80014890'),
        'scope':(20,150,'합성 설치 헤더의 범위','실물 보호 구간과 구분')},
        [('fail','bad',False),('bad','protect',False),('protect','exhaust',False),('exhaust','return',False)],250,
        '카드 콜백 실패 사례도 반환 1을 관측했습니다. 이 값을 업데이트 성공으로 해석하지 않습니다.','burn-continuation.json')
    v['payload_graph']=graph('burn-payload','주 페이로드에서 다음 기록 요청까지',{
        's1':(20,10,'섹션 1 / 10청크','각 128 KiB'),
        's2':(350,10,'섹션 2 / 125청크','모두 성공인 합성 결과'),
        'direct':(700,10,'별도 op 5 요청','sector 0xa00 · count 4'),
        'patch0':(20,150,'블록 0 변경 281바이트','앞선 헤더 쓰기 분석과 일치'),
        'patch10':(350,150,'블록 10 변경 512바이트','나머지 133청크는 원본과 같음'),
        'boundary':(700,150,'저장장치 진입점에서 중단','op 5 처리 · 최종 성공 미검증')},
        [('s1','s2',False),('s2','direct',False),('direct','boundary',True)],250,
        '135개 기록은 기록 함수의 결과를 공급한 호출자 실행입니다. 135개 물리 기록·읽기 비교를 수행한 것이 아닙니다.','burn-continuation.json')
    v['rows']=''.join(f'<tr><th>{esc(r["name"])}</th><td>{r["aggregate_program_calls"]}</td><td>{r["modeled_card_reads"]}</td><td>{r["protection_skip_count"]}</td><td><code>{r["stop"]}</code></td><td>{r["return_value"] if r["return_value"] is not None else "반환 전"}</td></tr>' for r in data['bounded_replay']['cases'])
    v['words']=str(len(list(witnesses(data))))
    v['k3_commit']=data['comparison']['commit']
    page=(ROOT/'analysis/continuation-template.html').read_text(encoding='utf-8')
    for k,value in v.items(): page=page.replace('{{'+k+'}}',value)
    assert '{{' not in page
    (ROOT/'burn-continuation-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built burn-continuation-report.html')


def build_raster():
    data=read('colorspace-raster.json')
    v={k:esc(t) for k,t in read('raster-copy.json').items()}
    v['branch_graph']=graph('raster-branch','변환한 폭과 x 좌표로 경로를 선택한다',{
        'word':(20,10,'폭 %32 == 0 · x 짝수','word 루프 / 0x8043ecfc'),
        'input':(350,10,'DrawShape_Line / style 0','원본 좌표 변환 후 분기'),
        'half':(700,10,'그 밖: 폭 %16 == 0 · x 짝수','halfword / 0x8043ed94'),
        'gdi':(350,150,'나머지 → GDI 채우기','홀수 x · 폭 4 · 폭 712 등'),
        'wordcase':(20,150,'32×2 사례 → 64바이트','높이 0 사례 → 쓰기 없음'),
        'halfcase':(700,150,'강조의 위·아래 폭 720','두 직접 쓰기 패스')},
        [('input','word',False),('input','half',False),('input','gdi',False),('word','wordcase',False),('half','halfcase',False)],250,
        '폭 32의 배수인 조건을 먼저 평가합니다. 이 재현은 좌표 배율을 0으로 초기화해 항등 변환 경로를 사용합니다.','colorspace-raster.json')
    v['context_graph']=graph('raster-context','원본 컨텍스트에서 8비트 간접 채우기까지',{
        'create':(20,10,'GdiCreateDisplayContextEx','원본 sDcOsd8 템플릿 복사'),
        'bitmap':(350,10,'비트맵 생성 · 선택','합성 736×176 / 8비트'),
        'binding':(700,10,'기본 컨텍스트 = ID17 조회','시험 도구가 연결'),
        'fill':(20,150,'8비트 FillRect 0x80225820','원본 clipping → memset'),
        'indirect':(350,150,'GDI 채우기 간접 호출','context +0x880'),
        'brush':(700,150,'원본 브러시 설정 · 도형 0','동일 컨텍스트에 적용')},
        [('create','bitmap',False),('bitmap','binding',True),('binding','brush',True),('brush','indirect',False),('indirect','fill',False)],250,
        '점선은 합성 연결 조건입니다. 기본 포인터가 0인 fallback은 정적으로만 확인했으며 카메라의 초기화 상태를 뜻하지 않습니다.','colorspace-raster.json')
    v['coverage_graph']=graph('raster-coverage','현재 확인한 픽셀과 남은 출력 경계',{
        'ui':(20,10,'이전 원본 UI 갱신','다섯 도형 인수 관측'),
        'raster':(350,10,'이번 원본 도형 실행','각 요청 뒤 전체 RAM 대조'),
        'indices':(700,10,'인덱스 픽셀 일치','두 위치 / 각 34,560바이트'),
        'glyph':(20,150,'텍스트 글리프','리소스 · 간접 함수 연결 필요'),
        'palette':(350,150,'실제 RGB 팔레트','인덱스와 RGB를 구분'),
        'lcd':(700,150,'DMA · LCD','장치 출력 미검증')},
        [('ui','raster',True),('raster','indices',False)],250,
        '점선은 이전 실행의 인수를 이번 시험에 전달했다는 뜻입니다. 전체 화면 생산자부터 픽셀까지 하나의 연속 실행은 아직 없습니다.','colorspace-raster.json')
    v['rows']=''.join(f'<tr><th>{esc(r["name"])}</th><td>{" → ".join(s["branch"] for s in r["steps"])}</td><td>{r["steps"][-1]["changed_bytes"]:,}</td><td><code>{r["steps"][-1]["frame_sha256"][:16]}…</code></td></tr>' for r in data['replay']['cases'])
    v['boundaries']=''.join(f'<tr><th><code>{pc}</code></th><td>{esc(text)}</td></tr>' for pc,text in data['replay']['modeled_boundaries'].items())
    v['words']=str(len(list(witnesses(data))))
    v['k3_commit']=data['comparison'][0]['commit']
    page=(ROOT/'analysis/raster-template.html').read_text(encoding='utf-8')
    for k,value in v.items(): page=page.replace('{{'+k+'}}',value)
    assert '{{' not in page
    (ROOT/'colorspace-raster-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built colorspace-raster-report.html')


if __name__=='__main__':
    build_burn()
    build_raster()
