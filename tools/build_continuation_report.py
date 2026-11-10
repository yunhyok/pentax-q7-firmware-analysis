"""Render NAND retry and indexed shape raster follow-up reports."""
from build_deep_report import ROOT, read, esc
from build_routing_report import graph
from verify_routing import witnesses


def build_burn():
    data=read('burn-continuation.json')
    terminal=read('burn-finalization.json')
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
        'boundary':(700,150,'저장장치 진입점의 상태','아래 종료 4사례의 시작점')},
        [('s1','s2',False),('s2','direct',False),('direct','boundary',True)],250,
        '135개 기록은 기록 함수의 결과를 공급한 호출자 실행입니다. 135개 물리 기록·읽기 비교를 수행한 것이 아닙니다.','burn-continuation.json')
    v['rows']=''.join(f'<tr><th>{esc(r["name"])}</th><td>{r["aggregate_program_calls"]}</td><td>{r["modeled_card_reads"]}</td><td>{r["protection_skip_count"]}</td><td><code>{r["stop"]}</code></td><td>{r["return_value"] if r["return_value"] is not None else "반환 전"}</td></tr>' for r in data['bounded_replay']['cases'])
    v['terminal_graph']=graph('burn-terminal','모든 저장장치 상태가 0일 때의 원본 요청 순서',{
        'extended':(20,10,'op 5 확장 헤더 쓰기','sector 0xa00 · 4섹터'),
        'read':(350,10,'op 4 블록 0 읽기','256섹터 · 모델이 데이터 제공'),
        'erase':(700,10,'op 8 블록 0 지우기','블록 1개'),
        'done':(20,150,'BurnNand 반환 0','콜백 1을 원본에서 변환'),
        'ready':(350,150,'해제 → 준비 콜백','원본 0x80019390 반환 1'),
        'write':(700,150,'op 5 블록 0 재기록','256섹터 · spare 16바이트')},
        [('extended','read',True),('read','erase',True),('erase','write',True),('write','ready',True),('ready','done',False)],250,
        '점선 구간의 장치 응답은 모델입니다. 세 오류 사례는 준비 콜백 없이 반환 1로 종료합니다.','burn-finalization.json')
    v['primary_graph']=graph('burn-primary','최종 128 KiB 버퍼의 독립 재구성',{
        'input':(20,10,'앞선 블록 0 기록 인수','전체 데이터 · spare를 보관'),
        'patch':(350,10,'원본 store 0x80014874','+0x39c: 0xffffffff → 10'),
        'output':(700,10,'131,072바이트 전체 일치','변경 4바이트 · spare 동일')},
        [('input','patch',True),('patch','output',False)],115,
        '읽기 모델은 보관한 바이트를 공급합니다. 실제 NAND의 기록 보존을 측정한 것이 아닙니다.','burn-finalization.json')
    v['terminal_rows']=''.join(f'<tr><th>{esc(r["name"])}</th><td>{len(r["requests"])}</td><td>{len(r["native_ready_callers"])}</td><td>{r["return_value"]}</td></tr>' for r in terminal['bounded_replay']['cases'])
    v['words']=str(len(list(witnesses(data))))
    v['k3_commit']=data['comparison']['commit']
    page=(ROOT/'analysis/continuation-template.html').read_text(encoding='utf-8')
    for k,value in v.items(): page=page.replace('{{'+k+'}}',value)
    assert '{{' not in page
    (ROOT/'burn-continuation-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built burn-continuation-report.html')


if __name__=='__main__':
    build_burn()
