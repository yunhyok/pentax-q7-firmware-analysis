"""Render the selection-highlight raster report."""
from build_deep_report import ROOT, read, esc
from build_routing_report import graph
from verify_routing import witnesses


def main():
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


if __name__ == '__main__':
    main()
