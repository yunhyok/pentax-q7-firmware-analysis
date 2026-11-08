"""Render the font-loading and indexed glyph evidence."""
from build_deep_report import ROOT, read, esc
from build_routing_report import graph
from verify_routing import witnesses


def main():
    data = read('colorspace-glyph.json')
    v = {key:esc(value) for key,value in read('glyph-copy.json').items()}
    v['pipeline_graph'] = graph('glyph-pipeline','파일과 텍스트가 원본 글리프 렌더러에서 만난다',{
        'file':(20,10,'FAT16 / LatinFont','130,886바이트 · 체인과 해시'),
        'load':(350,10,'DirectLoadFontEx','파일 읽기는 원본 바이트 모델'),
        'font':(700,10,'GdiCreateFont / type 0x202','오프셋 재배치 · 함수 테이블'),
        'input':(20,150,'앞선 sRGB 요청으로 재진입','AppDBTextOutByBufferID'),
        'convert':(350,150,'변환 → 글꼴 간접 호출','0x8022968c → 0x8022c058'),
        'pixels':(700,150,'8비트 글리프 렌더러','context+0x88c → 인덱스 RAM')},
        [('file','load',True),('load','font',False),('font','pixels',False),('input','convert',False),('convert','pixels',False)],250,
        '점선은 원본 파일 바이트를 공급하는 모델입니다. 화면 생산자 전체는 재진입 이전의 별도 검증입니다.','colorspace-glyph.json')
    v['packing_graph'] = graph('glyph-packing','2비트 코드와 이번 컨텍스트의 인덱스',{
        'source':(20,10,'64×48 셀 / 행당 16바이트','바이트 상위 2비트부터 읽기'),
        'codes':(350,10,'코드 0 · 1 · 2 · 3','0은 기존 픽셀 보존'),
        'indices':(700,10,'보존 · 2 · 1 · 3','RGB 팔레트 값은 미확정')},
        [('source','codes',False),('codes','indices',False)],115,
        '각 글리프는 폭 테이블의 유효 폭만 씁니다. 두 사례에서 코드 1·2의 픽셀을 관측했고 코드 3 매핑은 원본 경로와 합성 oracle 테스트로 대조했습니다.','colorspace-glyph.json')
    v['rows'] = ''.join(f'<tr><th>{"텍스트 요청 4단위" if len(c["units"])==4 else "직접 글리프 1단위"}</th><td><code>{c["entry"]}</code></td><td>{c["changed_bytes"]:,}</td><td>{c["vex_block_events"]:,}</td><td><code>{c["frame_sha256"][:16]}…</code></td></tr>' for c in data['bounded_replay']['cases'])
    v['words'] = str(len(list(witnesses(data))))
    v['functions'] = str(len(data['selected_functions']))
    v['boundaries'] = ''.join(f'<tr><th>{esc(stage)}</th><td><code>{pc}</code></td><td>{esc(description)}</td></tr>' for stage,apis in data['bounded_replay']['modeled_boundaries'].items() for pc,description in apis.items())
    v['k3_commit'] = data['comparison'][0]['commit']
    page = (ROOT/'analysis/glyph-template.html').read_text(encoding='utf-8')
    for key,value in v.items():
        page = page.replace('{{'+key+'}}',value)
    assert '{{' not in page
    (ROOT/'colorspace-glyph-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built colorspace-glyph-report.html')


if __name__ == '__main__':
    main()
