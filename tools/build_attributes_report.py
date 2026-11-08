"""Render captured font attributes and the separately configured scaled draw."""
from build_deep_report import ROOT, read, esc
from build_routing_report import graph


def main():
    data = read('colorspace-attributes.json')
    values = {k:esc(v) for k,v in read('attributes-copy.json').items()}
    values.update({k:esc(v) for k,v in read('binding-copy.json').items()})
    values['binding_graph'] = graph('context-binding','등록 슬롯에 따른 원본 선택 결과',{
        'present':(20,10,'다음 슬롯에 컨텍스트 있음','시험 ID18 → 컨텍스트 B'),
        'write':(350,10,'원본 활성 포인터 쓰기','0x8024a614 → 0x800eb4d8'),
        'new':(700,10,'속성·텍스트 모두 B','GDI 본문은 관측 모델'),
        'missing':(20,150,'다음 슬롯이 비어 있음','화면 draw ID는 18로 교체'),
        'retain':(350,150,'활성 포인터 쓰기 없음','이전 컨텍스트 A 유지'),
        'old':(700,150,'속성 대체·텍스트 모두 A','등록·할당 성공은 별도 조건')},
        [('present','write',False),('write','new',False),('missing','retain',False),('retain','old',False)],250,
        '서로 다른 컨텍스트를 등록한 합성 시험입니다. 원본 선택·교체·조회만 실행하고 GDI 본문에서 멈춥니다. 실제 카메라의 ID17·18 할당이나 픽셀 출력은 입증하지 않습니다.','context-binding.json')
    values['boundary_graph'] = graph('attributes-boundary','캡처와 별도 재입력의 경계',{
        'refresh':(20,10,'원본 갱신 4회','속성 72건 · 텍스트 25건'),
        'capture':(350,10,'요청 캡처 모델','sRGB: 48×48 / 간격 0 / 색 2'),
        'alias':(700,10,'별도 합성 컨텍스트','ID17 = 기본 ID0 가정'),
        'set':(20,150,'원본 속성 분기·setter','종류 7 → 12 → 4 적용'),
        'draw':(350,150,'원본 텍스트·축소 렌더러','context+0x894 → StretchBlitFont'),
        'frame':(700,150,'전체 합성 인덱스 프레임','129,536바이트 + 양끝 보호')},
        [('refresh','capture',False),('capture','alias',True),('alias','set',True),('set','draw',False),('draw','frame',False)],250,
        '점선은 별도 재입력과 합성 ID 연결입니다. 실제 UI 상태를 이어 실행한 도식이 아닙니다. 글꼴 파일과 메모리·운영체제 경계는 별도 목록의 모델을 사용합니다.','colorspace-attributes.json')
    values['dispatch_graph'] = graph('attributes-dispatch','크기 설정에 따른 원본 렌더러 분기',{
        'default':(20,10,'기본 크기 64×48','속성 적용 전 대조 실행'),
        'plain':(350,10,'context+0x88c','BlitFont 0x8022607c'),
        'original':(700,10,'첫 글리프 폭 24','렌더러 진입에서 정지'),
        'configured':(20,150,'요청 크기 48×48','캡처 속성 별도 적용'),
        'stretch':(350,150,'context+0x894','StretchBlitFont 0x80226748'),
        'scaled':(700,150,'첫 글리프 24 → 18','전체 축소 실행은 별도 검증')},
        [('default','plain',False),('plain','original',False),('configured','stretch',False),('stretch','scaled',False)],250,
        '두 대조 실행은 첫 렌더러까지 각각 114 VEX 블록 이벤트입니다. 아래 조건의 전체 실행은 68,969 이벤트이며 실제 실행 시간 측정은 아닙니다.','colorspace-attributes.json')
    values['rows'] = ''.join(f'<tr><th>{r["kind"]}</th><td><code>{r["table_word"]}</code></td><td><code>{r["callee"]}</code></td><td>{esc("; ".join(r["writes"]))}</td></tr>' for r in data['attribute_dispatch'])
    values['frame_sha'] = data['bounded_replay']['scaled']['frame_sha256']
    values['k3_commit'] = read('colorspace-glyph.json')['comparison'][0]['commit']
    page = (ROOT/'analysis/attributes-template.html').read_text(encoding='utf-8')
    for key,value in values.items():
        page = page.replace('{{'+key+'}}',value)
    assert '{{' not in page
    (ROOT/'colorspace-attributes-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built colorspace-attributes-report.html')


if __name__ == '__main__':
    main()
