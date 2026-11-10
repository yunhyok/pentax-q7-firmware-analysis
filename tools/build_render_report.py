"""Render the Color Space draw-path report."""
from build_deep_report import ROOT, read, esc
from build_routing_report import graph


def main():
    data=read('colorspace-render.json')
    v={k:esc(t) for k,t in read('render-copy.json').items()}
    v['refresh_graph']=graph('render-refresh','큐 요청에서 두 쓰기 패스까지',{
        'request':(20,10,'UiService_Refresh(1)','0x80ae00f0'),
        'send':(350,10,'원본 SendRequest','[0x80, 1, 0, 0]'),
        'receive':(700,10,'원본 Perform 소비자','큐 전달·동기화는 모델'),
        'write':(20,150,'GuiComponent_Write','쓰기 패스 0, 이어서 1'),
        'update':(350,150,'위젯 갱신·전체 그리기','현재 선택의 active list'),
        'refresh':(700,150,'UiService_DoRefresh(3)','0x80adf978의 호출')},
        [('request','send',False),('send','receive',True),('receive','refresh',False),('refresh','update',False),('update','write',False)],250,
        '한 메시지를 한 번 소비하고 중단합니다. 모델 경계 전체는 R1 replay.modeled_boundaries에 열거했습니다.','colorspace-render.json')
    v['pixel_graph']=graph('render-pixels','텍스트와 선택 아이콘의 서로 다른 도달점',{
        'locale':(20,10,'원본 언어·줄 descriptor','단위당 2바이트 / 25줄'),
        'text':(350,10,'텍스트 API','좌표·길이·해시 관측'),
        'glyph':(700,10,'GDI / 간접 글꼴 렌더러','글리프 픽셀 미실행'),
        'rle':(20,150,'선택 아이콘 RLE 원본','296 → 1,008바이트'),
        'indices':(350,150,'인덱스 픽셀 직접 쓰기','0이 아닌 330바이트 / 사례'),
        'ram':(700,150,'합성 버퍼 전체 대조','2위치 / 보호 바이트 유지')},
        [('locale','text',False),('text','glyph',True),('rle','indices',False),('indices','ram',False)],250,
        '윗줄은 텍스트 요청, 아랫줄은 별도로 실행한 아이콘 그리기입니다. 아이콘 검증을 전체 화면 검증으로 확대하지 않았습니다.','colorspace-render.json')
    v['buffer_graph']=graph('render-buffer','표시 버퍼 요청과 물리 출력 경계',{
        'update':(20,10,'ScreenControl_Update','원본 코드 실행'),
        'roll':(350,10,'ScreenOsdLayer_Roll','캐시 요청 · draw/show 교대'),
        'request':(700,10,'표시 버퍼 지정 요청','합성 ID 17 ↔ 18'),
        'context':(20,150,'표시 컨텍스트 선택','정적 연결만 확인'),
        'layer':(350,150,'LayerSetFrameBuffer / Move','0x800442f8 / 0x80044370'),
        'lcd':(700,150,'DMA / LCD','실제 픽셀 출력 미검증')},
        [('update','roll',False),('roll','request',False),('context','layer',True),('layer','lcd',True)],250,
        '첫 행은 실행에서 관측한 요청, 둘째 행은 그 이후의 정적 연결과 미검증 장치 경계입니다.','colorspace-render.json')
    v['geometry']=('''<figure><div class="diagram-wrap"><svg class="diagram" viewBox="0 0 1000 235" role="img" aria-labelledby="focus-title focus-desc"><title id="focus-title">다섯 부분으로 만든 선택 강조 영역</title><desc id="focus-desc">논리 폭720 높이48. 위와 왼쪽 인덱스4d, 아래와 오른쪽4f, 안쪽4e. 설명용 세로 확대이며 실제 팔레트 RGB가 아니다.</desc><rect class="node" x="20" y="24" width="720" height="120"/><rect x="20" y="24" width="720" height="15" fill="#798ea8"/><rect x="20" y="24" width="10" height="110" fill="#798ea8"/><rect x="20" y="134" width="720" height="10" fill="#d5a775"/><rect x="730" y="34" width="10" height="110" fill="#d5a775"/><rect x="30" y="34" width="700" height="100" fill="#294757"/><text class="label" x="45" y="70">내부: [4, y+4, 712, 40, 0x4e]</text><text class="label" x="45" y="101">옵션 문구: (96, y) · y = 64 또는 112</text><text class="label" x="760" y="55">위·왼쪽 0x4d</text><text class="label" x="760" y="87">아래·오른쪽 0x4f</text><text class="sub" x="20" y="177">실제 요청: 위 720×6 / 왼쪽 4×44 / 아래 720×4 / 오른쪽 4×44 / 내부 712×40</text><text class="sub" x="20" y="205">설명용 배색·세로 확대. 팔레트의 실제 RGB와 최종 도형 픽셀은 미검증.</text></svg></div><figcaption>좌표·팔레트 인덱스의 재구성 도식. <a href="analysis/colorspace-render.json">[R1: frame_commands]</a></figcaption></figure>''')
    v['rows']=''.join(f'<tr><th>{i+1}</th><td>{"영어" if r["locale"]==0 else "프랑스어"}</td><td>{"sRGB" if r["setting"]==0 else "AdobeRGB"}</td><td>{len(r["text"])}</td><td>{r["draw_before"]} → {r["draw_after"]}</td><td>{r["show_before"]} → {r["show_after"]}</td></tr>' for i,r in enumerate(data['replay']['refresh_cases']))
    v['k3_commit']=data['references'][1]['commit']
    page=(ROOT/'analysis/render-template.html').read_text(encoding='utf-8')
    for k,value in v.items():page=page.replace('{{'+k+'}}',value)
    assert '{{' not in page
    (ROOT/'colorspace-render-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built colorspace-render-report.html')


if __name__ == '__main__':
    main()
