"""Build the Q7 Color Space UI report from evidence and reviewed Korean copy."""
from build_deep_report import ROOT, read, esc
from build_routing_report import graph


def main():
    ui = read('colorspace-ui.json')
    v = {k: esc(t) for k, t in read('colorspace-copy.json').items()}
    v['entry_graph'] = graph('ui-entry', '색공간 화면의 이벤트와 설정 경로', {
        'event': (20,10,'E3 행 + 이벤트 12','0x80a438f4'),
        'mode': (350,10,'모드 0x53 진입','26개 GUI 컴포넌트'),
        'focus': (700,10,'캔버스 키 9 / 10','다른 선택지 활성화'),
        'listener': (700,150,'포커스 콜백','0x80a84f88'),
        'setter': (350,150,'설정 ID 0xd7 쓰기','sRGB 0 / AdobeRGB 1'),
        'ram': (20,150,'설정 RAM 1바이트','0x8153ca43')},
        [('event','mode',False),('mode','focus',False),('focus','listener',False),('listener','setter',False),('setter','ram',False)],250,
        '실선은 이 합성 실행에서 호출한 원본 코드입니다. 물리 버튼, RTOS 큐와 표시 장치는 모델 경계 밖입니다.','colorspace-ui.json')
    v['state_graph'] = graph('ui-state', '현재값과 백업값의 변화', {
        'open': (20,10,'열기: 현재값 → 백업','초기 포커스도 1회 쓰기'),
        'choose': (350,10,'선택: 현재값 즉시 변경','백업은 유지'),
        'confirm': (700,10,'확정: 현재값 유지','추가 쓰기 0회'),
        'cancel': (350,150,'취소: 백업 → 현재값','복원 쓰기 1회'),
        'reopen': (700,150,'다시 열기','유지·복원값으로 활성화')},
        [('open','choose',False),('choose','confirm',False),('choose','cancel',False),('confirm','reopen',False),('cancel','reopen',False)],250,
        '같은 값 확정 사례는 선택 단계가 없습니다. 다시 열 때 초기 포커스가 같은 값을 한 번 더 씁니다.','colorspace-ui.json')
    v['render_graph'] = graph('ui-render', '위젯 리소스에서 문자열 출력까지', {
        'table': (20,10,'위젯 테이블 0x8080753c','16바이트 레코드'),
        'labels': (350,10,'type 9 문자열 라벨','언어별 포인터 배열'),
        'write': (700,10,'WriteStringInfo','0x80ad2254 / 정적 추적'),
        'active': (20,150,'선택 캔버스 활성화','표식·안내 가시성'),
        'locale': (350,150,'로케일 + 글꼴·문자','ResourceString 계열'),
        'pixel': (700,150,'래스터 → 화면 합성','최종 픽셀은 미검증')},
        [('table','labels',False),('labels','write',True),('table','active',False),('write','locale',True),('locale','pixel',True)],250,
        '점선은 정적 연결 또는 미실행 경로입니다. 실제 라벨 생성과 포커스만 재실행했으며 화면 픽셀은 만들지 않았습니다.','colorspace-ui.json')
    v['cases'] = ''.join('<tr><th>'+esc(c['case'])+'</th><td>'+str(c['initial'])+' → '+str(c['selected'])+'</td><td>'+str(c['steps'][-1]['getter'])+'</td><td>'+str(sum(len(s['setting_byte_stores']) for s in c['steps']))+'</td></tr>' for c in ui['replay']['cases'])
    v['labels'] = ''.join(f'<tr><th>{esc(r["role"])}</th><td>{r["widget"]}</td><td>{r["language_table"]}</td></tr>' for r in ui['rendering']['labels'])
    v['hooks'] = ''.join(f'<tr><th><code>{a}</code></th><td>{esc(t)}</td></tr>' for a,t in ui['replay']['modeled_boundaries'].items())
    v['k3_commit'] = ui['sources']['semantic_contract']['commit']
    page = (ROOT/'analysis/colorspace-template.html').read_text(encoding='utf-8')
    for key,value in v.items():
        page = page.replace('{{'+key+'}}',value)
    assert '{{' not in page
    (ROOT/'colorspace-ui-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built colorspace-ui-report.html')


if __name__ == '__main__':
    main()
