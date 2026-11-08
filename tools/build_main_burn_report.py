"""Render two separately initialized MAIN updater prefix experiments."""
from build_deep_report import ROOT, read, esc
from build_routing_report import graph


def main():
    data = read('main-burn-prefix.json')
    values = {k:esc(v) for k,v in read('main-burn-copy.json').items()}
    values['open_graph'] = graph('main-open','원본 매체 열기에서 첫 NAND 요청까지',{
        'burn':(20,10,'MAIN Burn / 매체 초기화','타입 1 · 플래그 2'),
        'filex':(350,10,'원본 FileX 열기·드라이버','요청 4 → TlMediaInit'),
        'nand':(700,10,'NAND op 2 진입 직전','0x80053124 · 응답 없음')},
        [('burn','filex',False),('filex','nand',False)],115,
        '합성 뮤텍스·빈 상태에서 원본 경로를 실행했습니다. 281 VEX 블록 이벤트 뒤 정지하며, 장치 본문과 HostAck·BurnNand는 실행하지 않습니다.','main-burn-prefix.json')
    values['header_graph'] = graph('main-installed','별도 매체 모델에서 헤더와 카드 읽기 요청까지',{
        'model':(20,10,'열기·기하 모델','0xf1 · 256 / 262144 섹터'),
        'burn':(350,10,'원본 HostAck → BurnNand','0x805e1a00 → 0x805dd7b8'),
        'header':(700,10,'원본 설치 헤더 선택','selector 0 · 일반 헤더'),
        'spare':(20,150,'op 6 요청 / 모델 응답','섹터 0 / 1개 · 16바이트 FF'),
        'data':(350,150,'op 4 요청 / 모델 응답','섹터 0 / 3개 · 합성 헤더'),
        'card':(700,150,'원본 Read → FileX 진입','0x20000바이트 요청 뒤 정지')},
        [('model','burn',True),('burn','header',False),('header','spare',False),('spare','data',True),('data','card',True)],250,
        '첫 op 6 요청까지 134, 첫 카드 FileX 진입까지 누적 156 VEX 블록 이벤트입니다. 점선은 공급한 모델 결과가 다음 원본 경로를 열어 주는 부분입니다. 앞 도식과 이어 실행하지 않습니다.','main-burn-prefix.json')
    values['boundaries'] = ''.join(f'<tr><th>{esc(mode)}</th><td><code>{pc}</code></td><td>{esc(role)}</td></tr>' for mode,apis in data['bounded_replay']['modeled_apis'].items() for pc,role in apis.items())
    values['k3_commit'] = read('update-service.json')['comparison']['commit']
    page = (ROOT/'analysis/main-burn-template.html').read_text(encoding='utf-8')
    for key,value in values.items():
        page = page.replace('{{'+key+'}}',value)
    assert '{{' not in page
    (ROOT/'main-burn-prefix-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built main-burn-prefix-report.html')


if __name__ == '__main__':
    main()
