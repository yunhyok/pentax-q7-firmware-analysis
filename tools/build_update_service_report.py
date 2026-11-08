"""Render the distinct MAIN updater bridge and its bounded return semantics."""
from build_deep_report import ROOT, read, esc
from build_routing_report import graph


def main():
    data = read('update-service.json')
    values = {k:esc(v) for k,v in read('update-service-copy.json').items()}
    values['namespace_graph'] = graph('update-namespace','메인 업데이트 경로와 E01은 별개 구현',{
        'main':(20,10,'MAIN DownloadCard','0x805e10ac · 원본 헤더 읽기'),
        'handle':(350,10,'MAIN BurnGetHandle','+0xca4 → 0x805dd7b8'),
        'burn':(700,10,'MAIN Burn / BurnNand','Burn 진입에서 모델로 대체'),
        'boot':(20,150,'E01 DownloadCard','별도 ELF 주소 공간'),
        'old':(350,150,'E01 BurnGetHandle','+0x1254 → 0x80012654'),
        'terminal':(700,150,'E01 NAND 종료 재현','앞선 보고서의 별도 사례')},
        [('main','handle',False),('handle','burn',True),('boot','old',False),('old','terminal',True)],250,
        '상단은 이번 메인 경로, 하단은 앞선 E01 근거입니다. 점선은 별도 재현이나 모델 경계입니다. 두 행을 잇는 실행 전환을 확인한 도식이 아닙니다.','update-service.json')
    values['return_graph'] = graph('update-returns','하위 상태와 상위 반환값은 다르다',{
        'ok':(20,10,'Burn 모델 → 0','DownloadCard 원본 반환 1'),
        'okmap':(350,10,'I43 원본 반환 0','결과는 로그 인수로 전달'),
        'okret':(700,10,'동기 래퍼 반환 1','updating = 0'),
        'err':(20,150,'Burn 모델 → 7','DownloadCard 원본 반환 0'),
        'errmap':(350,150,'I43 원본 반환 254','결과는 로그 인수로 전달'),
        'errret':(700,150,'동기 래퍼 반환 1','updating = 0')},
        [('ok','okmap',False),('okmap','okret',False),('err','errmap',False),('errmap','errret',False)],250,
        '백업 플래그 0인 합성 상태에서 원본 래퍼를 실행한 결과입니다. Burn 본문·저장장치와 실제 업데이트 성공을 검증한 결과가 아닙니다.','update-service.json')
    values['boundaries'] = ''.join(f'<tr><th>{esc(stage)}</th><td><code>{pc}</code></td><td>{esc(label)}</td></tr>' for stage,apis in data['modeled_boundaries'].items() for pc,label in apis.items())
    values['k3_commit'] = data['comparison']['commit']
    page = (ROOT/'analysis/update-service-template.html').read_text(encoding='utf-8')
    for key,value in values.items():
        page = page.replace('{{'+key+'}}',value)
    assert '{{' not in page
    (ROOT/'update-service-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built update-service-report.html')


if __name__ == '__main__':
    main()
