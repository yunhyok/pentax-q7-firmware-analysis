"""Render the offline rebuild, AF foundation and UI-boundary report."""
from build_deep_report import ROOT, read, esc
from build_routing_report import graph


def main():
    values={k:esc(v) for k,v in read('implementation-copy.json').items()}
    values['rebuild_graph']=graph('rebuild-boundaries','재생성에서 실기 부팅까지의 검증 경계',{
        'decode':(20,10,'448 압축 블록 복원','원본 SHA-256 고정'),
        'pack':(350,10,'동일 토큰 / 제한된 변경','블록 위치·크기 유지'),
        'verify':(700,10,'전체 재복원 + 코드 실행','변경된 함수: 0 → 1'),
        'footer':(20,150,'앱 파일 검사','3 식별자 + 바이트 합'),
        'burn':(350,150,'E01 BurnGetHandle','kind 3 → BurnNand'),
        'camera':(700,150,'기록·부팅·촬영','실기 미검증')},
        [('decode','pack',False),('pack','verify',False),('footer','burn',True),('burn','camera',True)],250,
        '위 행은 실제 수행한 오프라인 재생성입니다. 아래 행은 별도로 조사한 업데이트 단계이며, 점선 구간을 전체 실행한 것은 아닙니다. 분석용 ELF는 카메라 업데이트 파일이 아닙니다.','rebuild-evidence.json')
    values['af_graph']=graph('af-foundation','AF 추정값과 기존 렌즈 제어 경계',{
        'samples':(20,10,'위치 i32 / 대비 float32','CalcFocus의 샘플 창'),
        'fit':(350,10,'Approximation 0x8037d704','전역 scratch / 위치 추정'),
        'correct':(700,10,'호출자 보정·유효성 조건','iFocusPos / 렌즈 위치'),
        'drive':(20,150,'LensDriveControl','mode / speed / delta'),
        'policy':(350,150,'렌즈 제한·큐·VD 조건','검색·정지·위치 이동'),
        'command':(700,150,'LensCommunication','응답·실기 구동은 별도')},
        [('samples','fit',False),('fit','correct',False),('drive','policy',False),('policy','command',False)],250,
        '계산 단계와 명령 단계를 나누어 표시했습니다. CalcFocus의 후속 보정은 mode 2 구동 요청으로 이어집니다. 입력 유형, 렌즈 정책 및 완료 경로를 확보하는 기반 연구이며 AF 패치를 적용하지 않았습니다.','portability-evidence.json')
    values['ui_graph']=graph('ui-boundaries','Q7 화면 자원과 메뉴의 연결',{
        'input':(20,10,'4-way · e-dial · OK · MENU','Q7 물리 입력'),
        'canvas':(350,10,'Canvas / Popup / 설정 ID','상태·포커스·명령'),
        'resources':(700,10,'아이콘 + 문자열·폰트','서로 다른 자원 경로'),
        'icon':(20,150,'RLE 또는 Zoran bank','ID / geometry / cache'),
        'draw':(350,150,'LCD indexed draw','투명 0 / recolor 규칙'),
        'osd':(700,150,'OSD buffer + palette','실제 LCD 출력 미검증')},
        [('input','canvas',False),('canvas','resources',False),('icon','draw',False),('draw','osd',False)],250,
        '아래 행은 검증한 아이콘 경로입니다. 전체 GUI 상태 전이나 Zoran 디코더, 실제 화면 갱신은 재실행 범위에 포함하지 않았습니다.','portability-evidence.json')
    p=read('portability-evidence.json')
    values['geometry_rows']=''.join(f'<tr><th>{r["icon_id"]}</th><td>{r["layout_width"]} × {r["height"]}</td><td>{r["data_width"]}</td></tr>' for r in p['replay']['geometry']['icon_sizes'])
    values['k3_commit']=p['comparison']['k3_artifact_reference_commit']
    page=(ROOT/'analysis/implementation-template.html').read_text(encoding='utf-8')
    for key,value in values.items(): page=page.replace('{{'+key+'}}',value)
    assert '{{' not in page
    (ROOT/'implementation-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built implementation-report.html')


if __name__=='__main__': main()
