"""Render AF request, cached completion and sequence-stop boundaries."""
from build_deep_report import ROOT, read, esc
from build_routing_report import graph


def main():
    data=read('af-completion.json')
    v={k:esc(t) for k,t in read('af-copy.json').items()}
    v['route_graph']=graph('af-route','AF 요청과 렌즈 작업자의 반환 경로',{
        'drive':(20,10,'LensDriveControl','0x8037eb78 → 알림 0x6003c'),
        'capture':(350,10,'원본 캡처 수신자','점프 테이블 → ExecuteFocusControl'),
        'set':(700,10,'검색 / 정지 setter','pending 설정 · 메시지 6 / 8'),
        'result':(20,150,'결과 기록 · pending 해제','바깥 수신자 반환 1과 구분'),
        'link':(350,150,'원본 LensCommunication','허용 맵 → 길이·모드 → 하위 API'),
        'worker':(700,150,'원본 LensComThreadMain','한 메시지 소비 후 중단')},
        [('drive','capture',False),('capture','set',False),('set','worker',True),('worker','link',False),('link','result',False)],250,
        '점선: 제출된 메시지와 렌즈 RAM을 옮기는 직렬화 모델. 하위 API 응답도 합성 값입니다.','af-completion.json')
    v['state_graph']=graph('af-state','캐시 기반 완료의 두 단계',{
        'arm':(20,10,'검색 후 request+1 == 1','setter 7 / 4 / 6에도 대기 설정'),
        'one':(350,10,'상태 1 / 시작 확인','motion==1 또는 count≥6 / 우회'),
        'two':(700,10,'상태 2 / 종료 확인','motion==0일 때만 완료'),
        'done':(700,150,'상태 0 · 완료 알림 두 개','0x6003f / 0x10060032'),
        'valid':(350,150,'getter의 별도 유효성 반환','이 콜백의 조건에 사용하지 않음'),
        'zero':(20,150,'정기 통신 실패 / 제어 리셋','원본 코드가 캐시를 0으로 변경')},
        [('arm','one',False),('one','two',False),('two','done',False)],250,
        '조건을 만족한 상태 1 콜백에서는 완료하지 않습니다. 연속 0 입력: 7회째 상태 2, 8회째 완료. 우회 플래그는 정적 조건입니다.','af-completion.json')
    v['phase_graph']=graph('af-phase','AF 완료와 촬영 단계 전이는 별도 조건',{
        'start':(20,10,'검색 알림 0x6003e','단계가 2일 때 3으로'),
        'phase':(350,10,'완료 알림 0x6003f','단계가 4일 때만 5로'),
        'flag':(700,10,'완료 알림 0x10060032','blFocusCompleteflag 설정'),
        'case2':(20,150,'초기 단계 2 사례','AF 완료 뒤에도 단계 3'),
        'case4':(350,150,'초기 단계 4 별도 사례','완료 시 단계 5'),
        'physical':(700,150,'실제 초점 · 렌즈 정지','이 소프트웨어 플래그만으론 미확정')},
        [('start','case2',False),('phase','case4',False)],250,
        '단계 4는 시험 입력입니다. 실제 촬영이 3에서 4로 진행하는 경로를 이 실행에서 재현한 것은 아닙니다.','af-completion.json')
    v['abort_graph']=graph('af-abort','AF 시퀀스 취소 요청과 종료 대기',{
        'command':(350,10,'명령 0xe0002','OnNotifyCommand'),
        'guard':(20,10,'blBKControl == 1','취소 플래그만 설정'),
        'stop':(700,10,'그 밖: StopAF(1)','CAF enable=0 / quit=1'),
        'exit':(20,150,'종료 이벤트 0x08 대기','mode 1 / timeout 0xffffffff'),
        'wake':(350,150,'잠든 시퀀스만 깨움','이벤트 0x10'),
        'sequence':(700,150,'시퀀스 활성 == 1','정지 요청 플래그 설정')},
        [('command','guard',False),('command','stop',False),('stop','sequence',False),('sequence','wake',False),('wake','exit',True)],250,
        '활성 상태지만 깨어 있으면 깨우기 없이 종료 대기. 이벤트 전달·반환은 모델이며 렌즈 정지 명령과 같은 완료 신호가 아닙니다.','af-completion.json')
    rows=[]
    for row in data['replay']['command_cases']:
        drives=[s for s in row['steps'] if s['action']=='drive']
        final=row['steps'][-1]
        rows.append(f'<tr><th>{esc(row["name"])}</th><td>{" → ".join(str(s["setter_return"]) for s in drives)}</td><td>{" → ".join(str(s["waits"]) for s in drives)}</td><td>{final["motion_check_state"]}</td><td>{final["af_complete"]}</td><td>{final["capture_phase"]}</td></tr>')
    v['case_rows']=''.join(rows)
    v['boundary_rows']=''.join(f'<tr><th><code>{a}</code></th><td>{esc(t)}</td></tr>' for a,t in data['replay']['modeled_boundaries'].items())
    v['k3_commit']=data['comparison']['commit']
    page=(ROOT/'analysis/af-template.html').read_text(encoding='utf-8')
    for k,value in v.items(): page=page.replace('{{'+k+'}}',value)
    assert '{{' not in page
    (ROOT/'af-completion-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built af-completion-report.html')


if __name__=='__main__': main()
