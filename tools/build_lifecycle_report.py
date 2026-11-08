"""Render bounded storage and lens-readiness lifecycle evidence."""
from build_deep_report import ROOT,read,esc
from build_routing_report import graph


def main():
    loader,lens=read('loader-storage.json'),read('lens-readiness.json')
    v={k:esc(t) for k,t in read('lifecycle-copy.json').items()}
    v['storage_graph']=graph('storage-flow','원본 BurnNand에서 첫 기록 경계까지',{
        'input':(20,10,'원본 첫 청크 + 합성 헤더','131,072바이트 / 1,024블록'),
        'map':(350,10,'원본 섹션 맵·사전 검사','op 6 × 2,691 / op 8 × 640'),
        'program':(700,10,'첫 op 5 호출 직전 중단','sector 0 / count 256'),
        'model':(20,150,'합성 FCU 결과','spare = FF / status = 0'),
        'source':(350,150,'기록 대상 버퍼 관측','원본 입력과 281바이트 차이'),
        'device':(700,150,'실제 저장 장치','기록·erase·복구 미실행')},
        [('input','map',False),('map','program',False),('model','map',True),('program','device',True)],250,
        'FCU 요청의 발생과 순서는 원본 코드에서 관측했습니다. 요청 결과는 모델로 공급했고 첫 기록 요청은 실행 전에 멈췄습니다.','loader-storage.json')
    v['program_graph']=graph('program-readback','별도 helper의 기록·재읽기·비교',{
        'write':(20,10,'op 5 / 데이터 + extra','오류 상태면 반환 0'),
        'read':(350,10,'상태 0 → op 4','handle +0x1250 버퍼'),
        'compare':(700,10,'상태 0 → 바이트 비교','count × 512 / 첫 차이 중단'),
        'failed':(20,150,'상태 오류 또는 불일치','map[block] = 0x78 / 반환 0'),
        'same':(350,150,'끝까지 일치','반환 1 / 맵 유지'),
        'tests':(700,150,'1·2섹터 합성 8사례','실제 미디어 비교가 아님')},
        [('write','read',False),('read','compare',False),('write','failed',False),('compare','same',False)],250,
        'op 5와 op 4 반환값 및 읽은 바이트는 모델 입력입니다. 비교 루프·조기 종료·실패 맵 쓰기는 원본 MIPS로 실행했습니다.','loader-storage.json')
    v['gate_graph']=graph('readiness-gates','AF 지원과 명령 허용의 서로 다른 조건',{
        'state':(20,10,'통신 상태 & 0x08','primary + regular 결과'),
        'af':(350,10,'ExGetAfEnable','0x08 AND group2/op4'),
        'policy':(700,10,'상위 AF 지원 판정','map-ready는 검사하지 않음'),
        'ready':(20,150,'map-ready == 1 ?','0이면 맵 제한 생략'),
        'admit':(350,150,'LensCommunication','ready=1일 때 연산 맵 검사'),
        'link':(700,150,'하위 통신 모델 경계','bit 0x08은 검사하지 않음')},
        [('state','af',False),('af','policy',False),('ready','admit',False),('admit','link',False)],250,
        '두 행은 다른 검사입니다. AF 지원 0인데 검색 요청이 전달되는 합성 상태와 AF 지원 1인데 VDRC 상태 0인 초기화를 재현했습니다.','lens-readiness.json')
    v['reset_graph']=graph('cache-reset','실패 응답과 전체 리셋의 차이',{
        'valid':(20,10,'초기화 성공의 캐시','통신 0x2f / ready 1'),
        'failure':(350,10,'선택한 응답 실패','함수별 데이터·상태 보존 차이'),
        'observe':(700,10,'값과 유효 상태를 함께 관측','0 값 + valid 1도 가능'),
        'timeout':(20,150,'timeout mask 0x100','결과 5 / 이전 ready==1'),
        'reset':(350,150,'control + data reset','맵·상태·PLC·VDRC 초기화'),
        'reentry':(700,150,'초기화 재진입 관측','중첩 실행은 모델에서 중단')},
        [('valid','failure',False),('failure','observe',False),('timeout','reset',False),('reset','reentry',True)],250,
        '실패 응답과 전체 리셋은 같은 작업이 아닙니다. 실제 시간 순서와 장치에서 이 상태가 발생하는 빈도는 측정하지 않았습니다.','lens-readiness.json')
    v['program_rows']=''.join(f'<tr><th>{esc(c["name"])}</th><td>{c["sectors"]}</td><td>{c["compared_bytes_per_operand"]}</td><td>{c["result"]}</td><td><code>{esc(c["map"])}</code></td></tr>' for c in loader['replay']['program_cases'])
    v['lens_rows']=''.join(f'<tr><th>{esc(c["case"])}</th><td>0x{c["after"]["communications_state"]:02x}</td><td>{c["after"]["af_enable"]}</td><td>{c["after"]["validity"][2]}</td><td>{str(c["after"]["search_forwarded"]).lower()}</td></tr>' for c in lens['replay']['startup_cases'])
    v['k3_loader']=loader['comparison']['k3_commit'];v['k3_lens']=lens['comparison']['commit']
    page=(ROOT/'analysis/lifecycle-template.html').read_text(encoding='utf-8')
    for key,value in v.items():page=page.replace('{{'+key+'}}',value)
    assert '{{' not in page
    (ROOT/'storage-readiness-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built storage-readiness-report.html')


if __name__=='__main__':main()
