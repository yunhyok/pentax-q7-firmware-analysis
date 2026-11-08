"""Build the HDR per-pass enable and final submit-selection report."""
from build_deep_report import ROOT, read, esc
from build_routing_report import graph
from verify_routing import witnesses


def main():
    values={k:esc(v) for k,v in read('control-copy.json').items()}
    values['topology_graph']=graph('hdr-topology','HDR 보조 설정과 네 IPU 패스',{
        'format':(20,10,'HDR format 0x0f01','input type 6 / output type 8'),
        'input':(350,10,'보조 설정 ID 0x1f','input[0x1738]: 1 → 0'),
        'top':(700,10,'CreateTopology','phase=0 / level 0 → 1'),
        'loc':(20,150,'location 0 / 6 / 10 / 5','1x0 → 1x1 → 5x1 → 0x1'),
        'pass':(350,150,'IPU 패스 N=4','index 3 / final flag true'),
        'select':(700,150,'Commit mode 0','[0,N) = [0,4)')},
        [('format','input',False),('input','top',False),('loc','pass',False),('pass','select',False)],250,
        '활성 HDR 보조 설정이 초기 phase를 덮어씁니다. 이 조건으로 네 패스가 구성되며, mode 0은 전체 범위를 선택합니다. 마지막 패스 전용 mode 2를 사용한 것은 아닙니다.','hdr-pass-followup.json')
    values['control_graph']=graph('hdr-fc-control','마지막 HDR 패스의 활성화와 제어 워드',{
        'knobs':(20,10,'마지막 0x1 / Q=0','S=0 / D=0 / T=1'),
        'bypass':(350,10,'FC1 bypass = 0','pass local+0x24 → payload+0x44'),
        'enable':(700,10,'enabled = 1','0xb60000ec ← 0'),
        'flag':(20,150,'FC1 flag = (T == 0)','pass local+0x28 = 0'),
        'pack':(350,150,'FC mode 1 Export','payload+0x12c = flag & 1'),
        'reg':(700,150,'packed control = 0','0xb60000fc ← 0')},
        [('knobs','bypass',False),('bypass','enable',False),('flag','pack',False),('pack','reg',False)],250,
        '이 그림의 S·D·Q·T는 본문의 원본 필드 정의를 따릅니다. 제어 비트의 물리적 의미는 명명하지 않았습니다. 두 MMIO 주소의 값은 소프트웨어가 제출하는 설정입니다.','control-followup.json')
    values['submit_graph']=graph('hdr-submit','전체 선택 범위와 최종 제출 패스',{
        'ctor':(20,10,'processor 기본값','mode +0x284=0 / CBC +0x288=0'),
        'commit':(350,10,'Commit 선택 범위','begin=0 / end=4'),
        'task':(700,10,'task 슬롯 0·1·2·3','존재하는 슬롯만 제출'),
        'queue':(20,150,'직접 제출 task 큐','Go / CIpuDriver'),
        'writer':(350,150,'WriteAll·WriteEnable','UID / dirty / config 조건'),
        'boundary':(700,150,'실기 관측 경계','DMA·완료 IRQ·픽셀 미측정')},
        [('ctor','commit',False),('commit','task',False),('queue','writer',False),('writer','boundary',True)],250,
        '화살표는 확인한 호출·선택 관계입니다. 점선 뒤의 실제 하드웨어 결과는 이 분석으로 관측하지 않았습니다. task 생성과 설정 변환이 성공하고 해당 슬롯이 존재하는 조건을 전제로 합니다.','hdr-pass-followup.json')
    docs=[read(n) for n in ('control-followup.json','hdr-pass-followup.json','fc1-enable-checks.json')]
    rows=[]
    for p in docs[0]['fresh_hdr']['passes']:
        payload=p['expected_payload']
        bypass,flag=payload['bypass_word'],payload['mode_1_flag_word']
        rows.append(f"<tr><th>{p['pass_index']}{' · 마지막' if p['final_pass'] else ''}</th><td>{p['topology_location']}</td><td>{esc(p['pass_class'])}</td><td>{p['topology_word']}</td><td>{bypass}</td><td>{flag}</td><td>{bypass}</td><td>{flag}</td></tr>")
    values['pass_table']='<div class="table-wrap"><table><caption>실제 HDR 패스별 설정값 — EC=0xb60000ec, FC=0xb60000fc; writer 조건 충족 시 기록</caption><thead><tr><th>index</th><th>location</th><th>class</th><th>T</th><th>bypass</th><th>flag</th><th>EC</th><th>FC</th></tr></thead><tbody>'+''.join(rows)+'</tbody></table></div>'

    values['function_count']=str(len({f['address'] for d in docs for f in d['selected_functions']}))
    values['word_count']=str(sum(len(list(witnesses(d))) for d in docs))
    k3=read('control-comparison.json')
    values['k3_commit']=k3['latest_public_main_sha_verified_via_gh']
    values['k3_base']=k3['k3_repository']+'/blob/'+values['k3_commit']+'/analysis/'
    page=(ROOT/'analysis/control-template.html').read_text(encoding='utf-8')
    for key,value in values.items(): page=page.replace('{{'+key+'}}',value)
    assert '{{' not in page
    (ROOT/'hdr-control-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built hdr-control-report.html')


if __name__=='__main__': main()
