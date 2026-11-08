"""Build the FC1 semantics and HDR task lifecycle follow-up."""
from build_deep_report import ROOT, read, esc
from build_routing_report import graph
from verify_routing import witnesses


def main():
    values={k:esc(v) for k,v in read('task-copy.json').items()}
    values['meaning_graph']=graph('fc1-meaning','FC1 제어 워드의 서로 다른 출처',{
        'type':(20,10,'저장된 입력 유형 T','input_format_mode에서 분류'),
        'top':(350,10,'패스별 Top_BlockControls','해당 분기: bit = (T == 0)'),
        'export':(700,10,'FIPLIB Export','mode 1: payload+0x12c'),
        'raw':(20,150,'상위 descriptor 0xf','version c/d/f: 원시 u32'),
        'field':(700,150,'ID 0xab / 0xf setter','같은 filter+0x48에 저장'),
        'reg':(700,290,'writer: 0xb60000fc','물리적 비트 동작 미확정')},
        [('type','top',False),('top','export',False),('export','field',False),('raw','field',False),('field','reg',False)],390,
        'FIPLIB 값은 Export payload+0x12c와 ID 0xab setter를 거칩니다. 직접 입력은 ID 0xf setter를 거쳐 같은 객체 필드에 도달합니다. 활성화 주소 0xb60000ec는 별개입니다.','fc1-semantics.json')
    values['task_graph']=graph('hdr-tasks','네 패스에서 큐 제출까지',{
        'passes':(20,10,'1x0 → 1x1 → 5x1 → 0x1','FIPLIB wrapper 0·1·2·3'),
        'handler':(350,10,'CalculateTopology','C12 handler / CreateTask'),
        'task':(700,10,'CIpuTaskC12 × 4','task class는 네 패스 공통'),
        'config':(20,150,'TranslateFilters → Commit','설정 변환 / subimage 준비'),
        'go':(350,150,'processor Go → task Go','mode 0 / CBC 0'),
        'queue':(700,150,'driver+0x224 큐','task pointer / wait 0')},
        [('passes','handler',False),('handler','task',False),('config','go',False),('go','queue',False)],250,
        '형식별 FIPLIB 클래스와 드라이버 task 클래스를 구분했습니다. task 슬롯이 존재하고 앞선 설정이 성공해야 뒤의 제출 경로로 이어집니다. 재실행의 크기·대체 함수는 검증 절에 명시합니다.','task-create-followup.json')
    values['done_graph']=graph('hdr-done','IRQ에서 HDR 대기 해제까지의 조건부 연결',{
        'irq':(20,10,'IsrIpuDone','등록 ID 0x29 / 실제 IRQ 미관측'),
        'event':(350,10,'driver+0x30c / bit 0','counter +0x34c 증가'),
        'worker':(700,10,'드라이버 대기 성공','PowerOff → Notify(event 2)'),
        'sub':(20,150,'task Update','하위 이미지가 남으면 재큐잉'),
        'taskdone':(350,150,'OnProcessingDone','끝난 task → processor'),
        'count':(700,150,'processor Update','패스·완료 횟수 조건'),
        'callback':(20,290,'CObserverWrapper','IpuCallBack(event 2)'),
        'path':(350,290,'0x815a1bc4 / bit 0','보조 이벤트와 구분'),
        'wait':(700,290,'PathWait 성공 분기','IpuToneMapRgb 후속 정리')},
        [('irq','event',False),('event','worker',True),('sub','taskdone',False),('taskdone','count',False),('callback','path',False),('path','wait',True)],390,
        '행은 위에서 아래로 이어지는 소프트웨어 경로입니다. 점선은 이벤트 대기 경계이며 실제 IRQ·스케줄링 관측을 뜻하지 않습니다. 남은 하위 이미지가 있으면 중간 행에서 같은 task를 다시 제출합니다.','task-completion-followup.json')
    docs=[read(n) for n in ('fc1-semantics.json','task-create-followup.json','task-completion-followup.json')]
    tasks=docs[1]['replay']['result']
    classes=read('hdr-pass-followup.json')['fresh_hdr']['pass_classes']
    values['task_rows']=''.join(
        f'<tr><th>{i} / {esc(classes[i])}</th><td>{tasks["task_ids"][i]}</td>'
        f'<td>{tasks["final_flags"][i]}</td><td>{tasks["task_fields"][i]["0x224"]}</td>'
        f'<td>{fc["uid"]}</td><td>{fc["enabled"]}</td><td>{fc["flags"]}</td></tr>'
        for i,fc in enumerate(tasks['fc1']))
    values['function_count']=str(len({f['address'] for d in docs for f in d['selected_functions']}))
    values['word_count']=str(sum(len(list(witnesses(d))) for d in docs))
    k3=read('task-comparison.json');values['k3_commit']=k3['latest_public_main_sha_verified_via_gh']
    values['k3_base']=k3['k3_public_repository']+'/blob/'+values['k3_commit']+'/analysis/'
    page=(ROOT/'analysis/task-template.html').read_text(encoding='utf-8')
    for key,value in values.items(): page=page.replace('{{'+key+'}}',value)
    assert '{{' not in page
    (ROOT/'hdr-task-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built hdr-task-report.html')


if __name__=='__main__': main()
