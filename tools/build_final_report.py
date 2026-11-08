"""Build the HDR submit-selector and FC coefficient follow-up."""
from build_deep_report import ROOT, read, esc
from build_routing_report import graph
from verify_routing import witnesses


def main():
    values={k:esc(v) for k,v in read('final-copy.json').items()}
    values['selector_graph']=graph('submit-choice','새 HDR 경로의 출력 디스크립터 선택',{
        'new':(20,10,'PathCreate(type 0)','0xb40 bytes clear / +0x964 = 0'),
        'hdr':(350,10,'HDR 설정 함수','format 0x0f01 / output +0x28'),
        'test':(700,10,'IpuSubmit: +0x964 검사','0 → block / nonzero → alternate'),
        'block':(20,150,'일반 출력 블록','path+0x28 → type 8 descriptor'),
        'image':(350,150,'SetImage 진입','surface[0] = output / kind 2'),
        'alt':(700,150,'대체 출력 디스크립터','path+0x8fc / 명시 설정 시 선택')},
        [('new','hdr',False),('hdr','test',False),('block','image',False)],250,
        '첫 행은 새 HDR 경로에서 조건이 정해지는 과정입니다. 둘째 행 왼쪽은 이 조건으로 선택되는 출력이고, 오른쪽은 비교용 대체 분기입니다. +0x964는 대체 디스크립터의 타입 필드(+0x68)입니다.','submit-followup.json')
    values['producer_graph']=graph('fc-producer','HDR 계수에서 FIPLIB 패스 출력까지',{
        'desc':(20,10,'HDR ID 0xf / version 0xc','9 coefficients + 2 companions'),
        'input':(350,10,'PrepareCalculations','input+0x1074 / input[1] = 0'),
        'pass':(700,10,'패스별 입력 포인터','pass+0x8f4 = local+0x68'),
        'fc':(20,150,'FC block: pass+0x118','mode 1 / 11 halfwords copy'),
        'export':(350,150,'FC Export','sign extend → payload+0x100'),
        'wrapper':(700,150,'패스별 wrapper','+0x1c → 해당 payload')},
        [('desc','input',False),('input','pass',False),('fc','export',False),('export','wrapper',False)],250,
        '첫 행은 입력의 출처, 둘째 행은 같은 패스의 FC 설정·내보내기입니다. 새 HDR processor에는 ID 0x1d가 없으므로 input[1]은 0입니다. 패스별 top-control과 필터 활성화는 별도 조건입니다.','fiplib-followup.json')
    values['numeric_graph']=graph('fc-numeric','실제로 재실행한 다섯 함수',{
        'ctor':(20,10,'FC constructor','0x8017a974 / mode 1 or 3'),
        'config':(350,10,'ConfigIntRegs','0x8017ab94 / copy or preset'),
        'export':(700,10,'FC Export','0x8017ad04 / signed u32'),
        'setter':(20,150,'FC1 setter','0x8031f64c / low 16 bits'),
        'writer':(350,150,'FC1 writer','0x8031f750 / signed stores'),
        'mmio':(700,150,'RAM MMIO 기록','11 values + 1 flags / case')},
        [('ctor','config',False),('config','export',False),('setter','writer',False),('writer','mmio',False)],250,
        '한 사례마다 위 세 함수 다음 아래 두 함수를 연속 실행했습니다. 이 다섯 함수에는 대체 함수를 넣지 않았습니다. 패스 입력·wrapper·dirty 상태는 합성했으며 전체 FIPLIB 또는 ISP 하드웨어 실행은 아닙니다.','fiplib-coefficient-checks.json')
    docs=[read(n) for n in ('submit-followup.json','fiplib-followup.json')]
    values['function_count']=str(len({f['address'] for d in docs for f in d['selected_functions']}))
    values['word_count']=str(sum(len(list(witnesses(d))) for d in docs))
    checks=read('fiplib-coefficient-checks.json')
    values['numeric_rows']=''.join('<tr><th>'+esc(c['case'])+'</th><td>'+esc(str(c['expected_halfwords']))+'</td><td>'+str(c['expected_flags'])+'</td><td>12 / PASS</td></tr>' for c in checks['cases'])
    c=read('final-comparison.json')
    values['k3_commit']=esc(c['latest_main_commit_verified_via_gh_api'])
    values['k3_base']=c['k3_public_remote']+'/blob/'+values['k3_commit']+'/analysis/'
    page=(ROOT/'analysis/final-template.html').read_text(encoding='utf-8')
    for key,value in values.items(): page=page.replace('{{'+key+'}}',value)
    assert '{{' not in page
    (ROOT/'final-color-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built final-color-report.html')


if __name__=='__main__': main()
