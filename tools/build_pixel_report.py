"""Build the buffer identity and color-pass follow-up report."""
from build_deep_report import ROOT, read, esc
from build_routing_report import graph


def main():
    values={k:esc(v) for k,v in read('pixel-copy.json').items()}
    values['buffer_graph']=graph('hdr-buffer','HDR IPU 출력에서 JPEG 입력까지',{
        'alloc':(20,10,'HDR 작업 버퍼 B','HdrImageMixing / W+0x70'),
        'view':(350,10,'하위 이미지 출력 view','B + offset / ToneMapRgb'),
        'ipu':(700,10,'IPU 출력 설정','PathSetBuffers / path+0x28'),
        'hdr':(20,150,'HDR 결과 B','context+0x3dc → descriptor'),
        'ldc':(350,150,'LDC 입력·출력 B','같은 descriptor / 성공 경로'),
        'direct':(700,150,'ApsJpegDirectCompress','입력 주소 T(B) / PathCreate(1)'),
        'jpeg':(20,290,'JPEG path 입력','type 1 / path+8 = T(B)'),
        'code':(350,290,'기존 압축 결과','참조된 이미지: **descriptor = 0'),
        'exif':(700,290,'EXIF·파일 조립','새 CodeGo 압축은 건너뜀')},
        [('alloc','view',False),('view','ipu',False),('hdr','ldc',False),('ldc','direct',False),('code','exif',False)],390,
        '세 행은 동일 HDR 성공 경로의 서로 다른 구간입니다. 첫 행의 출력은 B 내부의 view이며 둘째 행에서 B를 다시 전달합니다. 셋째 행 왼쪽은 DirectCompress가 만드는 JPEG 입력입니다. 이 주소 연결은 소프트웨어 설정 근거이며 DMA 완료나 픽셀 값의 관측이 아닙니다.','buffer-followup.json')
    values['pass_graph']=graph('pass-select','패스 범위와 마지막 패스 플래그',{
        'mode':(20,10,'SetParam(ID 0xa)','processor+0x284 = mode'),
        'range':(350,10,'Commit: [begin, end)','0: 전체 / 1: 앞쪽 / 2: 마지막'),
        'tasks':(700,10,'선택된 task','해당 범위의 non-null 항목'),
        'index':(20,150,'TranslateFilters','i == N−1 → final flag'),
        'config':(350,150,'패스별 config / wrapper','stride 0x374 / 0x24'),
        'filters':(700,150,'CM 10 / FC1 13','마지막 패스 전용 아님')},
        [('mode','range',False),('range','tasks',False),('index','config',False),('config','filters',False)],250,
        '위 행은 제출할 패스 범위, 아래 행은 필터 변환의 선택 문맥입니다. final-pass 표에 설정된 항목은 ID 0입니다. 순회 범위만으로 특정 촬영에서 실제 선택한 N과 mode는 결정되지 않습니다.','pass-followup.json')
    values['overwrite_graph']=graph('filter-overwrite','같은 필터 객체에서 다른 덮어쓰기 범위',{
        'cm0':(20,10,'상위 ID 0xe → CM','object+0x88..+0xa8: 9계수'),
        'cm1':(350,10,'FIPLIB → CM','+0xb0 / +0xb4 / +0xb8만 갱신'),
        'cm2':(700,10,'CM 레지스터 쓰기','9계수 유지 / companion 갱신'),
        'fc0':(20,150,'상위 ID 0xf → FC1','object+0x30..+0x40: 9계수'),
        'fc1':(350,150,'FIPLIB version 0xc → FC1','u32의 low 16비트로 교체'),
        'fc2':(700,150,'FC1 레지스터 쓰기','signed 16비트 → 32비트 확장')},
        [('cm0','cm1',False),('cm1','cm2',False),('fc0','fc1',False),('fc1','fc2',False)],250,
        '상위 descriptor 적용 뒤 FIPLIB 갱신을 시도하는 순서입니다. 두 갱신의 gate가 각각 있으며, 화살표는 조건을 만족한 경우의 객체 데이터 흐름입니다. 두 setter와 writer를 이어 실행해 객체 바이트와 MMIO 쓰기 28회를 확인했습니다.','color-handoff-checks.json')
    values['cbc_graph']=graph('cbc-select','동일 필터 객체의 직접 쓰기와 CBC 제출',{
        'direct':(20,10,'processor+0x288 == 0','task 큐 → CIpuDriver'),
        'write':(350,10,'WriteAll','UID 비교 → filter vtable+8'),
        'mmio':(700,10,'레지스터 직접 store','CM / FC1 writer'),
        'batch':(20,150,'processor+0x288 != 0','Commit → SubmitToBatch'),
        'chunk':(350,150,'CollectCbcChunks','UID 비교 → 청크 재사용·생성'),
        'exec':(700,150,'CbcBatchExec','같은 객체의 주소·값 청크')},
        [('direct','write',False),('write','mmio',False),('batch','chunk',False),('chunk','exec',False)],250,
        'CBC는 설정을 제출하는 다른 경로입니다. 청크 생성 함수는 같은 CM·FC1 객체 필드를 사용하지만 배치의 실제 하드웨어 실행을 재현한 것은 아닙니다.','pass-followup.json')
    docs=[read(n) for n in ('buffer-followup.json','pass-followup.json')]
    from verify_routing import witnesses
    values['function_count']=str(len({f['address'] for d in docs for f in d['selected_functions']}))
    values['word_count']=str(sum(len(list(witnesses(d))) for d in docs))
    comparison=read('followup-comparison.json')
    values['k3_commit']=esc(comparison['commit'])
    values['k3_base']=comparison['repository']+'/blob/'+comparison['commit']+'/analysis/'
    page=(ROOT/'analysis/pixel-template.html').read_text(encoding='utf-8')
    for key,value in values.items(): page=page.replace('{{'+key+'}}',value)
    assert '{{' not in page
    (ROOT/'pixel-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built pixel-report.html')


if __name__=='__main__': main()
