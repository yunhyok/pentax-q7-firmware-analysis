"""Render the Q7 lens/ISP/output follow-up using reviewed prose and evidence."""
from build_deep_report import ROOT, read, esc, diagram


def graph(key, title, nodes, edges, height, caption, source):
    return diagram(key, title, nodes, edges, height, caption).replace(
        'analysis/deep-evidence.json">[S3]', f'analysis/{source}">[근거]')


def main():
    values = {key:esc(value) for key,value in read('routing-copy.json').items()}
    values['lens_graph'] = graph('lens-route', 'AF 콜백에서 렌즈 통신까지', {
        'af':(20,10,'LensDriveControl','0x8037eb78 / 0x6003c'),
        'cap':(350,10,'OnNotifyCommand','0x8040a008 / binding 확인'),
        'exec':(700,10,'ExecuteFocusControl','0x8042e040 / mode 분기'),
        'q':(20,150,'큐 메시지 6 · 7 · 8','검색 / 위치 이동 / 정지'),
        'worker':(350,150,'렌즈 큐 수신부','명령별 ComSetFocus…'),
        'lens':(700,150,'LensCommunication','0x80111214 / 전송 요청'),
        'vd':(20,290,'mode 3: 검색 보류','pending flag = 1'),
        'sync':(350,290,'VD 동기화 메시지 2','VdSyncRegularCommunicationAf'),
        'com':(700,290,'검색 통신 요청','보류한 검색 정보 소비')},
        [('af','cap',True),('cap','exec',False),('q','worker',True),('worker','lens',False),('sync','com',False)],390,
        '첫 행 점선은 초기화로 수신자가 확인된 간접 점프입니다. 둘째 행 점선은 큐 전달 관계입니다. 셋째 행의 검색 보류 상태와 독립적으로 발생한 VD 메시지 2가 함께 있어야 검색 정보를 소비합니다. 모드 3이 VD 이벤트를 생성하는 것은 아닙니다.', 'lens-routing.json')
    values['isp_graph'] = graph('isp-route','상위 설정과 저수준 객체의 연결',{
        'setup':(20,10,'SetupColorMatrix','상위 ID 0xe · 0xf'),
        'cache':(350,10,'Still 설정 캐시','0x815c6f30 + index × 4'),
        'ipu':(700,10,'IpuSetFilter','path type 0 / RAM 복사'),
        'translator':(20,150,'CTranslatorC12','low ID 10 / 13 선택'),
        'cm':(350,150,'CCmFilter / CFc1Filter','vtable+0x20: 설정 저장'),
        'regs':(700,150,'WriteAll → writer','vtable+8 / dirty 조건'),
        'fip':(350,290,'FIPLIB 후속 갱신','조건에 따라 값 덮어쓰기'),
        'cbc':(700,290,'CBC 대체 제출','직접 쓰기와 별도 경로')},
        [('setup','cache',False),('cache','ipu',False),('translator','cm',False),('cm','regs',False),('cm','fip',True),('cm','cbc',True)],390,
        '첫 행은 설정 저장·소비, 둘째 행은 변환된 필터의 사용 관계입니다. 화살표는 데이터·객체 관계이며 픽셀의 통과 순서가 아닙니다. 점선은 조건부 대체·후속 경로입니다.', 'isp-routing.json')
    values['gamma_graph'] = graph('gamma-route','통계용 감마 LUT의 실제 쓰기',{
        'app':(20,10,'App gamma context','0x802559f0'),
        'sensor':(350,10,'SensorSetGammaWithId','0x801f7390'),
        'update':(700,10,'UpdateIppIpsGamma','0x801f7244 / busy polling'),
        'gc':(20,150,'GC LUT writer','0x801d585c / 77 words'),
        'gcport':(350,150,'0xb5002070','고정 data port에 반복 쓰기'),
        'dci':(20,290,'DCI LUT writer','0x801d58c4 / count words'),
        'dcport':(350,290,'0xb5002434','count = 0이면 data write 없음')},
        [('app','sensor',False),('sensor','update',False),('gc','gcport',False),('dci','dcport',False)],390,
        '아래 두 행은 UpdateIppIpsGamma의 조건부 호출 대상입니다. GC는 동기화 플래그, DCI는 버퍼+0x3f4 값 0x4d를 검사합니다. 최종 JPEG용 감마라고 단정하지 않았습니다.', 'isp-routing.json')
    values['matrix_rows'] = ''.join(f'<tr><th>{i}</th><td><code>+0x{0x14+2*i:02x}</code></td><td><code>0x{0xb6000200+4*i:08x}</code></td><td><code>0x{0xb60000c0+4*i:08x}</code></td></tr>' for i in range(9))
    values['output_graph'] = graph('output-route','HDR 저장 요청과 JPEG 코드 버퍼',{
        'save':(20,10,'HDR → SaveJpegImage','0x802d33d0'),
        'exif':(350,10,'ApsExifCreateJpeg','0x802c3454 / descriptor 분기'),
        'go':(700,10,'CreateCodeGo','0x802bb250 / 압축 작업'),
        'buffer':(20,150,'image / code buffer','descriptor · pointer · capacity'),
        'path':(350,150,'PathSubmit → PathGo','설정 제출 후 실행 요청'),
        'wait':(700,150,'PathWait → code size','0x802bb1ec / 재확인 조건'),
        'parts':(20,290,'partition → pipe 0','ApsPipePost / 0x1005'),
        'server':(350,290,'StillServer','pipe 0 / 0x1005 수신'),
        'ready':(700,290,'StillOnFileReady','pipe 3 / 0x1002 전달'),
        'store':(20,430,'StillStoreMain','StoreOnSave → ApsSaveFile'),
        'writer':(350,430,'ApsSaveWrite → callback','item+8: ptr / item+0xc: bytes'),
        'file':(700,430,'_fx_file_write','0x80087034 / 오류 확인')},
        [('save','exif',False),('exif','go',False),('buffer','path',False),('path','wait',True),('parts','server',True),('server','ready',False),('store','writer',False),('writer','file',False)],530,
        'HDR 압축·완료·저장 요청을 나누어 표시했습니다. 점선은 대기 또는 큐 전달 관계입니다. 셋째 행의 pipe 3 메시지를 마지막 행의 StillStoreMain이 받습니다. 마지막 행은 본문에 열거한 저장 함수들을 묶어 표시한 연결이며 실기 파일 쓰기의 관측 결과는 아닙니다.', 'output-routing.json')
    isp = read('isp-routing.json')
    values['isp_count'] = str(isp['decompilation']['count'])
    values['function_rows'] = ''.join(f'<tr><td>{esc(f["name"])}</td><td><code>0x{f["address"]:08x}</code></td><td>{f["size"]}</td></tr>' for f in sorted(isp['selected_functions'],key=lambda f:f['address']))
    page = (ROOT/'analysis/routing-template.html').read_text(encoding='utf-8')
    for key,value in values.items(): page = page.replace('{{'+key+'}}',value)
    assert '{{' not in page, 'unresolved routing template field'
    (ROOT/'routing-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built routing-report.html')


if __name__ == '__main__':
    main()
