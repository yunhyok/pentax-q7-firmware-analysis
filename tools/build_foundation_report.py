"""Render the loader and lens-policy follow-up with existing SVG primitives."""
from build_deep_report import ROOT,read,esc
from build_routing_report import graph


def main():
    v={k:esc(value) for k,value in read('foundation-copy.json').items()}
    v['card_graph']=graph('card-input','카드 입력의 두 검증 경로',{
        'flag':(20,10,'handle +0x1278','원본 hash flag = 0'),
        'read':(350,10,'같은 구간 두 번 읽기','실제 길이 + 바이트 비교'),
        'result':(700,10,'일치하면 반환 1','불일치 시 최대 2회 시도'),
        'hash':(20,150,'hash flag = 1','요청 길이 + 16'),
        'worker':(350,150,'해시 작업자 호출','계산 결과는 모델 입력'),
        'next':(700,150,'후속 loader 처리','콜백 성공 ≠ 전체 수용')},
        [('flag','read',False),('read','result',False),('hash','worker',False),('worker','next',True)],250,
        '상단은 원본 flag 0의 분기입니다. 하단은 flag 1을 넣은 합성 사례입니다. 해시 결과를 모델로 제공했으며 후속 전체 loader 성공을 입증하지 않습니다.','loader-foundation.json')
    v['map_graph']=graph('section-map','입력 헤더와 설치된 헤더에서 섹션 맵으로',{
        'incoming':(20,10,'업데이트 페이로드 헤더','파일 0x1000c0 / mode 1'),
        'map':(350,10,'BurnGetSectionsMap','크기·보호 조건 검사'),
        'out':(700,10,'섹션 0…6의 맵','위치 / 영역 / 입력량 / 보호'),
        'installed':(20,150,'기존 헤더 + geometry','이번에는 합성 입력'),
        'prefix':(350,150,'BurnNand 진입부 실행','map 반환 직후 중단'),
        'write':(700,150,'후속 기록·복구','이번 실행 범위 밖')},
        [('incoming','map',False),('installed','map',False),('map','out',False),('prefix','write',True)],250,
        '실제 NAND 배치 대신 명시한 합성 설치 헤더를 사용했습니다. BurnNand는 0x80012654에서 시작해 map 호출의 복귀 주소 0x80012ff0에서 멈췄습니다.','loader-foundation.json')
    v['lens_graph']=graph('lens-policy','렌즈 정보와 AF 정책·완료 경로',{
        'map':(20,10,'기능 / 연산 비트맵','group 2 / operation 4'),
        'admit':(350,10,'AF 지원 + 명령 허용','통신 상태 / map 검사'),
        'command':(700,10,'검색·위치·정지 요청','큐 / VD 동기화'),
        'cache':(20,150,'위치·속도·한계 캐시','값 + 유효 상태'),
        'policy':(350,150,'AF 계산·보정·제한','렌즈 ID fallback 포함'),
        'complete':(700,150,'이동 상태 → 완료 통지','요청 응답과 별도 경로')},
        [('map','admit',False),('admit','command',False),('cache','policy',False),('policy','command',False),('command','complete',True)],250,
        '연결별 함수와 대표 분기를 검사했습니다. 점선은 실제 렌즈 이동·상태 변화를 연속 재현한 경로가 아닙니다.','lens-foundation.json')
    loader=read('loader-foundation.json')
    v['header_rows']=''.join(f'<tr><th>{esc(f["name"])}</th><td>{f["header_offset"]}</td><td>0x{f["value"]:x}</td></tr>' for f in loader['header']['fields'] if int(f['header_offset'],16)<=0x234)
    v['map_rows']=''.join(f'<tr><th>{esc(c["name"])}</th><td>{c["result"]}</td></tr>' for c in loader['replay']['section_map_cases'])
    v['k3_commit']=loader['comparison']['k3_commit']
    page=(ROOT/'analysis/foundation-template.html').read_text(encoding='utf-8')
    for key,value in v.items():page=page.replace('{{'+key+'}}',value)
    assert '{{' not in page
    (ROOT/'loader-lens-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built loader-lens-report.html')


if __name__=='__main__':main()
