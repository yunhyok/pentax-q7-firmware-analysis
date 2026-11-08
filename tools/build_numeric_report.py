"""Render the C recompilation evidence and its package-capacity boundary."""
from build_deep_report import ROOT, read, esc
from build_routing_report import graph


def main():
    data = read('recompiled-numeric.json')
    v = {k:esc(t) for k,t in read('numeric-copy.json').items()}
    v['build_graph'] = graph('numeric-build','C 재구성과 호스트 메모리 교체',{
        'source':(20,10,'독립 재구성 C','Q13 3×3 / 겹침 보존'),
        'compile':(350,10,'Zig 0.15.2 / Clang','MIPS32r2 · O32 · FP32'),
        'text':(700,10,'text 164바이트','외부 import / code relocation 0'),
        'original':(20,150,'원본 함수 236바이트','0x8041bc90…0x8041bd7c'),
        'overlay':(350,150,'원래 주소에 text 교체','후단 72바이트 보존'),
        'replay':(700,150,'원본과 교체본 재실행','96 함수 / 4 호출부 사례')},
        [('source','compile',False),('compile','text',False),('original','overlay',False),('overlay','replay',False)],250,
        '위 행의 컴파일 결과를 아래 행의 호스트 메모리에 배치했습니다. 카메라나 업데이트 파일에 설치한 그림이 아닙니다.','recompiled-numeric.json')
    v['caller_graph'] = graph('numeric-caller','원본 호출부 안에서의 비교',{
        'config':(20,10,'합성 설정 객체 4개','색공간 0/1 · style 0/1/2'),
        'caller':(350,10,'MakeColorMatrix 원본','0x8041c180'),
        'matrix':(700,10,'Q13 원본 또는 C 결과','14 / 15회씩, 총 58회'),
        'return':(20,150,'실제 반환까지 실행','원본 hue·LUT 경로 사용'),
        'compare':(350,150,'호출·쓰기·출력 비교','객체 / scratch / 보호 영역'),
        'limit':(700,150,'함수 계약 범위의 일치','영상 픽셀·장치 실행 미검증')},
        [('config','caller',False),('caller','matrix',False),('return','compare',False),('compare','limit',False)],250,
        '호출부 분기 주입이나 하위 함수 hook을 사용하지 않았습니다. 선택한 객체에서 원본 코드가 스스로 선택한 분기를 비교했습니다.','recompiled-numeric.json')
    r=data['replay']
    v['package_graph']=graph('numeric-package','고정 슬롯 안의 재인코딩과 후속 참조 보정',{
        'patch':(20,10,'C text 164바이트','실제 변경은 142바이트'),
        'window':(350,10,'E04 #154 / 창 재구성','78,817비트 / 9,853바이트'),
        'next':(700,10,'E04 #155 / 복사 보정','78,813비트 / 9,852바이트'),
        'tables':(20,150,'원래 테이블·슬롯 유지','각 슬롯 9,856바이트'),
        'decode':(350,150,'4세그먼트·448블록 검사','다시 만든 ELF = 실행한 이미지'),
        'device':(700,150,'실제 카메라 수용','하드웨어 inflate·부팅 미검증')},
        [('patch','window',False),('window','next',False),('tables','decode',False),('decode','device',True)],250,
        '155번의 앞 블록 이력 참조를 보정해야 요청 범위 밖의 차이가 사라집니다. 점선은 소프트웨어 검증으로 확정하지 못한 장치 경계입니다.','recompiled-numeric.json')
    v['rows']=''.join(f'<tr><th>{c["color_space"]}</th><td>{c["style"]}</td><td>{c["hue"]} / {c["saturation"]}</td><td>{len(c["call_sites"])}</td><td>{c["nonstack_stores"]}</td></tr>' for c in r['caller_cases'])
    v['source_sha']=r['build']['source_lf_sha256'];v['object_sha']=r['build']['object_sha256'];v['text_sha']=r['build']['text_sha256']
    v['k3_commit']=data['comparison']['commit']
    page=(ROOT/'analysis/numeric-template.html').read_text(encoding='utf-8')
    for key,value in v.items():page=page.replace('{{'+key+'}}',value)
    assert '{{' not in page
    (ROOT/'recompiled-numeric-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built recompiled-numeric-report.html')


if __name__=='__main__':main()
