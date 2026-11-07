"""Render the follow-up HTML from reviewed copy and measured evidence."""
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def read(name):
    return json.loads((ROOT / "analysis" / name).read_text(encoding="utf-8"))
def esc(value):
    return html.escape(str(value))


def diagram(key, title, nodes, edges, height, caption):
    parts = [f'<figure><div class="diagram-wrap"><svg class="diagram" viewBox="0 0 1000 {height}" role="img" aria-labelledby="{key}-title {key}-desc"><title id="{key}-title">{esc(title)}</title><desc id="{key}-desc">{esc(caption)}</desc><defs><marker id="{key}-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path class="arrow" d="M0 0 L8 4 L0 8Z"/></marker></defs>']
    for source, target, dashed in edges:
        x, y, *_ = nodes[source]
        tx, ty, *_ = nodes[target]
        if x == tx:
            path = f"M{x+135} {y+72} L{tx+135} {ty}"
        else:
            path = f"M{x+270} {y+36} L{tx} {ty+36}"
        parts.append(f'<path class="edge {"uncertain" if dashed else ""}" d="{path}" marker-end="url(#{key}-arrow)"/>')
    for x, y, label, subtitle in nodes.values():
        parts.append(f'<rect class="node" x="{x}" y="{y}" width="270" height="72" rx="5"/><text class="label" x="{x+12}" y="{y+29}">{esc(label)}</text><text class="sub" x="{x+12}" y="{y+53}">{esc(subtitle)}</text>')
    return "".join(parts) + f'</svg></div><figcaption>{esc(caption)} <a href="analysis/deep-evidence.json">[S3]</a></figcaption></figure>'


def main():
    values = {k: esc(v) for k, v in read("deep-copy.json").items()}
    values["segments"] = "".join(f'<tr><th>{s["name"]}</th><td><code>{s["file_offset"]:#x}–{s["file_end"]:#x}</code></td><td><code>{s["virtual_address"]:#x}–{s["virtual_address"]+s["decoded_size"]:#x}</code></td><td>{s["decoded_size"]:,}</td><td>{s["block_count"]}</td></tr>' for s in read("segment-decode.json")["segments"])
    comparison = read("comparison.json")
    values["comparison_rows"] = "".join(f'<tr><th><a href="{comparison["k3_repository"]}/blob/{comparison["k3_commit"]}/analysis/{path}">{i}. {esc(name)}</a></th><td>{esc(status)}</td><td>{esc(detail)}</td></tr>' for i, (name,path,status,detail) in enumerate(comparison["rows"],1))
    values["function_rows"] = "".join(f'<tr id="fn-{f["address"]:08x}"><td>{esc(f["name"])}</td><td><code>0x{f["address"]:08x}</code></td><td>{f["size"]:,}</td><td>{len(f["transfers"])}</td><td>{f.get("segment","E03 plain")}</td></tr>' for f in sorted(read("deep-evidence.json")["functions"],key=lambda f:f["address"]))
    values["threadx_diagram"] = diagram("tx", "ThreadX 초기화의 호출과 스레드 진입점", {
        "k":(20,110,"initialize_kernel_enter","0x800d1d88"),"l":(350,10,"initialize_low_level","0x800d9d38 / call"),"h":(350,110,"initialize_high_level","0x800cf220 / call"),"a":(350,210,"tx_application_define","0x800e9470 / call"),"s":(350,310,"thread_schedule","0x800d9b0c / tail jump"),"b":(700,210,"AppBootPrimary","0x800e8c44 / thread entry")},[("k","l",False),("k","h",False),("k","a",False),("k","s",False),("a","b",True)],400,"실선은 kernel_enter의 직접 호출·꼬리 점프입니다. 점선은 OsThreadCreateEx에 진입점 주소를 넘기는 관계입니다.")
    values["af_diagram"] = diagram("af", "AF 명령 처리와 작업 함수의 부분 호출도", {
        "n":(20,10,"OnNotifyCommand","0x8037e218"),"c":(350,10,"CAFSequenceStart","0x8037e194"),"e":(700,10,"EventFlag_Set","start signal"),"w":(20,205,"AfMain_Thread_sub","0x80383dfc"),"p":(350,125,"PeakCheck","0x8037b988"),"f":(350,225,"CalcFocus","0x8037d848"),"l":(350,325,"LensDriveControl","0x8037eb78"),"u":(700,325,"간접 수신자 미확정","pointer @ 0x80c17e00")},[("n","c",False),("c","e",False),("w","p",False),("w","f",False),("w","l",False),("l","u",True)],415,"위쪽은 명령 수신 경로, 아래쪽은 AF 작업 함수의 직접 호출입니다. 이벤트 객체에서 작업 스레드까지의 바인딩은 이 그림에서 연결하지 않았습니다. 점선은 대상 미확정입니다.")
    values["jpeg_diagram"] = diagram("jpg", "JPEG 제출과 완료 인터럽트", {
        "a":(20,10,"ApsCmpGetCodeSizeBySf","PathCreate(1) / 0x8014b790"),"p":(350,10,"PathSubmit","entry 0x801c83c8 / type == 1"),"j":(700,10,"JpegPathSubmit","bit 0x40 -> IcaPathSubmit"),"i":(20,170,"JpegPathInit","register ID 0x14"),"d":(350,170,"IsrJpegDone","status @ 0xb0181ca0"),"e":(700,170,"event flags set","zero: 0x04 / error: 0x40")},[("a","p",False),("p","j",False),("i","d",True),("d","e",False)],270,"위쪽은 코드 크기 계산에서 관찰한 경로 제출입니다. PathSubmit 진입점은 0x801c83c8이며 0x801c84bc는 내부 호출 위치입니다. 아래쪽 점선은 ISR 등록 관계이며 시간상 실행 순서를 뜻하지 않습니다. 양자화 레지스터와 실제 촬영 버퍼의 연결은 남아 있습니다.")
    values["color_diagram"] = diagram("col", "색 행렬 설정의 직접 호출", {
        "s":(20,10,"SetupColorMatrix","0x80428654"),"m":(350,10,"MakeColorMatrix","0x8041c180"),"q":(700,10,"MatrixMultiplication","0x8041bc90 / >> 13"),"h":(700,140,"HueShift","0x8041be94 / >> 8"),"i":(20,170,"I43_SetImageProcessing","configuration path")},[("s","m",False),("m","q",False),("m","h",False),("s","i",False)],270,"실선은 확인한 직접 호출입니다. 행렬 생성과 이미지 처리 설정 경로이며 매 픽셀을 소프트웨어에서 계산한다는 뜻은 아닙니다.")
    page = (ROOT / "analysis/deep-template.html").read_text(encoding="utf-8")
    for key,value in values.items():
        page = page.replace("{{" + key + "}}", value)
    assert "{{" not in page, "unresolved template field"
    (ROOT / "deep-report.html").write_text(page,encoding="utf-8",newline="\n")
    print("Built deep-report.html")


if __name__ == "__main__":
    main()
