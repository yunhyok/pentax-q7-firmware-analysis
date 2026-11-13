"""Build the shared-style DCP report from the complete frozen observations."""
from html import escape
from pathlib import Path

from check_q7_dcp_structure import load_record, canonical

ROOT = Path(__file__).resolve().parents[1]


def fmt(value):
    return f"{value:.6g}"


def interval(s):
    return fmt(s["min"]) + " … " + fmt(s["max"])


def table(headers, rows, label):
    return '<div class="table-wrap" role="region" tabindex="0" aria-label="' + escape(label) + '"><table><thead><tr>' + ''.join('<th scope="col">'+escape(h)+'</th>' for h in headers) + '</tr></thead><tbody>' + ''.join('<tr>'+''.join('<td>'+escape(str(c))+'</td>' for c in row)+'</tr>' for row in rows) + '</tbody></table></div>'


def main():
    d = load_record()
    a, m = d["profiles"]["adobe"], d["profiles"]["matrix"]
    structural = []
    for tag in ("ColorMatrix1", "ColorMatrix2", "ForwardMatrix1", "ForwardMatrix2", "ProfileHueSatMapDims", "ProfileHueSatMapData1", "ProfileHueSatMapData2", "ProfileLookTableDims", "ProfileLookTableData", "ProfileToneCurve", "ProfileHueSatMapEncoding", "ProfileLookTableEncoding", "BaselineExposureOffset", "DefaultBlackRender"):
        row = [tag]
        for p in (a, m):
            v = p["tags"].get(tag)
            row.append("없음" if v is None else (' × '.join(map(str, v["dimensions"])) if "dimensions" in v else f'type {v["type"]}, count {v["count"]}'))
        structural.append(row)
    tables = [[n.replace("Profile", ""), ' × '.join(map(str,t["dimensions_hsv"])), t["nodes"], interval(t["hue_shift_degrees"]), interval(t["saturation_scale"]), interval(t["value_scale"]), t["identity_nodes"]] for n,t in a["tables"].items()]
    matrix_rows = [[role,n,interval(v["range"]),fmt(v["determinant"])] for role,p in (("Adobe Standard",a),("matrix-test",m)) for n,v in p["matrices"].items()]
    inputs = [[role,p["file"],p["bytes"],p["sha256"]] for role,p in (("Adobe Standard",a),("matrix-test",m))]
    directory = [[row[k] for k in ("tag","name","type","count","entry_offset","payload_offset","payload_bytes")] for row in a["directory"]]
    values = {
        "{{STRUCTURE}}": table(["태그", "Adobe Q7", "Q7 matrix-test"],structural,"태그 존재 비교"),
        "{{TABLES}}": table(["테이블", "H × S × V", "노드 수", "색상 이동 (°)", "채도 배율", "명도 배율", "identity 노드"],tables,"테이블 수치 범위"),
        "{{MATRICES}}": table(["입력", "행렬", "저장 원소 범위", "행렬식"],matrix_rows,"행렬 수치 범위"),
        "{{INPUTS}}": table(["입력", "파일명", "바이트", "SHA-256"],inputs,"입력 파일 해시"),
        "{{DIRECTORY}}": table(["태그 번호", "이름", "type", "count", "IFD 위치", "값 위치", "값 바이트"],directory,"Adobe Q7 IFD 근거 위치"),
        "{{SUMMARY_SHA}}": canonical(d),
    }
    text = (ROOT / "analysis/q7-dcp-template.html").read_text(encoding="utf-8")
    for key,value in values.items():
        if text.count(key) != 1:
            raise ValueError("Expected one template marker: " + key)
        text = text.replace(key,value)
    if "{{" in text:
        raise ValueError("Unexpanded template marker")
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports/q7-dcp-structure.html").write_text(text, encoding="utf-8", newline="\n")
    print("Built q7-dcp-structure.html")


if __name__ == "__main__":
    main()
