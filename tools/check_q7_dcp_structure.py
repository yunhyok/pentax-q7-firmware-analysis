"""Read two pinned Q7 DCPs; emit aggregate metadata, never table payloads."""
if not __debug__:
    raise RuntimeError("Validation requires assertions; run without -O")

import argparse
from copy import deepcopy
from os import fstat
from os.path import lexists
from stat import S_ISREG
from hashlib import sha256
import json
from math import isfinite, prod, sqrt
from pathlib import Path
import struct
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
CAP = 2_000_000
RESEARCH_CODE_SHA = "1ffc7911e8b7f82b6d309656a176fbf69390440423263c0f37e1188b44f64a92"
RESEARCH_RECORD_SHA = "44a688b31ca9b7fcbfee10adc6911942acd71a589bd70a6259db54304e02beec"
OBSERVATIONS_SHA = "f0118a7afb3b34df06a994f5cdf7ee2b59f1a8de5035a16967769db9d95f335c"
K3_COMMIT = "2b50cf4f46a61b077789692b3ccc851d4d8d65b9"

PINS = {
    "adobe": "83ba6fbd61d52fdb70c60ed6765220fc3554baf8876c6e8834967714fea08fff",
    "matrix": "fe68b3460a400cf00bf9dfbe49f06f5f1c2cbc1010642d214df375d60504729e",
}
PARSER_SHA = "83c9ea9d745a4ac12bba4164ff729aeb8e64bdd3783e8575727251758ee3a7e7"
EXTRA_TAGS = {50730: "BaselineExposure", 50932: "ProfileCalibrationSignature", 50941: "ProfileEmbedPolicy",
              50942: "ProfileCopyright", 51109: "BaselineExposureOffset",
              51110: "DefaultBlackRender"}
REPORT_PINS = {
    "analysis/adobe-profiles.json": "ad818a31bed1807282fef795ae6744ad64cf30d1ba660e87dbb407af92af625e",
    "analysis/lightroom-as-shot.json": "5d2e25129c4d97284618ffb38e44423d95b70064af8e8208e9c076c3eba2d7cd",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def capture(path, cap=CAP):
    """Validate the open descriptor and read at most cap+1 bytes once."""
    with path.open("rb") as stream:
        info = fstat(stream.fileno())
        require(S_ISREG(info.st_mode) and 0 <= info.st_size <= cap, "Invalid bounded regular input")
        data = stream.read(cap + 1)
    require(len(data) <= cap and len(data) == info.st_size, "Input changed size or exceeds cap")
    return data


def pinned(path, expected, normalize_lf=False):
    data = capture(path)
    checked = data.replace(b"\r\n", b"\n") if normalize_lf else data
    require(sha256(checked).hexdigest() == expected, "Input SHA-256 mismatch: " + path.name)
    return data


def captured_json(path, expected):
    data = pinned(path, expected, normalize_lf=True)
    return json.loads(data), {"sha256": sha256(data).hexdigest(),
                             "sha256_lf": sha256(data.replace(b"\r\n", b"\n")).hexdigest()}


def load_parser(root):
    path = root / "inspect_adobe_profiles.py"
    source = pinned(path, PARSER_SHA, normalize_lf=True).replace(b"\r\n", b"\n")
    module = ModuleType("q7_pinned_dcp_parser")
    exec(compile(source, str(path), "exec"), module.__dict__)
    module.TAGS.update(EXTRA_TAGS)
    return module


def span(values):
    require(bool(values) and all(map(isfinite, values)), "Empty or non-finite values")
    return {"min": min(values), "max": max(values)}


def tone_metrics(values):
    if values is None:
        return {"status": "absent", "points": None, "domain_0_1": None,
                "strict_x": None, "nondecreasing_y": None,
                "sdr_endpoints": None, "identity_max_abs_at_knots": None,
                "identity_rms_at_knots": None}
    require(len(values) >= 4 and len(values) % 2 == 0, "Invalid tone-pair count")
    require(all(map(isfinite, values)), "Non-finite tone point")
    x, y = values[::2], values[1::2]
    delta = [b-a for a, b in zip(x, y)]
    return {"status": "stored_knots_only", "points": len(x),
            "domain_0_1": all(0 <= v <= 1 for v in values),
            "strict_x": all(a < b for a, b in zip(x, x[1:])),
            "nondecreasing_y": all(a <= b for a, b in zip(y, y[1:])),
            "sdr_endpoints": (x[0], y[0], x[-1], y[-1]) == (0, 0, 1, 1),
            "identity_max_abs_at_knots": max(map(abs, delta)),
            "identity_rms_at_knots": sqrt(sum(d*d for d in delta)/len(delta))}


def inspect(data, parser):
    result = parser.describe(data)  # Reuse the repository's IFD and bounds checks.
    endian = "<" if data[:2] == b"II" else ">"
    offset, = struct.unpack_from(endian + "I", data, 4)
    count, = struct.unpack_from(endian + "H", data, offset)
    values, directory = {}, []
    for i in range(count):
        entry = offset + 2 + i*12
        tag, kind, n, pointer = struct.unpack_from(endian + "HHII", data, entry)
        size = parser.TYPE_SIZES[kind]*n
        start = entry + 8 if size <= 4 else pointer
        name = parser.TAGS.get(tag, "tag_" + str(tag))
        directory.append({"tag": tag, "name": name, "type": kind, "count": n,
                          "entry_offset": entry, "payload_offset": start, "payload_bytes": size})
        if name not in result["tags"]:
            continue
        payload = data[start:start+size]
        if kind in (3, 4, 11):
            values[name] = list(struct.unpack(endian + {3:"H", 4:"I", 11:"f"}[kind]*n, payload))
        elif kind in (5, 10):
            pairs = list(struct.iter_unpack(endian + ("II" if kind == 5 else "ii"), payload))
            require(all(den != 0 for _, den in pairs), "Zero rational denominator")
            values[name] = [num/den for num, den in pairs]
        if name in values:
            result["tags"][name]["range"] = span(values[name])
    result["ifd_entry_count"] = count
    result["directory"] = directory
    matrices = {}
    for name in ("ColorMatrix1", "ColorMatrix2", "ForwardMatrix1", "ForwardMatrix2"):
        if name in values:
            require(result["tags"][name]["type"] == 10 and len(values[name]) == 9, "Expected 3x3 SRATIONAL")
            a,b,c,d,e,f,g,h,i = values[name]
            matrices[name] = {"shape": [3,3], "range": span(values[name]),
                              "determinant": a*(e*i-f*h)-b*(d*i-f*g)+c*(d*h-e*g)}
    result["matrices"] = matrices
    tables = {}
    for name, dim_name in (("ProfileHueSatMapData1", "ProfileHueSatMapDims"),
                           ("ProfileHueSatMapData2", "ProfileHueSatMapDims"),
                           ("ProfileLookTableData", "ProfileLookTableDims")):
        if name not in values:
            continue
        dims = values[dim_name]
        require(len(dims) == 3 and dims[0] >= 1 and dims[1] >= 2 and dims[2] >= 1, "Invalid table dimensions")
        v = values[name]
        require(result["tags"][name]["type"] == 11 and len(v) == 3*prod(dims), "Table size mismatch")
        hue, sat, val = v[::3], v[1::3], v[2::3]
        zero_s = val[::dims[1]]
        tables[name] = {"dimensions_hsv": dims, "nodes": prod(dims),
                        "hue_shift_degrees": span(hue), "saturation_scale": span(sat),
                        "value_scale": span(val), "zero_saturation_nodes": len(zero_s),
                        "zero_saturation_value_all_one": all(z == 1 for z in zero_s),
                        "identity_nodes": sum(h == 0 and s == 1 and v == 1 for h,s,v in zip(hue,sat,val)),
                        "nonnegative_scales": min(sat) >= 0 and min(val) >= 0}
    result["tables"] = tables
    result["tone_curve"] = tone_metrics(values.get("ProfileToneCurve"))
    result["optional_presence"] = {name: name in result["tags"] for name in
        ("ProfileToneCurve", "ProfileHueSatMapEncoding", "ProfileLookTableEncoding",
         "BaselineExposure", "BaselineExposureOffset", "DefaultBlackRender")}
    return result, values


def self_test(parser):
    parser.self_test()
    require(tone_metrics(None)["identity_max_abs_at_knots"] is None, "Absent curve became identity")
    require(tone_metrics([0,0, .5,.5, 1,1])["identity_max_abs_at_knots"] == 0, "Identity failed")
    require(tone_metrics([0,0, .5,.75, 1,1])["identity_max_abs_at_knots"] == .25, "Deviation failed")
    require(not tone_metrics([0,0, .5,.8, 1,.7])["nondecreasing_y"], "Y reversal missed")
    require(not tone_metrics([0,0, 0,.5, 1,1])["strict_x"], "Repeated X missed")
    require(not tone_metrics([0,0, 1,1.1])["domain_0_1"], "Domain escape missed")
    for bad in ([0,0,1], [0,0,1,float("nan")]):
        try:
            tone_metrics(bad)
        except ValueError:
            continue
        raise ValueError("Invalid tone data accepted")
    return {"existing_parser_self_test": "passed", "tone_checks": 8}


def analyze(args):
    parser = load_parser(args.k3_root)
    tests = self_test(parser)
    profiles, decoded = {}, {}
    for name in PINS:
        path = getattr(args, name)
        profiles[name], decoded[name] = inspect(pinned(path, PINS[name]), parser)
        profiles[name]["file"] = path.name
    a,b = decoded["adobe"], decoded["matrix"]
    difference = {name: {"payload_equal": profiles["adobe"]["tags"][name]["sha256"] == profiles["matrix"]["tags"][name]["sha256"],
                        "max_abs_element_difference": max(abs(x-y) for x,y in zip(a[name],b[name]))}
                  for name in ("ColorMatrix1", "ColorMatrix2")}
    sources, parsed = {}, {}
    for relative, expected in REPORT_PINS.items():
        parsed[relative], sources[relative] = captured_json(args.k3_root / relative, expected)
    catalog = parsed["analysis/adobe-profiles.json"]
    k3 = next(row for row in catalog if row["file"] == "PENTAX K-3 Mark III Adobe Standard.dcp")
    shared = set(k3["tags"]) & set(profiles["adobe"]["tags"])
    as_shot = parsed["analysis/lightroom-as-shot.json"]
    record = {"schema": 1, "task": "Q7-DCP-STRUCTURE-27", "scope": "static DCP aggregate analysis; no renderer, RAW, camera or firmware execution",
              "parser": {"path": "inspect_adobe_profiles.py", "sha256_lf": PARSER_SHA},
              "source_reports": sources, "profiles": profiles, "color_matrix_difference": difference,
              "adobe_forward_pair_payload_equal": profiles["adobe"]["tags"]["ForwardMatrix1"]["sha256"] == profiles["adobe"]["tags"]["ForwardMatrix2"]["sha256"],
              "k3iii_archived_comparison": {"file": k3["file"], "sha256": k3["sha256"],
                    "matching_shared_payloads": sorted(n for n in shared if k3["tags"][n]["sha256"] == profiles["adobe"]["tags"][n]["sha256"]),
                    "differing_shared_payloads": sorted(n for n in shared if k3["tags"][n]["sha256"] != profiles["adobe"]["tags"][n]["sha256"]),
                    "tone_curve_present": "ProfileToneCurve" in k3["tags"], "input_reparsed": False},
              "historical_as_shot_q7": as_shot["observed_ui"]["q7-adobe-standard"], "self_checks": tests}
    return record


def canonical(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")).hexdigest()


def publication_metadata():
    return {"task": "Q7-DCP-PUBLIC-28", "research_code_sha256": RESEARCH_CODE_SHA,
            "public_code_sha256_lf": sha256(capture(Path(__file__)).replace(b"\r\n", b"\n")).hexdigest(),
            "research_record_sha256": RESEARCH_RECORD_SHA,
            "observations_canonical_sha256": OBSERVATIONS_SHA,
            "k3iii_public_commit": K3_COMMIT,
            "k3iii_sources": {p: "https://github.com/yunhyok/pentax-k3iii-firmware-analysis/blob/" + K3_COMMIT + "/" + p
                              for p in ("inspect_adobe_profiles.py", *REPORT_PINS)},
            "capture_contract": "open once; fstat regular descriptor; cap 2000000; read cap+1; hash and parse same captured bytes",
            "environment_fields": ["profiles.*.file", "source_reports.*.sha256"],
            "hash_contract": "DCP uses exact bytes; helper and report pins normalize CRLF to LF; raw report SHA describes local bytes",
            "historical_postcheck": "inputs_unchanged_after_analysis belongs to research 27; public replay captures once and does not repeat that postcheck"}


def validate_report(record):
    observations = {k: v for k, v in record.items() if k not in ("_publication", "_reproduction")}
    require(canonical(observations) == OBSERVATIONS_SHA, "Complete research-27 observations differ")
    require(record.get("_publication") == publication_metadata(), "Publication metadata or public code differs")
    if "_reproduction" in record:
        r = record["_reproduction"]
        require(set(r) == {"observations_match_after_environment_normalization", "input_filenames", "source_report_hashes", "post_analysis_input_reread"}, "Unknown reproduction metadata")
        require(r["observations_match_after_environment_normalization"] is True and r["post_analysis_input_reread"] is False, "Invalid reproduction status")
        require(set(r["input_filenames"]) == set(PINS) and all(isinstance(x, str) for x in r["input_filenames"].values()), "Invalid input labels")
        require(set(r["source_report_hashes"]) == set(REPORT_PINS), "Missing reproduction source")
        for p, hashes in r["source_report_hashes"].items():
            require(set(hashes) == {"sha256", "sha256_lf"} and hashes["sha256_lf"] == REPORT_PINS[p], "Reproduction source LF hash differs")
            require(isinstance(hashes["sha256"], str) and len(hashes["sha256"]) == 64 and all(c in "0123456789abcdef" for c in hashes["sha256"]), "Invalid raw source hash")
    return observations


def load_record():
    record = json.loads(capture(ROOT / "analysis/q7-dcp-structure.json"))
    validate_report(record)
    return record


def compare_observations(actual, frozen):
    expected = deepcopy(validate_report(frozen))
    expected.pop("inputs_unchanged_after_analysis")
    actual = deepcopy(actual)
    for role in PINS:
        actual["profiles"][role].pop("file")
        expected["profiles"][role].pop("file")
    for p in REPORT_PINS:
        actual["source_reports"][p].pop("sha256")
        expected["source_reports"][p].pop("sha256")
    require(actual == expected, "Reproduced observations differ beyond documented environment fields")


def output_preflight(path):
    require(not lexists(path) and path.parent.is_dir(), "Output must be a new path, including no dangling symlink")


def write_result(path, record):
    data = (json.dumps(record, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
    output_preflight(path)  # Repeat immediately before creation; Windows x mode alone is insufficient.
    with path.open("xb") as stream:
        stream.write(data)
    return sha256(data).hexdigest()


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--check-record", action="store_true", help="CI: validate the public record without DCPs or K-3 III checkout")
    for name in ("k3-root", "adobe", "matrix", "output"):
        cli.add_argument("--" + name, type=Path)
    args = cli.parse_args()
    try:
        if args.check_record:
            require(all(getattr(args, n) is None for n in ("k3_root", "adobe", "matrix", "output")), "Do not mix check-record and replay arguments")
            load_record()
            print("Complete research observations and publication metadata: PASS")
            return
        require(all(getattr(args, n) is not None for n in ("k3_root", "adobe", "matrix", "output")), "Replay requires --k3-root --adobe --matrix --output")
        output_preflight(args.output)  # Reject existing/dangling outputs before reading any input.
        frozen = load_record()
        actual = analyze(args)
        compare_observations(actual, frozen)
        result = deepcopy(frozen)
        result["_reproduction"] = {"observations_match_after_environment_normalization": True,
            "input_filenames": {role: actual["profiles"][role]["file"] for role in PINS},
            "source_report_hashes": actual["source_reports"], "post_analysis_input_reread": False}
        validate_report(result)
        digest = write_result(args.output, result)
        print(json.dumps({"output": args.output.name, "sha256": digest, "complete_observations_preserved": True}))
    except (OSError, ValueError, struct.error) as error:
        cli.exit(1, f"DCP verification failed: {error}\n")


if __name__ == "__main__":
    main()
