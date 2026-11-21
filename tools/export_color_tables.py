"""Export the Q7 v1.01 colour engine tables, selected by symbol name, as numbers.

The tables are read from the decoded E04 segment at the addresses that the main
address/name sidecars give for the names matched below. Values are written as
stored; nothing here states how the firmware combines them.
"""
import argparse
import json
from pathlib import Path
import re
import struct

from decode_segments import inspect as decode
from q7_symbols import recover

# group, struct format, value count, name pattern
GROUPS = (
    ("matrices_s16", "h", 9, r"^(cnsCameraBasicMatrix(Inverse)?|cnsFlatMatrix|cnsMakeUpMatrix[A-Za-z]+|cnarsSatCtlMatrix\d\d|"
                              r"cnsHueShiftMatrix\d\d|cnsHueShiftDisableMatrix|cnarsFilterEffectMatrix\d\d|arsActualMatrix3DDefault|"
                              r"arcnsSRGBAdobeRGB)$"),
    ("matrix_sets_6_s16", "h", 54, r"^cnsMakeUpMatrix[A-Za-z]+6$"),
    ("tone_u16", "H", 256, r"^(cnarwBasicTone\d+(Low|Middle|High)|cnarwReversalTone\d+)$"),
    ("dng_color_matrix_s32_pairs", "i", 18, r"^arcnlDNGColorMatrix[12]$"),
    ("ycbcr_s16", "h", 9, r"^arcnwYCbCrConversionMatrixDefault$"),
    ("chroma_offsets_s16", "h", 9, r"^(cnars(Cb|Cr)(Offset|Addition)(AdobeRGB)?|cnarsCbCrOAdditionNon)$"),
    ("tone_constants_u16", "H", 1, r"^cnwBasicTone(SaturationPointMin|SaturationPointOutput|BaseNumber)$"),
    ("composition_rate_u16", "H", 97, r"^cnwHighlightShadowCompositionRate2048$"),
    ("custom_image_records_u8", "B", 28, r"^cntCustomImageUnit[A-Za-z0-9]+$"),
    ("chroma_suppression_u16", "H", 2048, r"^arwCChromaSuppressionRatioLut$"),
    ("chroma_suppression_param_u16", "H", 17, r"^arcntChromaSuppression$"),      # the first of its equal records
)
# Statics that have no symbol of their own: (label, preceding symbol, offset from it, format, count).
ANONYMOUS = (
    ("key_table_u32", "arcwXvdEvtoRatio256", 0x124, "I", 9),
    ("reversal_bounds_u32", "arcwXvdEvtoRatio256", 0x148, "I", 7),
    ("cm_base_matrix_s16", "arcnwYCbCrConversionMatrixDefault", 0x80, "h", 9),
    ("lut_node_levels_u16", "arcnwYCbCrConversionMatrixDefault", 0x94, "H", 9),
)
SEGMENT = "E04"


def export(data):
    report, outputs = decode(data)
    segment = next(item for item in report["segments"] if item["name"] == SEGMENT)
    start, image = segment["virtual_address"], outputs[SEGMENT]
    summary, rows = recover(data)
    address = {}
    for row in rows:
        address.setdefault(row["name"], row["address"])
    result = {
        "scope": "Colour tables read from PENTAX Q7 firmware by symbol name. Values as stored; how the f"
                 "irmware combines them is described in the research notes that accompany this file.",
        "firmware": {"file": "fwdc603p.bin", "sha256": summary["input_sha256"]},
    }
    for group, fmt, count, pattern in GROUPS:
        size = struct.calcsize(f"<{count}{fmt}")
        table = {}
        for name, value in sorted(address.items(), key=lambda item: item[1]):
            if re.search(pattern, name):
                if not start <= value <= start + len(image) - size:
                    raise ValueError(f"{name} is outside the decoded {SEGMENT} segment")
                table[name] = {"address": f"{value:#010x}",
                               "values": list(struct.unpack_from(f"<{count}{fmt}", image, value - start))}
        if not table:
            raise ValueError(f"no symbol matched {group}")
        result[group] = table
    result["anonymous"] = {}
    for label, symbol, offset, fmt, count in ANONYMOUS:
        value = address[symbol] + offset
        if not start <= value <= start + len(image) - struct.calcsize(f"<{count}{fmt}"):
            raise ValueError(f"{label} is outside the decoded {SEGMENT} segment")
        result["anonymous"][label] = {"after": symbol, "offset": offset, "address": f"{value:#010x}",
                                      "values": list(struct.unpack_from(f"<{count}{fmt}", image, value - start))}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("output must not exist")
    result = export(args.firmware.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:    # the same bytes on every platform
        json.dump(result, stream, indent=1, sort_keys=True)
        stream.write("\n")
    print(json.dumps({group: len(result[group]) for group, *_ in GROUPS}))


if __name__ == "__main__":
    main()
