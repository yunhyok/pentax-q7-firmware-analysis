"""Replay two pure Q7 MIPS matrix routines with angr VEX; no camera/MMIO execution."""
import argparse
import hashlib
import json
import random
import struct
from pathlib import Path


def reference(left, right, shift):
    result = []
    for row in range(3):
        for col in range(3):
            total = sum(left[row * 3 + k] * right[k * 3 + col] for k in range(3))
            value = (((total + (1 << (shift - 1))) & 0xFFFFFFFF) >> shift) & 0xFFFF
            result.append(value - 0x10000 if value & 0x8000 else value)
    return result


def main():
    import angr
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must not exist")
    project = angr.Project(str(args.elf), auto_load_libs=False)
    rng = random.Random(7)
    cases = []
    for address, shift in ((0x8041BC90, 13), (0x8041BE94, 8)):
        scale = 1 << shift
        identity = [scale, 0, 0, 0, scale, 0, 0, 0, scale]
        mixed = [scale, scale//2, -scale//4, 0, scale, 17, -53, 0, scale]
        random_matrix = [rng.randint(-16000, 16000) for _ in range(9)]
        for title, left, right, alias in (("identity", identity, mixed, False),
                                         ("signed", mixed, random_matrix, False),
                                         ("alias-left", mixed, random_matrix, True)):
            destination = 0x10001000 if alias else 0x10000000
            state = project.factory.call_state(address, destination, 0x10001000, 0x10002000,
                    ret_addr=0x0BADF000, prototype="void f(void *, void *, void *)",
                    add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                 angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
            state.memory.store(0x10001000, struct.pack("<9h", *left))
            state.memory.store(0x10002000, struct.pack("<9h", *right))
            simulation = project.factory.simgr(state)
            simulation.explore(find=0x0BADF000, n=1000)
            if len(simulation.found) != 1 or simulation.errored:
                raise RuntimeError(f"incomplete replay at {address:x}: {simulation}")
            final = simulation.found[0]
            actual = list(struct.unpack("<9h", final.solver.eval(final.memory.load(destination, 18), cast_to=bytes)))
            expected = reference(left, right, shift)
            assert actual == expected, (address, actual, expected)
            cases.append(dict(address=address, shift=shift, case=title, left=left, right=right,
                              actual=actual, expected=expected, passed=True))
    result = dict(analysis_elf_sha256=hashlib.sha256(args.elf.read_bytes()).hexdigest(),
                  engine=f"angr {angr.__version__} / VEX", cases=cases,
                  scope="Concrete pure-function replay; no peripheral or camera runtime validation.")
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"{len(cases)} MIPS replay cases passed")


if __name__ == "__main__":
    main()
