"""Bounded LZ repair windows using the original compiled Huffman tables.

Adapted from the independently replayed HQ fixed-table probe. This does not
regenerate tables, relocate blocks or search beyond the selected token windows.
"""
from bisect import bisect_left
from collections import defaultdict

from decode_segments import table_symbol

MAX_CANDIDATES = 1_000_000

def leaf_prefixes(table, is_literal):
    if not table:
        raise ValueError('empty compiled table')
    codes = {}
    for prefix in range(1 << 15):
        bits = f'{prefix:015b}' + '0' * 32
        cursor = 0

        def peek(n):
            if not 0 <= n <= len(bits) - cursor:
                raise ValueError('invalid table prefix width')
            return int(bits[cursor:cursor + n], 2) if n else 0

        def take(n):
            nonlocal cursor
            value = peek(n)
            cursor += n
            return value

        try:
            word = table_symbol(table, is_literal, take, peek)
        except ValueError:
            continue
        if 0 < cursor <= 15:
            code = bits[:cursor]
            if code in codes and codes[code] != word:
                raise ValueError('ambiguous compiled table prefix')
            codes[code] = word
    if not codes:
        raise ValueError('compiled table has no usable positive-width prefixes')
    return codes


def copy_codes(literal, distance):
    lengths, distances = {}, {}
    for table, is_length, lookup in ((literal, True, lengths), (distance, False, distances)):
        for code, word in leaf_prefixes(table, is_length).items():
            if is_length:
                if word < 0x400 or not word & 0x800 or word >> 12 > 5:
                    continue
                extra, base = word >> 12, (word >> 2) & 0x1ff
            else:
                extra = word >> 4
                if extra > 13 or (extra and not word & 8):
                    continue
                base = (((word >> 2) & 3) << extra) + 1
            for x in range(1 << extra):
                value = base + x
                if is_length and not 3 <= value <= 258:
                    continue
                candidate = code + (f'{x:0{extra}b}' if extra else '')
                previous = lookup.get(value)
                if previous is None or (len(candidate), candidate) < (len(previous), previous):
                    lookup[value] = candidate
    return lengths, distances


def encode_window(target, start, end, literals, lengths, distances, budget=None):
    """Minimize bits inside one window, allowing overlapping history copies."""
    if not 0 <= start < end <= len(target):
        raise ValueError('invalid repair window')
    if budget is None:
        budget = [MAX_CANDIDATES]
    prefixes = defaultdict(list)
    max_distance = max(distances, default=0)
    for pos in range(max(0, start - max_distance), end - 2):
        prefixes[target[pos:pos + 3]].append(pos)
    costs, choices = {end: 0}, {}
    for pos in range(end - 1, start - 1, -1):
        literal = literals.get(target[pos])
        best = (len(literal) + costs[pos + 1], literal, 1, 0) if literal and pos + 1 in costs else None
        cap = min(258, end - pos)
        if cap >= 3:
            sources = prefixes[target[pos:pos + 3]]
            first = bisect_left(sources, pos - max_distance)
            last = bisect_left(sources, pos)
            budget[0] -= last - first
            if budget[0] < 0:
                raise ValueError('fixed-table candidate budget exceeded')
            by_cap = {}
            for source in sources[first:last]:
                d = pos - source
                distance_code = distances.get(d)
                if not distance_code:
                    continue
                lo, hi = 3, cap
                while lo < hi:
                    mid = (lo + hi + 1) // 2
                    if target[source:source + mid] == target[pos:pos + mid]:
                        lo = mid
                    else:
                        hi = mid - 1
                current = (len(distance_code), distance_code, d)
                previous = by_cap.get(lo)
                if previous is None or current < previous:
                    by_cap[lo] = current
            best_distance = None
            for length in range(cap, 2, -1):
                current = by_cap.get(length)
                if current is not None and (best_distance is None or current < best_distance):
                    best_distance = current
                length_code = lengths.get(length)
                if length_code and best_distance is not None and pos + length in costs:
                    dcost, dcode, d = best_distance
                    candidate = (len(length_code) + dcost + costs[pos + length], length_code + dcode, length, d)
                    if best is None or candidate < best:
                        best = candidate
        if best is not None:
            costs[pos], code, length, distance = best
            choices[pos] = code, length, distance
    if start not in choices:
        raise ValueError('repair window cannot be represented by the fixed tables')
    pos, codes, copies = start, [], []
    while pos < end:
        code, length, distance = choices[pos]
        codes.append(code)
        if distance:
            copies.append((pos, length, distance))
        pos += length
    return ''.join(codes), copies


def repair_windows(target, rows, patch_ranges, literal, distance, literals):
    """Group tokens overlapping each direct patch; repair other invalid tokens."""
    windows = [(i, i + 1) for i, row in enumerate(rows) if not row[2]]
    for lo, hi in patch_ranges:
        selected = [i for i, row in enumerate(rows) if row[1] > lo and row[0] < hi and row[0] != row[1]]
        if selected:
            windows.append((selected[0], selected[-1] + 1))
    merged = []
    for lo, hi in sorted(windows):
        if merged and lo < merged[-1][1]:
            merged[-1] = merged[-1][0], max(hi, merged[-1][1])
        else:
            merged.append((lo, hi))
    lengths, distances = copy_codes(literal, distance)
    encoded, copies, i = [], [], 0
    budget = [MAX_CANDIDATES]
    for first, last in merged:
        encoded.extend(row[3] for row in rows[i:first])
        code, added = encode_window(target, rows[first][0], rows[last - 1][1], literals, lengths, distances, budget)
        encoded.append(code)
        copies.extend(added)
        i = last
    encoded.extend(row[3] for row in rows[i:])
    return ''.join(encoded), dict(windows=len(merged), replaced_tokens=sum(b-a for a,b in merged),
                                 new_copy_tokens=len(copies),
                                 new_cross_block_copy_tokens=sum(p-d < rows[0][0] for p,_,d in copies))
