"""Q7 DCP bounded interpolation and independent Decimal reference.

Copied formulas from research-29; not native SDK execution.
SPDX-License-Identifier: GPL-2.0-only
"""
"""Bounded mathematical SDR/linear-encoding LUT probe, not native SDK execution.

Formula source: pinned DNG SDK 1.7.1 dng_reference.cpp:1508-1762.
Python binary64 arithmetic intentionally does not claim native real32 bit identity.
"""
import math


def interpolate(values, dimensions, hsv):
    """Return weighted (hue shift degrees, saturation scale, value scale).

    Input H is degrees in [0,360), S,V in [0,1]. Values are full stored
    V-major, H-middle, S-minor triplets. Encoding=linear, overrange=false.
    """
    nh, ns, nv = dimensions
    if any(type(n) is not int for n in dimensions) or nh < 1 or ns < 2 or nv < 1:
        raise ValueError('Invalid dimensions')
    if len(values) != 3 * nh * ns * nv or not all(map(math.isfinite, values)):
        raise ValueError('Invalid table payload')
    h, s, v = hsv
    if not all(map(math.isfinite, hsv)) or not (0 <= h < 360 and 0 <= s <= 1 and 0 <= v <= 1):
        raise ValueError('Expected finite normalized SDR HSV')
    hp = h * nh / 360 if nh > 1 else 0.0
    sp = s * (ns - 1)
    vp = v * (nv - 1)
    h0 = min(int(hp), nh - 1)
    h1 = (h0 + 1) % nh
    s0 = min(int(sp), ns - 2)
    v0 = min(int(vp), nv - 2) if nv > 1 else 0
    hf, sf, vf = hp - h0, sp - s0, vp - v0
    def node(hh, ss, vv, channel):
        return values[3 * ((vv * nh + hh) * ns + ss) + channel]
    def along_h(ss, vv, channel):
        return (1 - hf) * node(h0, ss, vv, channel) + hf * node(h1, ss, vv, channel)
    result = []
    for channel in range(3):
        low = along_h(s0, v0, channel)
        high = along_h(s0 + 1, v0, channel)
        if nv > 1:
            low = (1 - vf) * low + vf * along_h(s0, v0 + 1, channel)
            high = (1 - vf) * high + vf * along_h(s0 + 1, v0 + 1, channel)
        result.append((1 - sf) * low + sf * high)
    return result


def apply_linear(hsv, coefficients):
    """HSV-domain result; gray hue is not an observed RGB property."""
    if not all(map(math.isfinite, (*hsv, *coefficients))):
        raise ValueError('Non-finite input')
    h, s, v = hsv
    dh, ds, dv = coefficients
    if ds < 0 or dv < 0:
        raise ValueError('This bounded probe requires nonnegative scales')
    return [(h + dh) % 360, min(s * ds, 1.0), min(max(v * dv, 0.0), 1.0)]

"""Independent Decimal tensor weights over every lattice node.

Does not import the scalar implementation or reuse its cell selection/strides.
This is an independent formula cross-check, not an independent SDK runtime.
"""
from decimal import Decimal, localcontext


def reference(values, dimensions, hsv):
    nh, ns, nv = dimensions
    with localcontext() as ctx:
        ctx.prec = 50
        h, s, v = (Decimal(str(x)) for x in hsv)
        hp, sp, vp = h * nh / 360, s * (ns - 1), v * (nv - 1)
        totals = [Decimal(0)] * 3
        total_weight = Decimal(0)
        nodes = iter(zip(values[::3], values[1::3], values[2::3]))
        for vv in range(nv):
            wv = max(Decimal(0), 1 - abs(vp - vv)) if nv > 1 else Decimal(1)
            for hh in range(nh):
                distance = abs(hp - hh)
                wh = max(Decimal(0), 1 - min(distance, nh - distance)) if nh > 1 else Decimal(1)
                for ss in range(ns):
                    point = next(nodes)
                    ws = max(Decimal(0), 1 - abs(sp - ss))
                    weight = wv * wh * ws
                    total_weight += weight
                    for i, value in enumerate(point):
                        totals[i] += weight * Decimal.from_float(float(value))
        if abs(total_weight - 1) > Decimal('1e-40'):
            raise ValueError('Reference partition did not sum to one')
        return [float(x) for x in totals]
