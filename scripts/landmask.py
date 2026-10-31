"""Turn world-atlas land-110m TopoJSON into a compact land bitmask for a dot-matrix map.

This is how src/rastro/assets/land.json was made (step 1.5 degrees). The input is
land-110m.json from the world-atlas npm package (version 2), built from Natural Earth's
1:110m land polygons, which are in the public domain.

Usage: python -I landmask.py <land-110m.json> <out.json> [step_degrees]
Writes {cols, rows, lon0, lat0, step, b64} and prints an ASCII preview.
"""
import base64
import bisect
import json
import sys

src, out = sys.argv[1], sys.argv[2]
step = float(sys.argv[3]) if len(sys.argv) > 3 else 1.5
LAT_TOP, LAT_BOTTOM = 84.0, -57.0  # leave Antarctica out

with open(src, encoding="utf-8") as f:
    topo = json.load(f)

(sx, sy), (tx, ty) = topo["transform"]["scale"], topo["transform"]["translate"]
arcs = []
for arc in topo["arcs"]:
    x = y = 0
    pts = []
    for dx, dy in arc:
        x += dx
        y += dy
        pts.append((x * sx + tx, y * sy + ty))
    arcs.append(pts)


def arc_points(i):
    return arcs[i] if i >= 0 else arcs[~i][::-1]


def ring(indices):
    pts = []
    for k, i in enumerate(indices):
        a = arc_points(i)
        pts.extend(a if k == 0 else a[1:])
    return pts


rings = []


def collect(geom):
    kind = geom["type"]
    if kind == "GeometryCollection":
        for g in geom["geometries"]:
            collect(g)
    elif kind == "Polygon":
        rings.extend(ring(r) for r in geom["arcs"])
    elif kind == "MultiPolygon":
        for poly in geom["arcs"]:
            rings.extend(ring(r) for r in poly)


collect(topo["objects"]["land"])

edges = []
for r in rings:
    for i in range(len(r)):
        edges.append((r[i - 1], r[i]))

cols = int(round(360 / step))
rows = int(round((LAT_TOP - LAT_BOTTOM) / step))
bits = []
preview = []
for row in range(rows):
    lat = LAT_TOP - (row + 0.5) * step
    xs = []
    for (x1, y1), (x2, y2) in edges:
        if (y1 > lat) != (y2 > lat):
            xs.append(x1 + (lat - y1) * (x2 - x1) / (y2 - y1))
    xs.sort()
    line = []
    for col in range(cols):
        lon = -180 + (col + 0.5) * step
        land = bisect.bisect_left(xs, lon) % 2 == 1
        bits.append(1 if land else 0)
        line.append("#" if land else ".")
    preview.append("".join(line))

while len(bits) % 8:
    bits.append(0)
packed = bytes(
    sum(bit << (7 - j) for j, bit in enumerate(bits[i:i + 8])) for i in range(0, len(bits), 8)
)
data = {
    "cols": cols,
    "rows": rows,
    "lon0": -180,
    "lat0": LAT_TOP,
    "step": step,
    "b64": base64.b64encode(packed).decode("ascii"),
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(data, f)

print(f"cols={cols} rows={rows} land={sum(bits)} b64_chars={len(data['b64'])}")
for line in preview[::3]:
    print(line[::3])
