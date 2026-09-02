import struct, json

def fnv1a64(data):
    h = 0xcbf29ce484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h

path = r"E:\SteamLibrary\steamapps\common\Sid Meier's Civilization VI\DLC\Expansion2\Binaries\Win64\GameCore_XP2_FinalRelease.dll"
data = open(path, "rb").read()

e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
assert data[e_lfanew:e_lfanew+4] == b"PE\0\0"

coff = e_lfanew + 4
num_sections = struct.unpack_from("<H", data, coff + 2)[0]
size_of_opt = struct.unpack_from("<H", data, coff + 16)[0]
opt = coff + 20

magic = struct.unpack_from("<H", data, opt)[0]
assert magic == 0x20B, "not PE32+"

# data directory 第 3 项 = IMAGE_DIRECTORY_ENTRY_EXCEPTION
dd_off = opt + 112
exc_va, exc_size = struct.unpack_from("<II", data, dd_off + 3*8)

# section headers
sec_off = opt + size_of_opt
sections = []
for i in range(num_sections):
    off = sec_off + i*40
    name = data[off:off+8].rstrip(b"\0").decode("ascii", "replace")
    vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, off+8)
    sections.append((name, va, vsize, rawptr, rawsize))

def rva_to_off(rva):
    for name, va, vsize, rawptr, rawsize in sections:
        span = max(vsize, rawsize)
        if va <= rva < va + span:
            return rva - va + rawptr
    return None

count = exc_size // 12
pdata = []
for i in range(count):
    off = rva_to_off(exc_va + i*12)
    begin, end, unwind = struct.unpack_from("<III", data, off)
    size = end - begin
    uoff = rva_to_off(unwind)
    cnt = data[uoff + 2]
    ulen = 4 + 2*cnt + (cnt & 1)*2
    uh = fnv1a64(data[uoff:uoff+ulen])
    pdata.append((begin, size, uh))

pdata.sort(key=lambda x: x[0])

print("exception dir: VA=0x%x size=%d" % (exc_va, exc_size))
print("pdata 条目数: %d" % len(pdata))
print("begin_rva 范围: 0x%x ~ 0x%x" % (pdata[0][0], pdata[-1][0]))
print("首条: begin=0x%x size=%d" % (pdata[0][0], pdata[0][1]))
print("末条: begin=0x%x size=%d" % (pdata[-1][0], pdata[-1][1]))

out = {
    "dll": path,
    "exception_va": "0x%x" % exc_va,
    "exception_size": exc_size,
    "count": len(pdata),
    "entries": [{"begin_rva": "0x%x" % b, "size": s, "unwind_hash": "0x%016x" % u} for b, s, u in pdata],
}
out_path = r"E:\WorkSpace\Civ6\Civ6DllLoader\tools\runtime_pdata.json"
json.dump(out, open(out_path, "w"))
print("已保存: %s" % out_path)
