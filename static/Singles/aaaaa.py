# check_pngs.py
# Run this in the same folder as your PNGs.
# It will sample up to 20 PNGs and print their metadata status.

import os, random, zlib

PNG_SIG = b"\x89PNG\r\n\x1a\n"

def is_png_signature(data: bytes) -> bool:
    return len(data) >= 8 and data[:8] == PNG_SIG

def read_uint32(b, off):
    return (b[off] << 24) | (b[off+1] << 16) | (b[off+2] << 8) | b[off+3]

def parse_chunks(data: bytes):
    """Return (chunk_types, text_map)"""
    chunks = []
    text_map = {}
    if not is_png_signature(data):
        return chunks, text_map

    off = 8
    n = len(data)
    while off + 12 <= n:
        ln = read_uint32(data, off); off += 4
        ctype = bytes(data[off:off+4]); off += 4
        start = off
        end = off + ln
        if end > n: break
        chunk_type = ctype.decode("latin-1", errors="replace")
        chunk_data = data[start:end]
        off = end + 4  # skip CRC
        chunks.append(chunk_type)

        if chunk_type == "tEXt":
            try:
                null = chunk_data.index(0)
                k = chunk_data[:null].decode("latin-1", errors="replace")
                v = chunk_data[null+1:].decode("latin-1", errors="replace")
                text_map[k] = v
            except Exception:
                pass
        elif chunk_type == "zTXt":
            try:
                null = chunk_data.index(0)
                k = chunk_data[:null].decode("latin-1", errors="replace")
                compd = chunk_data[null+2:]
                v = zlib.decompress(compd).decode("latin-1", errors="replace")
                text_map[k] = v
            except Exception:
                pass
        elif chunk_type == "iTXt":
            parts = chunk_data.split(b"\x00", 5)
            if len(parts) == 6:
                k, comp_flag, comp_method, lang, trans, txt = parts
                try:
                    if comp_flag == b"\x01":
                        v = zlib.decompress(txt).decode("utf-8", errors="replace")
                    else:
                        v = txt.decode("utf-8", errors="replace")
                    text_map[k.decode("latin-1", errors="replace")] = v
                except Exception:
                    pass

        if chunk_type == "IEND":
            break

    return chunks, text_map

def main():
    files = [f for f in os.listdir(".") if f.lower().endswith(".png")]
    if not files:
        print("No PNG files found in current folder.")
        return

    sample = files[:20]
    print(f"Checking {len(sample)} PNG(s) out of {len(files)} found...\n")

    good = 0
    for f in sample:
        with open(f, "rb") as fp:
            data = fp.read()
        chunks, meta = parse_chunks(data)
        print(f"File: {f}")
        print("  Chunks:", chunks)
        if meta:
            good += 1
            for k, v in meta.items():
                print(f"  {k} = {v}")
        else:
            print("  No PNG text metadata found.")
        print()

    print("Summary:")
    print(f"  {good}/{len(sample)} had text metadata chunks.")
    print(f"  {len(sample)-good}/{len(sample)} had none.")

if __name__ == "__main__":
    main()
