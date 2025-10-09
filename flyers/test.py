#!/usr/bin/env python3
"""
Pixel Art Upscaler
- Recursively scans a folder for images (PNG/JPG/JPEG by default)
- Upscales with NEAREST (no blur) for clean pixel edges
- Saves to an 'upscaled' directory, preserving folder structure

Usage:
  python upscaler.py            # 8x (32->256) upscale in current folder
  python upscaler.py --path .\Sprites
  python upscaler.py --scale 10 # 10x upscale
  python upscaler.py --size 320 # force largest dimension to 320px, preserving aspect
  python upscaler.py --ext .png .gif --overwrite
"""

import argparse
import sys
import os
from pathlib import Path
from PIL import Image

SUPPORTED_DEFAULT_EXTS = [".png", ".jpg", ".jpeg"]

def parse_args():
    p = argparse.ArgumentParser(description="Upscale pixel art with nearest-neighbor.")
    p.add_argument("--path", type=str, default=".", help="Folder to scan (default: current).")
    p.add_argument("--out", type=str, default="upscaled", help="Output folder (default: upscaled).")
    p.add_argument("--scale", type=int, default=8, help="Scale factor (default: 8 → 32×32 → 256×256).")
    p.add_argument("--size", type=int, default=None,
                   help="Optional target size for the LONGEST side (overrides --scale).")
    p.add_argument("--ext", nargs="*", default=SUPPORTED_DEFAULT_EXTS,
                   help="Extensions to include (default: .png .jpg .jpeg)")
    p.add_argument("--overwrite", action="store_true", help="Overwrite existing outputs.")
    p.add_argument("--flat", action="store_true",
                   help="Do not mirror subfolders; put all outputs directly in OUT.")
    return p.parse_args()

def is_image(path: Path, exts):
    return path.is_file() and path.suffix.lower() in {e.lower() for e in exts}

def target_size_from_scale(w, h, scale):
    return (max(1, w * scale), max(1, h * scale))

def target_size_from_longest(w, h, longest):
    # Preserve aspect; scale so the longest side == longest
    if w >= h:
        scale = max(1, longest // max(1, w))
    else:
        scale = max(1, longest // max(1, h))
    # Ensure at least 1px
    return (max(1, w * scale), max(1, h * scale))

def upscale_image(src: Path, dst: Path, scale: int, longest_side: int | None, overwrite: bool) -> bool:
    if dst.exists() and not overwrite:
        return False  # skipped
    try:
        with Image.open(src) as im:
            # Convert to RGBA to preserve transparency reliably
            if im.mode not in ("RGBA", "RGB", "P", "LA", "L"):
                im = im.convert("RGBA")
            else:
                # Convert palette images to RGBA to avoid weird palette scaling
                if im.mode == "P":
                    im = im.convert("RGBA")

            w, h = im.size
            if longest_side:
                new_w, new_h = target_size_from_longest(w, h, longest_side)
            else:
                new_w, new_h = target_size_from_scale(w, h, scale)

            # Use NEAREST for crisp pixels
            up = im.resize((new_w, new_h), resample=Image.NEAREST)

            # Ensure output parent exists
            dst.parent.mkdir(parents=True, exist_ok=True)

            # Save as PNG to preserve transparency and avoid JPEG artifacts
            save_as = dst.with_suffix(".png")
            up.save(save_as, format="PNG", optimize=True)
            return True
    except Exception as e:
        print(f"[ERROR] {src}: {e}")
        return False

def main():
    args = parse_args()
    root = Path(args.path).resolve()
    out_root = Path(args.out).resolve()

    if not root.exists():
        print(f"[!] Input path not found: {root}")
        sys.exit(1)

    exts = args.ext
    # Normalize extensions to include leading dot
    exts = [e if e.startswith(".") else f".{e}" for e in exts]

    files = [p for p in root.rglob("*") if is_image(p, exts)]
    if not files:
        print("[!] No images found with extensions:", ", ".join(exts))
        sys.exit(0)

    print(f"[i] Found {len(files)} image(s).")
    print(f"[i] Output folder: {out_root}")
    if args.size:
        print(f"[i] Mode: longest-side to {args.size}px (aspect preserved)")
    else:
        print(f"[i] Mode: scale ×{args.scale}")

    done = 0
    skipped = 0
    for idx, src in enumerate(files, 1):
        if args.flat:
            rel_out = src.with_suffix(".png").name
            dst = out_root / rel_out
        else:
            rel = src.relative_to(root)
            dst = out_root / rel  # we will change suffix to .png inside save

        changed = upscale_image(src, dst, args.scale, args.size, args.overwrite)
        if changed:
            done += 1
            if idx % 25 == 0 or idx == len(files):
                print(f"  - {idx}/{len(files)} processed…")
        else:
            skipped += 1

    print(f"\n[✓] Completed.")
    print(f"    Upcaled: {done}")
    print(f"    Skipped: {skipped} (already existed, use --overwrite to replace)")

if __name__ == "__main__":
    main()
