#!/usr/bin/env python3
import os
import sys

def split_log(input_path: str, lines_per_file: int) -> None:
    if lines_per_file <= 0:
        raise ValueError("lines_per_file must be > 0")

    base_dir = os.path.dirname(os.path.abspath(input_path))
    base_name = os.path.basename(input_path)

    # Split "x.log" -> stem="x", ext=".log"
    stem, ext = os.path.splitext(base_name)
    if ext == "":
        ext = ".log"

    part_idx = 0
    line_idx_in_part = 0
    out_fh = None

    def open_next_file():
        nonlocal part_idx, line_idx_in_part, out_fh
        if out_fh:
            out_fh.close()
        part_idx += 1
        line_idx_in_part = 0
        out_path = os.path.join(base_dir, f"{stem}{part_idx}{ext}")
        out_fh = open(out_path, "w", encoding="utf-8", errors="replace", newline="")
        return out_path

    current_out_path = None
    total_lines = 0

    with open(input_path, "r", encoding="utf-8", errors="replace") as in_fh:
        for line in in_fh:
            if out_fh is None or line_idx_in_part >= lines_per_file:
                current_out_path = open_next_file()

            out_fh.write(line)
            line_idx_in_part += 1
            total_lines += 1

    if out_fh:
        out_fh.close()

    if total_lines == 0:
        print(f"No lines found in '{input_path}'. No output files created.")
        return

    print(f"Split complete: {total_lines} lines -> {part_idx} file(s)")
    print(f"Output pattern: {os.path.join(base_dir, f'{stem}1{ext}')} ... {os.path.join(base_dir, f'{stem}{part_idx}{ext}')}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 split_log.py <input_log_file> <lines_per_file>")
        print("Example: python3 split_log.py x.log 5000")
        sys.exit(1)

    input_file = sys.argv[1]
    try:
        lines_per_file = int(sys.argv[2])
    except ValueError:
        print("Error: lines_per_file must be an integer")
        sys.exit(1)

    split_log(input_file, lines_per_file)