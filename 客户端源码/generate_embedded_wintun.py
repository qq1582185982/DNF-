#!/usr/bin/env python3
"""
Convert wintun.dll to a C++ embedded header.
"""

import os
import sys


def dll_to_cpp_array(dll_path, output_path):
    if not os.path.exists(dll_path):
        print(f"Error: File not found: {dll_path}")
        return False

    with open(dll_path, "rb") as f:
        dll_data = f.read()

    file_size = len(dll_data)
    print(f"Reading {dll_path}...")
    print(f"File size: {file_size} bytes ({file_size / 1024:.1f} KB)")

    cpp = []
    cpp.append("// Auto-generated embedded wintun runtime")
    cpp.append(f"// Source: {os.path.basename(dll_path)}")
    cpp.append(f"// Size: {file_size} bytes ({file_size / 1024:.1f} KB)")
    cpp.append("")
    cpp.append("#ifndef EMBEDDED_WINTUN_H")
    cpp.append("#define EMBEDDED_WINTUN_H")
    cpp.append("")
    cpp.append("#include <cstddef>")
    cpp.append("#include <cstdint>")
    cpp.append("")
    cpp.append(f"const size_t EMBEDDED_WINTUN_DLL_SIZE = {file_size};")
    cpp.append("")
    cpp.append("const uint8_t EMBEDDED_WINTUN_DLL[] = {")

    for i in range(0, file_size, 16):
        chunk = dll_data[i:i + 16]
        hex_bytes = ", ".join(f"0x{b:02x}" for b in chunk)
        cpp.append(f"    {hex_bytes},")

    cpp.append("};")
    cpp.append("")
    cpp.append("#endif // EMBEDDED_WINTUN_H")
    cpp.append("")

    with open(output_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(cpp))

    print(f"Generated: {output_path}")
    return True


if __name__ == "__main__":
    dll_path = "wintun.dll"
    output_path = "embedded_wintun.h"

    if len(sys.argv) > 1:
        dll_path = sys.argv[1]
    if len(sys.argv) > 2:
        output_path = sys.argv[2]

    if dll_to_cpp_array(dll_path, output_path):
        print("Conversion successful!")
        sys.exit(0)

    print("Conversion failed!")
    sys.exit(1)
