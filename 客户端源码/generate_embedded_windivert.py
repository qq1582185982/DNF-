#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成嵌入式 WinDivert 文件的 C++ 头文件
将 WinDivert.dll 和 WinDivert64.sys 转换为字节数组
"""

import os
import sys

def file_to_cpp_array(filepath, array_name):
    """将文件转换为 C++ 字节数组"""
    with open(filepath, 'rb') as f:
        data = f.read()

    size = len(data)

    # 生成 C++ 数组声明（使用 static 确保每个编译单元有自己的副本）
    lines = []
    lines.append(f"// {os.path.basename(filepath)} ({size} bytes)")
    lines.append(f"static const unsigned char {array_name}[] = {{")

    # 每行16个字节
    for i in range(0, size, 16):
        chunk = data[i:i+16]
        hex_values = ', '.join(f'0x{b:02x}' for b in chunk)
        lines.append(f"    {hex_values},")

    lines.append("};")
    lines.append(f"static const unsigned int {array_name}_SIZE = {size};")
    lines.append("")

    return '\n'.join(lines)

def main():
    print("Generating embedded WinDivert files...")

    # Check if files exist
    dll_file = "WinDivert.dll"
    sys_file = "WinDivert64.sys"

    if not os.path.exists(dll_file):
        print(f"ERROR: Cannot find {dll_file}")
        sys.exit(1)

    if not os.path.exists(sys_file):
        print(f"ERROR: Cannot find {sys_file}")
        sys.exit(1)

    # Generate header file
    header_content = []
    header_content.append("/*")
    header_content.append(" * Embedded WinDivert Files")
    header_content.append(" * Auto-generated, do not edit manually")
    header_content.append(" */")
    header_content.append("")
    header_content.append("#ifndef EMBEDDED_WINDIVERT_H")
    header_content.append("#define EMBEDDED_WINDIVERT_H")
    header_content.append("")

    # Convert DLL
    print(f"  Processing {dll_file}...")
    header_content.append(file_to_cpp_array(dll_file, "EMBEDDED_WINDIVERT_DLL"))

    # Convert SYS
    print(f"  Processing {sys_file}...")
    header_content.append(file_to_cpp_array(sys_file, "EMBEDDED_WINDIVERT_SYS"))

    header_content.append("#endif // EMBEDDED_WINDIVERT_H")
    header_content.append("")

    # Write to file
    output_file = "embedded_windivert.h"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header_content))

    dll_size = os.path.getsize(dll_file)
    sys_size = os.path.getsize(sys_file)
    total_size = dll_size + sys_size

    print(f"OK Generated: {output_file}")
    print(f"  WinDivert.dll:    {dll_size:,} bytes")
    print(f"  WinDivert64.sys:  {sys_size:,} bytes")
    print(f"  Total:            {total_size:,} bytes ({total_size/1024:.1f} KB)")

if __name__ == "__main__":
    main()
