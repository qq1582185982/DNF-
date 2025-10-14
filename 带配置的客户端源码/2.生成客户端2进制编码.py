#!/usr/bin/env python3
"""
Convert exe file to C++ byte array
"""

import sys
import os

def exe_to_cpp_array(exe_path, output_path):
    """Convert exe file to C++ byte array header"""

    if not os.path.exists(exe_path):
        print(f"Error: File not found: {exe_path}")
        return False

    # Read exe file
    with open(exe_path, 'rb') as f:
        exe_data = f.read()

    file_size = len(exe_data)
    print(f"Reading {exe_path}...")
    print(f"File size: {file_size} bytes ({file_size/1024:.1f} KB)")

    # Generate C++ array
    cpp_content = []
    cpp_content.append("// Auto-generated embedded client binary")
    cpp_content.append(f"// Source: {os.path.basename(exe_path)}")
    cpp_content.append(f"// Size: {file_size} bytes ({file_size/1024:.1f} KB)")
    cpp_content.append("")
    cpp_content.append("#ifndef EMBEDDED_CLIENT_H")
    cpp_content.append("#define EMBEDDED_CLIENT_H")
    cpp_content.append("")
    cpp_content.append("#include <cstdint>")
    cpp_content.append("#include <cstddef>")
    cpp_content.append("")
    cpp_content.append(f"const size_t EMBEDDED_CLIENT_SIZE = {file_size};")
    cpp_content.append("")
    cpp_content.append("const uint8_t EMBEDDED_CLIENT_DATA[] = {")

    # Write bytes in rows of 16
    for i in range(0, file_size, 16):
        chunk = exe_data[i:i+16]
        hex_bytes = ', '.join(f'0x{b:02x}' for b in chunk)
        cpp_content.append(f"    {hex_bytes},")

    cpp_content.append("};")
    cpp_content.append("")
    cpp_content.append("#endif // EMBEDDED_CLIENT_H")
    cpp_content.append("")

    # Write to file
    with open(output_path, 'w') as f:
        f.write('\n'.join(cpp_content))

    print(f"Generated: {output_path}")
    print(f"Array size: {file_size} bytes")
    return True

if __name__ == '__main__':
    exe_path = 'tcp_proxy_client_base.exe'
    output_path = 'embedded_client.h'

    if len(sys.argv) > 1:
        exe_path = sys.argv[1]
    if len(sys.argv) > 2:
        output_path = sys.argv[2]

    if exe_to_cpp_array(exe_path, output_path):
        print("Conversion successful!")
        sys.exit(0)
    else:
        print("Conversion failed!")
        sys.exit(1)
