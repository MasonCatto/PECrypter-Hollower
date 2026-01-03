#include <windows.h>
#include <cstdint>
#include <vector>

#pragma pack(push, 1)
struct PIndex {
    uint32_t mval;
    uint8_t  fkey;
    uint32_t tsize;
    uint16_t ccount;
    uint16_t fchkid;
    uint32_t crc32;
    uint16_t shseed;
};
#pragma pack(pop)

unsigned char* LoadResBID(int id, DWORD* size) {     
    HMODULE hMod = GetModuleHandle(NULL);
    if (!hMod) return nullptr;
    HRSRC hRes = FindResourceA(hMod, MAKEINTRESOURCEA(id), (LPCSTR)RT_RCDATA);
    if (!hRes) return nullptr;
    *size = SizeofResource(hMod, hRes);
    HGLOBAL hGlob = LoadResource(hMod, hRes);
    if (!hGlob) return nullptr;
    return (unsigned char*)LockResource(hGlob);
}

std::vector<char> RecFWRP() {
    DWORD iSize = 0;
    unsigned char* idata = LoadResBID(999, &iSize);
    if (!idata || iSize < sizeof(PIndex)) return {};

    PIndex* idx = (PIndex*)idata;
    std::vector<char> pbuf;
    pbuf.reserve(idx->tsize);

    for (int i = 0; i < idx->ccount; ++i) {
        int resId = idx->fchkid + i;
        DWORD chksize = 0;
        unsigned char* resBuf = LoadResBID(resId, &chksize);
        
        if (resBuf && chksize > 0) {
            pbuf.insert(pbuf.end(), (char*)resBuf, (char*)resBuf + chksize);
        } else {
            return {};
        }
    }

    return pbuf;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    std::vector<char> data = RecFWRP();
    if (data.empty()) return -1;

    return 0;
}