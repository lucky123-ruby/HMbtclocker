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

// �ֶ����� NT_SUCCESS ��
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// Base64 �����
const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

// Base64 ���뺯��
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

// ��������
// ȷ���ڵ��ú���֮ǰ�Ѿ���������


void handleError(const char* message) {
    std::cerr << message << " Error code: " << GetLastError() << std::endl;
    exit(1);
}
// ȷ���ڵ��ú���֮ǰ�Ѿ���������
ULONG detectMaxRSAKeyLength() {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        handleError("Failed to open algorithm provider for key length detection.");
    }

    const ULONG possibleKeyLengths[] = { 2048, 4096 };  // ֻ���� 2048 �� 4096 λ
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

// ������Կ���ļ�
void saveKeyToFile(const std::wstring& filename, const std::string& key) {
    std::ofstream file(filename);
    if (!file) {
        handleError("Failed to open file for writing key.");
    }
    file << key;
    file.close();
}

// ��ȡ�ļ����ݵ��ֽ�����
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

// д���ֽ��������ļ�
void writeFile(const std::wstring& filename, const std::vector<BYTE>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        handleError("Failed to open file for writing.");
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
}

// ���ϵͳ֧�ֵ���� RSA ��Կ����
void rsaEncryptFile(const std::wstring& inputFilePath, const std::wstring& publicKeyPath, const std::wstring& privateKeyPath) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    SetConsoleOutputCP(CP_UTF8);
    std::wcout << L"Input file path: " << inputFilePath << std::endl;
    std::wcout << L"Public key path: " << publicKeyPath << std::endl;
    std::wcout << L"Private key path: " << privateKeyPath << std::endl;

    // �� RSA �㷨�ṩ����
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        handleError("Failed to open algorithm provider.");
    }

    // ���ϵͳ֧�ֵ������Կ����
    ULONG maxKeyLength = detectMaxRSAKeyLength();
    if (maxKeyLength == 0) {
        handleError("Could not determine a supported key length.");
    }

    // ������Կ����
    status = BCryptSetProperty(hAlg, BCRYPT_KEY_LENGTH, reinterpret_cast<PUCHAR>(&maxKeyLength), sizeof(maxKeyLength), 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        handleError("Failed to set key length.");
    }

    // ������Կ��
    status = BCryptGenerateKeyPair(hAlg, &hKey, 0, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        handleError("Failed to generate key pair.");
    }

    // ����ȷ����Կ
    status = BCryptFinalizeKeyPair(hKey, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        handleError("Failed to finalize key pair.");
    }

    // ������Կ
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

    // ����˽Կ
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

    // ��ȡҪ���ܵ��ļ�����
    std::vector<BYTE> plaintext = readFile(inputFilePath);

    // �����ļ�����
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

    // ���ܺ���ļ�·��
    std::wstring encryptedFilePath = inputFilePath + L".hm";  // �޸ĺ�׺Ϊ .hm
    std::wcout << L"Encrypted file path: " << encryptedFilePath << std::endl;

    // �����ܺ���ļ�·��
    if (std::filesystem::exists(encryptedFilePath)) {
        std::wcout << L"File exists: " << encryptedFilePath << std::endl;
    }
    else {
        std::wcout << L"File does NOT exist: " << encryptedFilePath << std::endl;
    }

    // д����ܺ�����ݵ����ļ�
    writeFile(encryptedFilePath, ciphertext);

    // ɾ��ԭʼ�ļ�
    if (!std::filesystem::remove(inputFilePath)) {
        handleError("Failed to remove original file.");
    }

    // ������Դ
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}


int encryptrsa() {
    SetConsoleOutputCP(CP_UTF8);
    std::wstring inputFilePath = L"aes_key.bin";
    std::wstring publicKeyPath = L"public_key.bin";
    std::wstring privateKeyPath = L"private_key.bin";

    // �̶���Կ
    std::string key = "abcdefghyfhyfmylmyl";
    // Base64 ������Կ
    std::string encodedKey = base64_encode(key);

    // ��ȡϵͳ�ĵ��ļ���·��
    PWSTR pszPath = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Documents, 0, NULL, &pszPath))) {
        std::wstring documentsPath(pszPath);
        CoTaskMemFree(pszPath);  // �ͷ��ڴ�

        // �����������Կ�ļ�������·��
        std::wstring encodedKeyPath = documentsPath + L"\\encoded_key.txt";

        // �����������Կ���ļ�
        saveKeyToFile(encodedKeyPath, encodedKey);

        // ִ�� RSA ���ܲ���
        rsaEncryptFile(inputFilePath, publicKeyPath, privateKeyPath);

        std::cout << "Encryption completed successfully." << std::endl;
        std::wcout << L"Encoded key saved to: " << encodedKeyPath << std::endl;
    }
    else {
        handleError("Failed to get documents folder path.");
    }

    return 0;
}


