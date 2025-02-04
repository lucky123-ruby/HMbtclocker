#include <Windows.h>
#include <iostream>
#include"decrypt.h"
bool requestAdminPrivileges() {
    // 获取当前程序路径
    TCHAR szFileName[MAX_PATH];
    if (GetModuleFileName(NULL, szFileName, MAX_PATH) == 0) {
        std::cerr << "Failed to get the executable path" << std::endl;
        return false;
    }

    // 启动新进程以请求管理员权限
    SHELLEXECUTEINFO shExecInfo;
    ZeroMemory(&shExecInfo, sizeof(shExecInfo));
    shExecInfo.cbSize = sizeof(shExecInfo);
    shExecInfo.fMask = SEE_MASK_FLAG_DDEWAIT | SEE_MASK_FLAG_NO_UI;
    shExecInfo.hwnd = NULL;
    shExecInfo.lpVerb = L"runas";  // "runas" 表示以管理员身份运行
    shExecInfo.lpFile = szFileName; // 当前程序路径
    shExecInfo.lpParameters = NULL;
    shExecInfo.lpDirectory = NULL;
    shExecInfo.nShow = SW_NORMAL;

    if (ShellExecuteEx(&shExecInfo) == 0) {
        std::cerr << "Failed to request administrator privileges" << std::endl;
        return false;
    }

    return true;
}

int main() {
    if (!IsUserAnAdmin()) {
        // 如果当前用户不是管理员，尝试请求管理员权限
        if (!requestAdminPrivileges()) {
            std::cerr << "Could not get administrator privileges." << std::endl;
            return 1;
        }
        // 请求管理员权限成功后退出程序，新的进程会以管理员权限运行
        return 0;
    }

    dect();// 程序正常运行的其他代码
    std::cout << "You have administrator privileges!" << std::endl;

    return 0;
}
