#include <Windows.h>
#include <iostream>
#include"decrypt.h"
bool requestAdminPrivileges() {
    // ��ȡ��ǰ����·��
    TCHAR szFileName[MAX_PATH];
    if (GetModuleFileName(NULL, szFileName, MAX_PATH) == 0) {
        std::cerr << "Failed to get the executable path" << std::endl;
        return false;
    }

    // �����½������������ԱȨ��
    SHELLEXECUTEINFO shExecInfo;
    ZeroMemory(&shExecInfo, sizeof(shExecInfo));
    shExecInfo.cbSize = sizeof(shExecInfo);
    shExecInfo.fMask = SEE_MASK_FLAG_DDEWAIT | SEE_MASK_FLAG_NO_UI;
    shExecInfo.hwnd = NULL;
    shExecInfo.lpVerb = L"runas";  // "runas" ��ʾ�Թ���Ա�������
    shExecInfo.lpFile = szFileName; // ��ǰ����·��
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
        // �����ǰ�û����ǹ���Ա�������������ԱȨ��
        if (!requestAdminPrivileges()) {
            std::cerr << "Could not get administrator privileges." << std::endl;
            return 1;
        }
        // �������ԱȨ�޳ɹ����˳������µĽ��̻��Թ���ԱȨ������
        return 0;
    }

    dect();// �����������е���������
    std::cout << "You have administrator privileges!" << std::endl;

    return 0;
}
