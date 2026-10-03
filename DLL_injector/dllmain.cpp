#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>

// 全局变量，用于控制循环的运行与停止
volatile bool g_isRunning = false; 

// 注入DLL到目标进程 (保持不变)
bool InjectDLL(DWORD pid, const char* dllPath) {
    // ... 你原来的 InjectDLL 代码保持不变 ...
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDllPath) { CloseHandle(hProcess); return false; }

    if (!WriteProcessMemory(hProcess, pDllPath, dllPath, strlen(dllPath) + 1, NULL)) {
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE); CloseHandle(hProcess); return false;
    }

    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!pLoadLibrary) { VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE); CloseHandle(hProcess); return false; }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pDllPath, 0, NULL);
    if (!hThread) { VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE); CloseHandle(hProcess); return false; }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    std::cout << "DLL注入成功!" << std::endl;
    return true;
}

// 导出：开始检测与注入 (增加 dllPath 参数)
extern "C" __declspec(dllexport) bool StartInject(const char* dllPath) {
    // 如果路径为空，直接失败
    if (dllPath == nullptr || strlen(dllPath) == 0) return false;

    // 如果已经在运行，则直接返回
    if (g_isRunning) return false;

    g_isRunning = true; // 开启标志
    const wchar_t* targetProcessName = L"HTGame.exe";
    DWORD targetPid = 0;

    // 将 while(true) 改为 while(g_isRunning)
    while (g_isRunning) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            continue;
        }

        PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
        BOOL bRet = Process32First(hSnapshot, &pe);

        while (bRet) {
            if (_wcsicmp(pe.szExeFile, targetProcessName) == 0) {
                targetPid = pe.th32ProcessID;
                break;
            }
            bRet = Process32Next(hSnapshot, &pe);
        }

        CloseHandle(hSnapshot);

        if (targetPid != 0) {
            // 找到进程，执行注入 (使用 C# 传进来的绝对路径)
            InjectDLL(targetPid, dllPath);
            break; // 注入后退出检测循环
        }

        Sleep(0); 
    }

    g_isRunning = false; // 结束标志
    return (targetPid != 0);
}


// 导出：停止检测
extern "C" __declspec(dllexport) void StopDetect() {
    g_isRunning = false; // 只要设置为 false，C++里的 while 循环就会在下次迭代时退出
}

// 导出函数：提供给C#通过HANDLE直接调用的接口
extern "C" __declspec(dllexport) bool Injectdll(HANDLE hProcess, const char* dllPath)
{
    if (hProcess == NULL || dllPath == NULL || strlen(dllPath) == 0)
    {
        return false;
    }

    // 【核心修改点】将 C# 传来的 HANDLE 转换为 PID，然后直接丢给内部的 InjectDLL 处理
    DWORD pid = GetProcessId(hProcess);
    if (pid == 0)
    {
        return false; // 句柄无效或无权限获取PID
    }

    // 直接复用内部逻辑，不写重复代码
    return InjectDLL(pid, dllPath);
}