#include <Windows.h>
#include <string>
#include "MinHookManager.h"   // 你原有的 MinHook 封装

HMODULE g_hModule = NULL;
std::wstring GetLocalDllPath()
{
    wchar_t path[MAX_PATH] = { 0 };

    GetModuleFileNameW(g_hModule, path, MAX_PATH);

    std::wstring fullPath = path;

    size_t pos = fullPath.find_last_of(L"\\/");
    if (pos != std::wstring::npos)
    {
        fullPath = fullPath.substr(0, pos + 1);
    }

    fullPath += L"ulk_nte_tol.dll";

    return fullPath;
}

bool HasEnabledX11()
{
    LPCWSTR cmd = GetCommandLineW();

    if (cmd && wcsstr(cmd, L"-enabledx11"))
        return true;

    return false;
}

// 返回值：-customparam= 后面的参数值（已去除外层引号，若存在）
std::wstring GetCustomParamValue()
{
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv)
        return L"";

    std::wstring value;
    const std::wstring prefix = L"-customparam=";

    for (int i = 0; i < argc; ++i)
    {
        std::wstring arg = argv[i];
        if (arg.size() > prefix.size() &&
            _wcsnicmp(arg.c_str(), prefix.c_str(), prefix.size()) == 0)
        {
            value = arg.substr(prefix.size());   // 去掉前缀，只保留后面的部分

            // 如果值用引号包围（如 -customparam="hello world"），则去除外层引号
            if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"')
                value = value.substr(1, value.size() - 2);
            break;
        }
    }

    LocalFree(argv);
    return value;
}

// 通过命名管道通知 C# 进程：注入成功
void NotifyCSharpInjectionSuccess(const std::wstring& processName)
{
    // 约定管道名称（需与 C# 端一致）
    const wchar_t* pipeName = L"\\\\.\\pipe\\9AA45FF9-1CB0-46E6-B37E-452F65E4A1DA";

    // 等待管道服务器就绪（最多尝试 2 秒）
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 20; ++attempt)  // 每 100ms 尝试一次
    {
        hPipe = CreateFileW(
            pipeName,
            GENERIC_WRITE,
            0,                     // 不共享
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
        if (hPipe != INVALID_HANDLE_VALUE)
            break;
        Sleep(100);
    }

    if (hPipe == INVALID_HANDLE_VALUE)
        return;  // 管道服务器未启动，放弃通知

    DWORD dwMode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);

    std::wstring message = L"Injected:HTGame";
    DWORD bytesWritten = 0;
    WriteFile(hPipe, message.c_str(),
        (DWORD)(message.size() * sizeof(wchar_t)),
        &bytesWritten, NULL);
    FlushFileBuffers(hPipe);
    CloseHandle(hPipe);
}






// 原 ExitProcess 类型
typedef void (WINAPI* ExitProcess_t)(UINT uExitCode);
ExitProcess_t OriginalExitProcess = nullptr;

void WINAPI HookedExitProcess(UINT uExitCode)
{
    // 1. 发送退出通知给 C# 管道（重新打开连接、写入、关闭）
    const wchar_t* pipeName = L"\\\\.\\pipe\\9AA45FF9-1CB0-46E6-B37E-452F65E4A1DA";
    HANDLE hPipe = CreateFileW(pipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE)
    {
        DWORD dwMode = PIPE_READMODE_MESSAGE;
        SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);

        std::wstring message = L"Exiting";   // 约定的退出信号，C# 端需匹配
        DWORD bytesWritten = 0;
        WriteFile(hPipe, message.c_str(),
            (DWORD)(message.size() * sizeof(wchar_t)),
            &bytesWritten, NULL);
        FlushFileBuffers(hPipe);
        CloseHandle(hPipe);
    }

    // 2. 调用原始 ExitProcess（进程真正退出）
    OriginalExitProcess(uExitCode);
}




// 原函数类型定义
typedef BOOL(WINAPI* CreateProcessW_t)(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation);

CreateProcessW_t OriginalCreateProcessW = nullptr;

// 提取文件名（与之前相同）
std::wstring GetExecutableFileName(LPCWSTR lpApplicationName, LPWSTR lpCommandLine)
{
    std::wstring target;
    if (lpApplicationName && lpApplicationName[0] != L'\0') {
        target = lpApplicationName;
    }
    else if (lpCommandLine && lpCommandLine[0] != L'\0') {
        std::wstring cmd = lpCommandLine;
        size_t start = cmd.find_first_not_of(L" \t");
        if (start == std::wstring::npos) return L"";
        cmd = cmd.substr(start);
        if (cmd[0] == L'\"') {
            size_t end = cmd.find(L'\"', 1);
            if (end != std::wstring::npos)
                target = cmd.substr(1, end - 1);
            else
                target = cmd.substr(1);
        }
        else {
            size_t end = cmd.find_first_of(L" \t");
            if (end != std::wstring::npos)
                target = cmd.substr(0, end);
            else
                target = cmd;
        }
    }
    size_t pos = target.find_last_of(L"\\/");
    if (pos != std::wstring::npos)
        return target.substr(pos + 1);
    return target;
}

BOOL WINAPI HookedCreateProcessW(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    // 1. 检查是否是 HTGame.exe
    std::wstring fileName = GetExecutableFileName(lpApplicationName, lpCommandLine);
    if (fileName.empty() || _wcsicmp(fileName.c_str(), L"HTGame.exe") != 0) {
        // 非目标，直接放行
        return OriginalCreateProcessW(
            lpApplicationName, lpCommandLine,
            lpProcessAttributes, lpThreadAttributes,
            bInheritHandles, dwCreationFlags,
            lpEnvironment, lpCurrentDirectory,
            lpStartupInfo, lpProcessInformation);
    }

    //// 2. 是 HTGame，弹出确认框
    //int result = MessageBoxW(NULL,
    //    L"检测到启动器即将启动 HTGame，是否允许并注入 Unlock-WW-IPC.dll？",
    //    L"Hook CreateProcess",
    //    MB_YESNO | MB_ICONQUESTION);

    //if (result != IDYES) {
    //    SetLastError(ERROR_CANCELLED);
    //    return FALSE;
    //}


    //// 3. 构造新命令行：原始命令行 + 空格 + "-d3d11"
    //std::wstring newCommandLine;
    //if (lpCommandLine && lpCommandLine[0] != L'\0') {
    //    newCommandLine = std::wstring(lpCommandLine) + L" -d3d11";
    //}
    //else {
    //    newCommandLine = L"-d3d11";
    //}
    //// 注意：CreateProcessW 要求 lpCommandLine 是可修改的缓冲区，
    //// newCommandLine.data() 在 C++17 后返回 wchar_t*，安全可用；
    //// 若使用较早标准，可以用 &newCommandLine[0] 确保可写。
    //LPWSTR modifiedCmdLine = &newCommandLine[0];


    // 1. 获取自定义参数值
    std::wstring customValue = GetCustomParamValue();
    bool enableD3D11 = HasEnabledX11();

    // 2. 准备最终的命令行字符串
    std::wstring finalCmdLine;
    if (lpCommandLine && lpCommandLine[0] != L'\0') {
        finalCmdLine = lpCommandLine;
    }

    // 辅助 lambda 函数：安全地追加参数并添加空格
    auto AppendParam = [&](const std::wstring& param) {
        if (param.empty()) return;
        if (!finalCmdLine.empty()) {
            finalCmdLine += L" "; // 如果前面已经有内容，先补空格
        }
        finalCmdLine += param;
        };

    // 3. 按顺序追加参数
    // 追加自定义参数（假设你想传的是原始获取到的值）
    AppendParam(customValue);

    // 追加 DX11 参数
    if (enableD3D11) {
        AppendParam(L"-d3d11");
    }

    // 4. 处理 CreateProcess 的指针
    // 如果 finalCmdLine 为空，则保持为原始指针或 NULL
    LPWSTR modifiedCmdLine = finalCmdLine.empty() ? (LPWSTR)lpCommandLine : &finalCmdLine[0];


    //// 3、定义一个开关，设为 false 则不添加任何参数，保持默认
    //bool enableD3D11 = false;

    //if (HasEnabledX11())
    //{
    //    enableD3D11 = true;
    //}
    //else
    //{
    //    enableD3D11 = false;
    //}

    //LPWSTR modifiedCmdLine = (LPWSTR)lpCommandLine; // 默认指向原始命令行

    //if (enableD3D11) {
    //    // 只有开关打开时，才构造新命令行
    //    std::wstring newCommandLine;
    //    if (lpCommandLine && lpCommandLine[0] != L'\0') {
    //        newCommandLine = std::wstring(lpCommandLine) + L" -d3d11";
    //    }
    //    else {
    //        newCommandLine = L"-d3d11";
    //    }
    //    modifiedCmdLine = &newCommandLine[0];
    //}

    // 4. 以挂起方式创建进程，使用修改后的命令行
    DWORD newFlags = dwCreationFlags | CREATE_SUSPENDED;
    BOOL ok = OriginalCreateProcessW(
        lpApplicationName,
        modifiedCmdLine,            // 传入新命令行
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        newFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation);

    if (!ok) {
        return FALSE;
    }

    // 5. 注入 DLL（步骤与之前完全相同）
    HANDLE hProcess = lpProcessInformation->hProcess;
    HANDLE hThread = lpProcessInformation->hThread;
    //const wchar_t* dllPath = L"C:\\Users\\30lau\\Desktop\\Unlock-WW-IPC.dll";
    //const wchar_t* dllPath =L"D:\\wwfps_csharp\\NTE_unlockfps\\NTE_unlockfps\\bin\\x64\\Debug\\net9.0-windows\\ulk_nte_tools\\ulk_nte_tol.dll";

    //// 改为获取dll同目录下的ulk_nte_tol.dll
    std::wstring dllFullPath = GetLocalDllPath();
    const wchar_t* dllPath = dllFullPath.c_str();

    //std::wstring dllPath2 = GetLocalDllPath();
    //MessageBoxW(NULL, dllPath2.c_str(), L"当前路径", MB_OK);



    LPTHREAD_START_ROUTINE loadLibAddr = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!loadLibAddr) {
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        SetLastError(ERROR_DLL_NOT_FOUND);
        return FALSE;
    }

    size_t pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMem) {
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, pathSize, NULL)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        return FALSE;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0,
        loadLibAddr, remoteMem, 0, NULL);
    if (!hRemoteThread) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        return FALSE;
    }

    WaitForSingleObject(hRemoteThread, INFINITE);
    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);

    // 6. 恢复主线程运行
    ResumeThread(hThread);

    // 7. 通知 C# 注入成功
    NotifyCSharpInjectionSuccess(fileName);   // fileName = "HTGame.exe"

    return TRUE;
}

// 安装 / 卸载 Hook（与原来一致）
void InstallHook()
{
    if (MH_Initialize() != MH_OK) {
        MessageBoxW(NULL, L"MinHook 初始化失败", L"错误", MB_ICONERROR);
        return;
    }
    if (MH_CreateHookApi(
        L"kernel32.dll", "CreateProcessW",
        &HookedCreateProcessW,
        reinterpret_cast<LPVOID*>(&OriginalCreateProcessW)) != MH_OK) {
        MessageBoxW(NULL, L"创建 Hook 失败", L"错误", MB_ICONERROR);
        return;
    }

    // 新增 Hook：ExitProcess
    if (MH_CreateHookApi(
        L"kernel32.dll", "ExitProcess",
        &HookedExitProcess,
        reinterpret_cast<LPVOID*>(&OriginalExitProcess)) != MH_OK) {
        MessageBoxW(NULL, L"创建 ExitProcess Hook 失败", L"错误", MB_ICONERROR);
        return;
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        MessageBoxW(NULL, L"启用 Hook 失败", L"错误", MB_ICONERROR);
        return;
    }
}

void UninstallHook()
{
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        g_hModule = hModule;
        InstallHook();
        break;
    case DLL_PROCESS_DETACH:
        UninstallHook();
        break;
    }
    return TRUE;
}