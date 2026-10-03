#include <array>
#include <vector>
#include <atomic>
#include <thread>
#include <string>
#include <unordered_set>

// 防止 windows.h 定义 min 和 max 宏，避免与 std::min/std::max 冲突
#define NOMINMAX
// 减少 Windows.h 包含的内容，加快编译速度
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <Psapi.h>

#pragma comment(lib, "Psapi.lib")

#include "PatternScanner.hpp"
// #include "MinHookManager.h"
#include "HookUtility.h"

int g_TargetFps = 60;         // 用于存储目标帧率
int g_PowerSaving = -1;       // 用于存储省电模式状态 (0=关, 1=开)
int g_ProcessPriority = -1;   // 用于存储进程优先级 (0=Realtime, 1=High, 2=Above Normal, 3=Normal, 4=Below Normal, 5=Low)
int g_UnlimitedFpsMode = -1; // 用于存储是否无限帧率模式 (0=关, 1=开)

// 加密后的字符串数据
namespace encrypted_strings {
    //NTE Fps MEM_code
    //constexpr auto fps_code = XorString::encrypt("47 00 43 00 20 00 6D 00 6F 00 64 00 65 00 2C 00 20 00 69 00 6E 00 20 00 4D 00 42 00 00 00 00 00 48");
    // 260501
    constexpr auto fps_code = XorString::encrypt("47 00 43 00 20 00 6D 00 6F 00 64 00 65 00 2C 00 20 00 69 00 6E 00 20 00 4D 00 42 00 00 00 00 00");
    constexpr auto pipe_code = XorString::encrypt("\\\\.\\pipe\\655FEE20-FCEC-47F9-AE54-CB3C132D22C3");
}

// 辅助函数：向调试器输出格式化字符串
void DebugPrint(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);
    OutputDebugStringA(buffer);
}

BOOL __declspec(noinline) OnWinError(const char* szFunction, DWORD dwError)
{
    char szMessage[256];
    wsprintfA(szMessage, "%s failed with error %d", szFunction, dwError);
    MessageBoxA(nullptr, szMessage, "Error", MB_ICONERROR);

    //if (pIPCData)
    //    pIPCData->Status = IPCStatus::Error;

    return FALSE;
}


std::atomic<bool> g_IsRunning(true);


// 管道名称定义
//const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\655FEE20-FCEC-47F9-AE54-CB3C132D22C3";
const char* PIPE_NAME = "";
const int PIPE_BUFFER_SIZE = 4096;

// ============================================================
// 【通信处理逻辑】
// ============================================================
void HandleClient(HANDLE hPipe) {
    char recvbuf[PIPE_BUFFER_SIZE];
    DWORD bytesRead = 0;

    while (g_IsRunning) {
        // 1. 读取数据 (对应 Socket 的 recv)
        // ReadFile 在管道中是阻塞的，如果客户端断开，它会返回 FALSE 或返回 0 字节
        BOOL bSuccess = ReadFile(
            hPipe,
            recvbuf,
            PIPE_BUFFER_SIZE - 1, // 留一位给 '\0'
            &bytesRead,
            NULL
        );

        if (bSuccess && bytesRead > 0) {
            // 安全处理字符串结尾
            recvbuf[bytesRead] = '\0';

            // 解析数据 (保持原样)
            int itemsMatched = sscanf_s(recvbuf, "%d,%d,%d,%d",
                &g_TargetFps, &g_PowerSaving, &g_ProcessPriority, &g_UnlimitedFpsMode);

            // (可选) 如果需要回复，可以使用 WriteFile
            // const char* reply = "OK";
            // DWORD written;
            // WriteFile(hPipe, reply, (DWORD)strlen(reply), &written, NULL);
        }
        else {
            // 客户端断开或出错
            // 对于管道，如果 ReadFile 返回 0 或 FALSE，通常意味着连接断开
            if (!bSuccess) {
                int error = GetLastError();
                // ERROR_BROKEN_PIPE (109): 客户端正常关闭
                // ERROR_NO_DATA (232): 客户端关闭了写句柄
                if (error != ERROR_BROKEN_PIPE && error != ERROR_NO_DATA)
                {
                    //DebugPrint("[DLL] Pipe read error: %d\n", error);
                }
            }
            break; // 退出循环
        }
    }

    // 2. 清理连接
    // 管道不需要像 TCP 那样复杂的 shutdown 等待流程
    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe); // 断开与客户端的连接，准备下一次连接
    CloseHandle(hPipe);         // 关闭当前句柄
    //DebugPrint("[DLL] Pipe client disconnected.\n");
}

// ============================================================
// 【服务端主循环】
// ============================================================
DWORD WINAPI RunNetService(LPVOID lpParam)
{
    auto _pipe_code = XorString::decrypt(encrypted_strings::pipe_code.data(), encrypted_strings::pipe_code.size());
    PIPE_NAME = _pipe_code.c_str();

    // 循环处理连接
    while (g_IsRunning)
    {
        // 1. 创建命名管道实例
        // PIPE_ACCESS_DUPLEX: 双向通信 (如果只需要接收可用 PIPE_ACCESS_INBOUND)
        //HANDLE hPipe = CreateNamedPipe(
        //    PIPE_NAME,
        //    PIPE_ACCESS_DUPLEX,       // 双向
        //    PIPE_TYPE_MESSAGE |       // 消息流模式 (类似 TCP 的消息边界)
        //    PIPE_READMODE_MESSAGE |
        //    PIPE_WAIT,
        //    PIPE_UNLIMITED_INSTANCES, // 最大实例数
        //    PIPE_BUFFER_SIZE,         // 输出缓冲
        //    PIPE_BUFFER_SIZE,         // 输入缓冲
        //    0,                        // 默认超时
        //    NULL                      // 默认安全
        //);

        // 窄字符版，使用CreateNamedPipeA而不是CreateNamedPipe
        HANDLE hPipe = CreateNamedPipeA(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX,       // 双向
            PIPE_TYPE_MESSAGE |       // 消息流模式 (类似 TCP 的消息边界)
            PIPE_READMODE_MESSAGE |
            PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, // 最大实例数
            PIPE_BUFFER_SIZE,         // 输出缓冲
            PIPE_BUFFER_SIZE,         // 输入缓冲
            0,                        // 默认超时
            NULL                      // 默认安全
        );


        if (hPipe == INVALID_HANDLE_VALUE) {
            OnWinError("CreateNamedPipe", GetLastError());
            Sleep(1000); // 出错等待一下防止死循环刷屏
            continue;
        }

        // 2. 等待客户端连接 (对应 Socket 的 accept)
        // ConnectNamedPipe 是阻塞的。
        // 为了能响应 g_IsRunning 退出，我们在创建句柄后，
        // 依靠 ConnectNamedPipe 的阻塞等待。
        // 如果需要非常及时的退出响应，可以使用重叠(IO)模式，但这里保持简单。

        BOOL bConnected = ConnectNamedPipe(hPipe, NULL);

        // 如果 ConnectNamedPipe 返回 0，检查是否是因为客户端已连接
        if (!bConnected && GetLastError() != ERROR_PIPE_CONNECTED) {
            // 连接失败，关闭句柄重试
            CloseHandle(hPipe);
            continue;
        }

        // 3. 客户端已连接，处理通信
        // 注意：这里是在主服务线程中直接处理。
        // 如果处理耗时较长，建议创建新线程传参 hPipe，否则会阻塞后续连接。
        // 但参考原代码 HandleClient 是阻塞的，这里保持一致。
        HandleClient(hPipe);

        // HandleClient 内部已经调用了 CloseHandle，这里不需要再次关闭
    }

    //DebugPrint("[DLL] Pipe service stopped.\n");
    return 0;
}



// 枚举窗口的回调数据
struct EnumWindowsData {
    DWORD processId;
    HWND foundWindow;
};

// 枚举回调函数
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    EnumWindowsData* data = (EnumWindowsData*)lParam;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);

    if (pid == data->processId && IsWindowVisible(hwnd)) {
        if (GetWindowTextLengthA(hwnd) > 0) {
            char className[256];
            GetClassNameA(hwnd, className, sizeof(className));

            if (strcmp(className, "UnrealWindow") == 0) {
                data->foundWindow = hwnd;
                return FALSE; // 停止枚举
            }
        }
    }
    return TRUE;
}

// 检查Unity主窗口是否存在（单次检查）
bool IsUnityWindowReady() {
    EnumWindowsData data;
    data.processId = GetCurrentProcessId();
    data.foundWindow = NULL;

    EnumWindows(EnumWindowsProc, (LPARAM)&data);

    return (data.foundWindow != NULL);
}

// 循环等待Unity主窗口出现
bool WaitForUnityWindow(DWORD timeoutMs = 30000) {
    DWORD startTime = GetTickCount();

    while (GetTickCount() - startTime < timeoutMs) {
        if (IsUnityWindowReady()) {
            return true; // 找到了
        }
        Sleep(2);
    }

    return false; // 超时
}


// 辅助函数：查找当前进程的 Unity 主窗口句柄
HWND FindMyUnityWindow() {
    struct EnumData {
        DWORD processId;
        HWND hwnd;
    } data;

    data.processId = GetCurrentProcessId();
    data.hwnd = nullptr;

    // 枚举所有窗口，找到属于当前进程且类名为 UnityWndClass 的窗口
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        EnumData* pData = reinterpret_cast<EnumData*>(lParam);
        DWORD windowProcessId = 0;
        GetWindowThreadProcessId(hwnd, &windowProcessId);

        if (windowProcessId == pData->processId && IsWindowVisible(hwnd)) {
            char className[256] = { 0 };
            GetClassNameA(hwnd, className, sizeof(className));
            // Unity 主窗口的类名通常是 UnityWndClass
            if (strcmp(className, "UnrealWindow") == 0) {
                pData->hwnd = hwnd;
                return FALSE; // 找到了，停止枚举
            }
        }
        return TRUE; // 继续枚举
        }, reinterpret_cast<LPARAM>(&data));

    return data.hwnd;
}

// 安全写入 float
BOOL SafeWriteFloat(uintptr_t address, float value) {
    __try {
        *(float*)address = value;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

// 线程函数：循环向指定地址写入 300.0
void WriteThreadProc(uintptr_t addr)
{
    //DebugPrint("[DLL] Write thread started for address 0x%p\n", reinterpret_cast<void*>(addr));

    HANDLE hProcess = GetCurrentProcess();
    // 用于记录上一次实际写入的优先级索引，用于判断是否需要更新
    // 初始化为 -1，确保程序启动时会执行一次设置
    static int s_LastPriorityIndex = -1;

    while (true)
    {
        // --- 1. 进程优先级处理逻辑 (优先处理) ---

        // 计算“当前应该设置的优先级索引”
        // 默认为用户配置的全局优先级
        int currentTargetPriority = g_ProcessPriority;

        // 检查是否处于“省电模式”下的“失焦”状态
        bool shouldThrottlePriority = false;
        if (g_PowerSaving == 1)
        {
            static HWND hGameWnd = nullptr;
            // 动态获取窗口句柄
            if (!hGameWnd || !IsWindow(hGameWnd)) {
                hGameWnd = FindMyUnityWindow();
            }

            if (hGameWnd) {
                // 如果窗口存在且不在前台（失去焦点）
                if (GetForegroundWindow() != hGameWnd) {
                    shouldThrottlePriority = true;
                }
            }
        }

        // 如果满足降频条件，强制覆盖优先级索引为 5 (IDLE_PRIORITY_CLASS)
        if (shouldThrottlePriority) {
            currentTargetPriority = 5;
        }

        // 只有当配置有效时才尝试设置
        if (currentTargetPriority >= 0)
        {
            // 核心判断：如果当前目标优先级 与 上一次写入的优先级 不同，才执行写入
            if (currentTargetPriority != s_LastPriorityIndex)
            {
                DWORD dwPriorityClass = NORMAL_PRIORITY_CLASS; // 默认值

                // 索引映射到 Windows API 宏
                switch (currentTargetPriority)
                {
                case 0: dwPriorityClass = REALTIME_PRIORITY_CLASS; break;
                case 1: dwPriorityClass = HIGH_PRIORITY_CLASS; break;
                case 2: dwPriorityClass = ABOVE_NORMAL_PRIORITY_CLASS; break;
                case 3: dwPriorityClass = NORMAL_PRIORITY_CLASS; break;
                case 4: dwPriorityClass = BELOW_NORMAL_PRIORITY_CLASS; break;
                case 5: dwPriorityClass = IDLE_PRIORITY_CLASS; break;
                }

                // 写入优先级
                if (SetPriorityClass(hProcess, dwPriorityClass))
                {
                    s_LastPriorityIndex = currentTargetPriority;
                    //DebugPrint("[DLL] Process priority changed to index: %d (Throttled: %s)\n",currentTargetPriority, shouldThrottlePriority ? "Yes" : "No");
                }
            }
        }

        // --- 2. 帧率写入逻辑 ---

        int _fps = g_TargetFps;

        if (g_UnlimitedFpsMode == 1)
        {
            _fps = 3157;
        }

        // 复用上面的 shouldThrottlePriority 判断结果
        // 如果之前判定需要降频优先级，这里同时也把帧率限制为 15
        if (shouldThrottlePriority)
        {
            _fps = 15;
        }

        SafeWriteFloat(addr, _fps);

        Sleep(10);
    }
}


// 消息框线程函数
static DWORD WINAPI MessageBoxThreadGeneric(LPVOID lpParameter) {
    // 安全检查：确保传入了字符串
    if (lpParameter == nullptr) return 1;

    // 将参数转为 const char*
    const char* message = static_cast<const char*>(lpParameter);

    MessageBoxA(nullptr, message, "Error", MB_ICONWARNING);
    return 0;
}

// 安全读取内存（使用 SEH）
BOOL SafeReadMemory(LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize) {
    __try {
        memcpy(lpBuffer, lpAddress, nSize);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

// 安全读取 float
BOOL SafeReadFloat(uintptr_t address, float* outValue) {
    return SafeReadMemory((LPCVOID)address, outValue, sizeof(float));
}

void RunLogic()
{
    //// 直接等待Unity窗口（阻塞）
    if (WaitForUnityWindow(60000))
    {
        //DebugPrint("[DLL] Found Unity window, proceeding with hook installation.\n");
        Sleep(50);
    }


    auto startTime = GetTickCount64(); // 记录开始时间
    const DWORD TIMEOUT_MS = 2 * 60 * 1000; // 2分钟
    std::vector<uintptr_t> results;

    auto _fps_code = XorString::decrypt(encrypted_strings::fps_code.data(), encrypted_strings::fps_code.size());

    while (true)
    {
        results = PatternScanner::MultipleScan(_fps_code.c_str());

        if (!results.empty())
        {
            break;
        }

        // 判断是否超时
        if (GetTickCount64() - startTime > TIMEOUT_MS)
        {
            CreateThread(nullptr, 0, MessageBoxThreadGeneric, (LPVOID)"FPS pattern failed!", 0, nullptr);
            return;
        }

        Sleep(500);
    }

    // 取第一个结果，向高地址搜索字节序列 5A 00 ?? ??
    uintptr_t searchStart = results[0];
    const BYTE targetPattern[] = { 0x5A, 0x00, 0x00, 0x00 }; // 0x00 保留原样占位
    const BOOL  patternMask[] = { TRUE, TRUE, FALSE, FALSE }; // TRUE=严格匹配，FALSE=通配符(即跳过0x23)
    const int MAX_HIGH_OFFSET = 1000;
    uintptr_t markerAddr = 0;

    for (int i = 0; i <= MAX_HIGH_OFFSET - sizeof(targetPattern); ++i) {
        uintptr_t testAddr = searchStart + i;
        BYTE buffer[4];
        if (!SafeReadMemory((LPCVOID)testAddr, buffer, sizeof(buffer))) {
            break; // 不可读，退出搜索
        }

        // 自定义匹配逻辑
        bool matched = true;
        for (int j = 0; j < sizeof(targetPattern); ++j) {
            if (patternMask[j] && buffer[j] != targetPattern[j]) {
                matched = false;
                break;
            }
        }

        if (matched) {
            markerAddr = testAddr;
            break;
        }
    }

    if (markerAddr == 0) {
        CreateThread(nullptr, 0, MessageBoxThreadGeneric, (LPVOID)"FPS pattern2 failed!", 0, nullptr);
        return;
    }


    // 4. 从 markerAddr 向低地址搜索 **第二组** 30.0/60.0/120.0（循环扫描版）

    const int MAX_LOW_OFFSET = 300;        // 扫描范围
    const DWORD SEARCH_TIMEOUT_MS = 30000; // 30秒

    uintptr_t targetAddr = 0;
    float foundValue = 0.0f;

    DWORD startTick = GetTickCount();

    uintptr_t currentAddr = markerAddr;

    int matchCount = 0;
    uintptr_t firstMatchAddr = 0;
    float firstMatchValue = 0.0f;

    // 防止重复命中同一地址
    std::unordered_set<uintptr_t> visited;

    while (true)
    {
        // ✅ 超时判断
        if (GetTickCount() - startTick > SEARCH_TIMEOUT_MS)
        {
            CreateThread(nullptr, 0, MessageBoxThreadGeneric, (LPVOID)"FPS 36120 timeout!", 0, nullptr);
            return;
        }

        // ✅ 如果扫完范围，就从头再来（关键修复点）
        if ((markerAddr - currentAddr) > (uintptr_t)MAX_LOW_OFFSET)
        {
            currentAddr = markerAddr;
        }

        float val;

        if (SafeReadFloat(currentAddr, &val))
        {
            // ✅ 判断是否是目标值
            if (fabsf(val - 30.0f) < 0.001f ||
                fabsf(val - 60.0f) < 0.001f ||
                fabsf(val - 120.0f) < 0.001f)
            {
                // ✅ 防止重复统计同一地址
                if (visited.insert(currentAddr).second)
                {
                    matchCount++;

                    if (matchCount == 1)
                    {
                        firstMatchAddr = currentAddr;
                        firstMatchValue = val;
                    }
                    else if (matchCount == 2)
                    {
                        targetAddr = currentAddr;
                        foundValue = val;
                        break;
                    }
                }
            }
        }

        currentAddr--;

        // ✅ 防止CPU占满 + 让“30秒逻辑”有意义
        Sleep(1);
    }

    if (targetAddr == 0)
    {
        CreateThread(nullptr, 0, MessageBoxThreadGeneric, (LPVOID)"FPS 36120 failed!", 0, nullptr);
        return;
    }

    // 启动独立线程循环写入 (保持原有逻辑)
    std::thread(WriteThreadProc, targetAddr).detach();
    //DebugPrint("[DLL] Write thread detached for address 0x%p\n", reinterpret_cast<void*>(targetAddr));

    //MessageBox(NULL, TEXT("Inject fps ok!"), TEXT("Notification"), MB_ICONINFORMATION | MB_OK);
}



BOOL APIENTRY DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpReserved)
{
    if (hInstance)
        DisableThreadLibraryCalls(hInstance);

    // 检查是否是目标进程 260202
    HMODULE hYuanShen = GetModuleHandleA("YuanShen.exe");
    HMODULE hGenshinImpact = GetModuleHandleA("GenshinImpact.exe");
    HMODULE hStarRail = GetModuleHandleA("HTGame.exe");

    // 如果不是目标进程，直接返回TRUE（DLL加载成功但不初始化）
    if (!hYuanShen && !hGenshinImpact && !hStarRail) {
        return TRUE;
    }

    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        //const auto hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)RunLogic, nullptr, 0, nullptr);
        //if (!hThread)
        //    return OnWinError("CreateThread", GetLastError());

        //CloseHandle(hThread);


        // 260202 启动逻辑线程更改
        LPTHREAD_START_ROUTINE startRoutine = nullptr;

        // 判断当前是哪个进程
        if (hYuanShen || hGenshinImpact) {
            // ys或genshin进程，执行ys逻辑
            //startRoutine = (LPTHREAD_START_ROUTINE)RunLogicGenshin;
        }
        else if (hStarRail) {
            // sr进程，执行sr逻辑
            startRoutine = (LPTHREAD_START_ROUTINE)RunLogic;
        }

        if (startRoutine) {
            const auto hThread = CreateThread(nullptr, 0, startRoutine, nullptr, 0, nullptr);
            if (!hThread)
                return OnWinError("CreateThread", GetLastError());

            CloseHandle(hThread);

            // 启动网络服务线程
            const auto hThreadNet = CreateThread(nullptr, 0, RunNetService, nullptr, 0, nullptr);
            if (!hThreadNet)
            {
                return OnWinError("CreateThreadNet", GetLastError());
            }
            CloseHandle(hThreadNet);
        }
    }
    else if (fdwReason == DLL_PROCESS_DETACH)
    {
        // 禁用所有钩子
        //MinHookManager::DisableAllHooks();
    }

    return TRUE;

}