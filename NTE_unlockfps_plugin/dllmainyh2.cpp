// 必须放在所有 #include 之前
#define _CRT_SECURE_NO_WARNINGS 

#include <windows.h>
#include <stdio.h>
#include <string>
#include <psapi.h>
#include <ctime>
#include <TlHelp32.h>
#include <stdarg.h>     // va_list, va_start, va_end
#include <cmath>        // fabsf
#include "PatternScanner.hpp" // 特征码扫描

const DWORD LOOP_INTERVAL_MS = 10;          // 写入间隔(毫秒)
const int DUMP_RANGE = 1000;                 // 快照范围
const float TARGET_WRITE_VALUE = 300.0f;     // 最终要写入的值

volatile bool g_bIsRunning = true;

// 获取 DLL 所在目录
std::string GetDllDirectory(HMODULE hModule) {
    char path[MAX_PATH] = { 0 };
    GetModuleFileNameA(hModule, path, MAX_PATH);
    std::string::size_type pos = std::string(path).find_last_of("\\/");
    return std::string(path).substr(0, pos);
}

// 写日志（追加模式）
void LogToFile(const std::string& logPath, const char* format, ...) {
    FILE* fp = fopen(logPath.c_str(), "a");
    if (fp) {
        time_t now = time(0);
        struct tm tstruct;
        localtime_s(&tstruct, &now);
        char timeBuf[80];
        strftime(timeBuf, sizeof(timeBuf), "[%Y-%m-%d %H:%M:%S] ", &tstruct);
        fprintf(fp, "%s", timeBuf);
        va_list args;
        va_start(args, format);
        vfprintf(fp, format, args);
        va_end(args);
        fprintf(fp, "\n");
        fclose(fp);
    }
}

// 内存快照（增加基址参数用于显示偏移）
void DumpMemoryToFile(const std::string& logPath, uintptr_t targetAddr,
    uintptr_t baseAddress, const char* tag) {
    FILE* fp = fopen(logPath.c_str(), "a");
    if (!fp) return;

    uintptr_t startAddr = targetAddr - DUMP_RANGE;
    SIZE_T totalSize = DUMP_RANGE * 2;
    BYTE* buffer = (BYTE*)malloc(totalSize);
    if (buffer == NULL) { fclose(fp); return; }

    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)startAddr, buffer, totalSize, &bytesRead)) {
        fprintf(fp, "[%s] 读取内存失败 (错误码: %d)\n", tag, GetLastError());
        free(buffer); fclose(fp); return;
    }

    uintptr_t startOffset = startAddr - baseAddress;
    uintptr_t endOffset = startAddr + bytesRead - 1 - baseAddress;

    fprintf(fp, "---------- [%s] 内存快照 ----------\n", tag);
    fprintf(fp, "绝对地址: 0x%p ~ 0x%p\n", (LPVOID)startAddr, (LPVOID)(startAddr + bytesRead - 1));
    fprintf(fp, "相对偏移: EXE+0x%llX ~ EXE+0x%llX\n", (unsigned long long)startOffset, (unsigned long long)endOffset);
    fprintf(fp, "------------------------------------------------------------\n");

    for (SIZE_T i = 0; i < bytesRead; i += 16) {
        fprintf(fp, "%08llX: ", (unsigned long long)(startAddr + i));
        for (SIZE_T j = 0; j < 16; j++) {
            if (i + j < bytesRead) fprintf(fp, "%02X ", buffer[i + j]);
            else fprintf(fp, "   ");
            if (j == 7) fprintf(fp, " ");
        }
        fprintf(fp, " ");
        for (SIZE_T j = 0; j < 16; j++) {
            if (i + j < bytesRead) {
                char c = buffer[i + j];
                fprintf(fp, "%c", (c >= 32 && c <= 126) ? c : '.');
            }
        }
        fprintf(fp, "\n");
    }
    fprintf(fp, "------------------------------------------------------------\n");
    free(buffer);
    fclose(fp);
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

// 安全读取指针值（未直接使用，但保留）
BOOL SafeReadPtr(uintptr_t address, uintptr_t* outValue) {
    return SafeReadMemory((LPCVOID)address, outValue, sizeof(uintptr_t));
}

// 安全读取 float
BOOL SafeReadFloat(uintptr_t address, float* outValue) {
    return SafeReadMemory((LPCVOID)address, outValue, sizeof(float));
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

// 通过快照获取主模块（EXE）基址
uintptr_t GetMainModuleBase() {
    DWORD processId = GetCurrentProcessId();
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &me32)) {
            CloseHandle(hSnapshot);
            return (uintptr_t)me32.modBaseAddr;
        }
        CloseHandle(hSnapshot);
    }
    return 0;
}

DWORD WINAPI MainThread(LPVOID lpParam) {
    HMODULE hModule = (HMODULE)lpParam;
    std::string logPath = GetDllDirectory(hModule) + "\\config.log";
    LogToFile(logPath, "线程已启动，正在初始化...");

    // 1. 获取 EXE 基址
    uintptr_t baseAddress = GetMainModuleBase();
    if (baseAddress == 0) {
        LogToFile(logPath, "[致命错误] 无法获取主模块基址！");
        return 0;
    }
    LogToFile(logPath, "成功获取主模块基址: 0x%llX", (unsigned long long)baseAddress);

    // 2. 特征码扫描
    //auto results = PatternScanner::MultipleScanModule(
    //    "4D 00 65 00 6D 00 6F 00 72 00 79 00 20 00 74 00 68 00 72 00 65 00 73 00 68 00 6F 00 6C 00 64 00 20 00 66 00 6F 00 72 00 20 00 6C 00 6F 00 77 00 20 00 6D 00 65 00 6D 00 6F 00 72 00 79 00 20 00 47 00 43 00 20 00 6D 00 6F 00 64 00 65 00 2C 00 20 00 69 00 6E 00 20 00 4D 00 42 00 00 00 00 00",
    //    L"");
    //if (results.empty()) {
    //    LogToFile(logPath, "[错误] 未找到匹配的特征码，线程退出。");
    //    return 0;
    //}

    auto startTime = GetTickCount64(); // 记录开始时间
    const DWORD TIMEOUT_MS = 2 * 60 * 1000; // 2分钟

    std::vector<uintptr_t> results;

    while (true)
    {
        results = PatternScanner::MultipleScan(
            "47 00 43 00 20 00 6D 00 6F 00 64 00 65 00 2C 00 20 00 69 00 6E 00 20 00 4D 00 42 00 00 00 00 00 48"
        );

        if (!results.empty())
        {
            LogToFile(logPath, "特征码扫描完成，共找到 %zu 个结果:", results.size());
            break;
        }

        // 判断是否超时
        if (GetTickCount64() - startTime > TIMEOUT_MS)
        {
            LogToFile(logPath, "[错误] 2分钟内未找到匹配的特征码，线程退出。");
            return 0;
        }

        // 可选：每次失败记录日志（避免刷屏可以隔几次再打）
        LogToFile(logPath, "未找到特征码，重试中...");

        Sleep(500); // 休眠500ms，避免CPU占满（很重要）
    }

    LogToFile(logPath, "特征码扫描完成，共找到 %zu 个结果:", results.size());
    for (size_t i = 0; i < results.size(); ++i) {
        uintptr_t addr = results[i];
        LogToFile(logPath, "  结果 %zu: 0x%llX (EXE+0x%llX)",
            i + 1, (unsigned long long)addr, (unsigned long long)(addr - baseAddress));
    }

    // 3. 取第一个结果，向高地址搜索字节序列 A0 23 78 4A
    uintptr_t searchStart = results[0];
    const BYTE targetPattern[] = { 0xA0, 0x23, 0x78, 0x4A };
    const int MAX_HIGH_OFFSET = 1000;
    uintptr_t markerAddr = 0;

    LogToFile(logPath, "从特征码地址 0x%llX 开始，向高地址搜索目标字节序列 (最大偏移 %d)...",
        (unsigned long long)searchStart, MAX_HIGH_OFFSET);

    for (int i = 0; i <= MAX_HIGH_OFFSET - sizeof(targetPattern); ++i) {
        uintptr_t testAddr = searchStart + i;
        BYTE buffer[4];
        if (!SafeReadMemory((LPCVOID)testAddr, buffer, sizeof(buffer))) {
            break; // 不可读，退出搜索
        }
        if (memcmp(buffer, targetPattern, sizeof(targetPattern)) == 0) {
            markerAddr = testAddr;
            LogToFile(logPath, "找到目标字节序列位于: 0x%llX (EXE+0x%llX)",
                (unsigned long long)markerAddr, (unsigned long long)(markerAddr - baseAddress));
            DumpMemoryToFile(logPath, markerAddr, baseAddress, "标记点");
            break;
        }
    }

    if (markerAddr == 0) {
        LogToFile(logPath, "[错误] 在 %d 字节内未找到字节序列 A0 23 78 4A，线程退出。", MAX_HIGH_OFFSET);
        return 0;
    }

    // 4. 从 markerAddr 向低地址搜索 **第二组** 30.0/60.0/120.0
    const int MAX_LOW_OFFSET = 300;                // 最多向低地址搜索 300 字节
    const DWORD SEARCH_TIMEOUT_MS = 30000;         // 30 秒超时
    uintptr_t targetAddr = 0;
    float foundValue = 0.0f;
    DWORD startTick = GetTickCount();

    LogToFile(logPath, "从标记点 0x%llX 向低地址搜索 **第二组** 浮点值 (30.0/60.0/120.0)，范围 %d 字节，超时 %d 秒...",
        (unsigned long long)markerAddr, MAX_LOW_OFFSET, SEARCH_TIMEOUT_MS / 1000);

    uintptr_t currentAddr = markerAddr;
    int matchCount = 0;
    uintptr_t firstMatchAddr = 0;
    float firstMatchValue = 0.0f;

    while ((markerAddr - currentAddr) <= (uintptr_t)MAX_LOW_OFFSET) {
        // 超时检查
        if (GetTickCount() - startTick > SEARCH_TIMEOUT_MS) {
            LogToFile(logPath, "[错误] 搜索超时，仅找到 %d 个匹配，需要至少两个。", matchCount);
            return 0;
        }

        float val;
        if (!SafeReadFloat(currentAddr, &val)) {
            currentAddr--;
            continue;
        }

        // 检查是否为目标值
        if (fabsf(val - 30.0f) < 0.001f || fabsf(val - 60.0f) < 0.001f || fabsf(val - 120.0f) < 0.001f) {
            matchCount++;
            if (matchCount == 1) {
                firstMatchAddr = currentAddr;
                firstMatchValue = val;
                LogToFile(logPath, "找到第1个匹配: 值 %.1f 位于 0x%llX (EXE+0x%llX)",
                    val, (unsigned long long)currentAddr, (unsigned long long)(currentAddr - baseAddress));
                DumpMemoryToFile(logPath, currentAddr, baseAddress, "第一个匹配点");
            }
            else if (matchCount == 2) {
                targetAddr = currentAddr;
                foundValue = val;
                LogToFile(logPath, "找到第2个匹配: 值 %.1f 位于 0x%llX (EXE+0x%llX) -> 将以此地址写入 300.0",
                    val, (unsigned long long)targetAddr, (unsigned long long)(targetAddr - baseAddress));
                DumpMemoryToFile(logPath, targetAddr, baseAddress, "第二个匹配点(目标)");
                break;
            }
            // 如果 matchCount > 2 理论不会发生，但跳出循环
        }
        currentAddr--;
    }

    if (targetAddr == 0) {
        LogToFile(logPath, "[错误] 在限制范围内未找到第二组浮点值 30/60/120。共找到 %d 个匹配。线程退出。", matchCount);
        return 0;
    }

    // 5. 进入主循环，持续写入 300.0f 到第二个匹配的地址
    LogToFile(logPath, "进入主循环，每隔 %d ms 写入 %.1f 到地址 0x%llX...",
        LOOP_INTERVAL_MS, TARGET_WRITE_VALUE, (unsigned long long)targetAddr);

    while (g_bIsRunning) {
        float currentValue;
        bool readSuccess = SafeReadFloat(targetAddr, &currentValue);

        if (!readSuccess) {
            LogToFile(logPath, "[错误] 读取目标地址失败! 地址: 0x%llX", (unsigned long long)targetAddr);
            Sleep(1000);
            continue;
        }

        // 若不等于目标值则写入
        if (fabsf(currentValue - TARGET_WRITE_VALUE) > 0.001f) {
            if (SafeWriteFloat(targetAddr, TARGET_WRITE_VALUE)) {
                LogToFile(logPath, "数值变动: %.2f -> %.2f (地址: 0x%llX) 写入成功",
                    currentValue, TARGET_WRITE_VALUE, (unsigned long long)targetAddr);
                DumpMemoryToFile(logPath, targetAddr, baseAddress, "写入后快照");
            }
            else {
                LogToFile(logPath, "[警告] 写入失败! 地址: 0x%llX (错误代码: %d)",
                    (unsigned long long)targetAddr, GetLastError());
            }
        }
        Sleep(LOOP_INTERVAL_MS);
    }

    LogToFile(logPath, "线程接收到退出信号，停止运行。");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, MainThread, hModule, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        g_bIsRunning = false;
        break;
    }
    return TRUE;
}