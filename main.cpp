/*
 * 夜白过检测 1.0
 * Compile: x86_64-w64-mingw32-g++ -mwindows -municode -static -o YebaiAntiCheat.exe main.cpp -lwininet -ladvapi32 -lcomctl32 -lshell32
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <process.h>
#include <shellapi.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

// ====== 配置 ======
#define WIN_WIDTH      420
#define WIN_HEIGHT     355
#define ACE_FOLDER     L"C:\\Program Files\\AntiCheatExpert"
#define GAME_PROC      L"NRC-Win64-Shipping.exe"

// ====== 全局 ======
static HWND g_hStatus = NULL;
static HWND g_hBtnStart = NULL;
static HWND g_hBtnExit = NULL;
static HWND g_hMainWnd = NULL;
static volatile LONG g_Running = 0;
static HANDLE g_hMonThread = NULL;
static WCHAR g_szLog[8192] = {0};
static CRITICAL_SECTION g_csLog;

// ====== UI 日志 ======
static void AddLog(const WCHAR* fmt, ...) {
    WCHAR buf[512];
    va_list ap;
    va_start(ap, fmt);
    vswprintf(buf, 512, fmt, ap);
    va_end(ap);
    EnterCriticalSection(&g_csLog);
    int l = (int)wcslen(g_szLog);
    if (l > 6000) memmove(g_szLog, g_szLog + 2000, sizeof(WCHAR) * 6000);
    wcscat(g_szLog, buf);
    wcscat(g_szLog, L"\r\n");
    if (g_hStatus) {
        SetWindowTextW(g_hStatus, g_szLog);
        SendMessageW(g_hStatus, EM_SETSEL, -1, -1);
        SendMessageW(g_hStatus, EM_SCROLLCARET, 0, 0);
    }
    LeaveCriticalSection(&g_csLog);
}
static void ClsLog() {
    EnterCriticalSection(&g_csLog);
    g_szLog[0] = 0;
    if (g_hStatus) SetWindowTextW(g_hStatus, L"");
    LeaveCriticalSection(&g_csLog);
}

// ====== 进程检测 ======
static int IsRunning(const WCHAR* n) {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {sizeof(PROCESSENTRY32W)};
    BOOL ok = Process32FirstW(h, &pe);
    int f = 0;
    while (ok) {
        if (wcsicmp(pe.szExeFile, n) == 0) { f = 1; break; }
        ok = Process32NextW(h, &pe);
    }
    CloseHandle(h);
    return f;
}

// ====== 杀游戏进程 ======
static void KillGame() {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = {sizeof(PROCESSENTRY32W)};
    BOOL ok = Process32FirstW(h, &pe);
    while (ok) {
        if (wcsicmp(pe.szExeFile, GAME_PROC) == 0) {
            HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (hp) { TerminateProcess(hp, 0); CloseHandle(hp); }
            break;
        }
        ok = Process32Next(h, &pe);
    }
    CloseHandle(h);
}

// ====== 执行命令行并等待 ======
static int RunCmd(WCHAR* cmd, int waitMs) {
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return -1;
    }
    WaitForSingleObject(pi.hProcess, waitMs);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

// ====== 删除文件夹（带重试）======
static int DelFolder() {
    WCHAR cmd[1024];
    int retry;
    for (retry = 0; retry < 3; retry++) {
        if (retry > 0) Sleep(2000);
        // 先用 takeown 获取所有权
        wsprintfW(cmd, L"takeown /F \"%S\" /R /D Y 2>nul", ACE_FOLDER);
        RunCmd(cmd, 8000);
        // 用 icacls 授权当前用户
        wsprintfW(cmd, L"icacls \"%S\" /T /grant Users:F /C 2>nul", ACE_FOLDER);
        RunCmd(cmd, 8000);
        // 强制删除
        wsprintfW(cmd, L"cmd /c rmdir /S /Q \"%S\" 2>nul", ACE_FOLDER);
        RunCmd(cmd, 8000);
        // 检查是否还存在
        if (GetFileAttributesW(ACE_FOLDER) == INVALID_FILE_ATTRIBUTES) return 0;
    }
    return -1;
}

// ====== 锁住文件夹权限 =======
// 效果等同于手动：右键属性->安全->高级->禁用继承->删除所有用户->只保留所有者
static int LockFolder() {
    WCHAR cmd[1024];
    // 移除继承，拒绝所有用户的访问权限（递归）
    wsprintfW(cmd, L"icacls \"%S\" /inheritance:r /deny Everyone:(F) /T /C", ACE_FOLDER);
    RunCmd(cmd, 15000);
    return 0;
}

// ====== 解锁文件夹权限 =======
static int UnlockFolder() {
    WCHAR cmd[1024];
    // 移除拒绝ACE
    wsprintfW(cmd, L"icacls \"%S\" /T /remove:d Everyone 2>nul", ACE_FOLDER);
    RunCmd(cmd, 5000);
    // 恢复继承
    wsprintfW(cmd, L"icacls \"%S\" /T /inheritance:e 2>nul", ACE_FOLDER);
    RunCmd(cmd, 5000);
    return 0;
}

// ====== 监控线程 ======
static unsigned __stdcall MonThrd(void* a) {
    (void)a;
    AddLog(L"【1/4】正在清理残留...");
    DelFolder();
    AddLog(L"【1/4】清理完成");
    AddLog(L"【2/4】等待游戏启动...");

    // 等待游戏启动
    DWORD st = GetTickCount();
    while (g_Running) {
        if (IsRunning(GAME_PROC)) { AddLog(L"【2/4】检测到游戏进程!"); break; }
        if (GetTickCount() - st > 600000) {
            AddLog(L"【2/4】等待超时");
            InterlockedExchange(&g_Running, 0);
            if (g_hBtnStart) { EnableWindow(g_hBtnStart, 1); SetWindowTextW(g_hBtnStart, L"开始过检测"); }
            _endthreadex(0); return 0;
        }
        Sleep(500);
    }
    if (!g_Running) { AddLog(L"【2/4】用户取消"); _endthreadex(0); return 0; }

    // 游戏已启动，等待5秒让ACE文件夹生成
    AddLog(L"【3/4】过检测执行中...");
    Sleep(5000);

    // 锁住文件夹权限
    LockFolder();
    AddLog(L"【3/4】过检测执行成功!");

    // 监控游戏是否退出
    AddLog(L"【4/4】监控中...");
    while (g_Running) {
        if (!IsRunning(GAME_PROC)) {
            Sleep(1500); // 确认一下
            if (!IsRunning(GAME_PROC)) {
                AddLog(L"【4/4】游戏已退出!");
                break;
            }
            AddLog(L"【4/4】游戏恢复，继续监控...");
        }
        Sleep(1000);
    }

    // 游戏退出，解锁+删除+自动退出程序
    if (g_Running) {
        AddLog(L"正在清理...");
        UnlockFolder();
        DelFolder();
        KillGame();
    }

    AddLog(L"=== 完成 ===");
    InterlockedExchange(&g_Running, 0);
    if (g_hBtnStart) { EnableWindow(g_hBtnStart, 1); SetWindowTextW(g_hBtnStart, L"开始过检测"); }
    Sleep(800);
    if (g_hMainWnd) PostMessageW(g_hMainWnd, WM_CLOSE, 0, 0);
    _endthreadex(0);
    return 0;
}

static void StartMon() {
    if (g_hMonThread) { CloseHandle(g_hMonThread); g_hMonThread = NULL; }
    InterlockedExchange(&g_Running, 1);
    ClsLog();
    AddLog(L"=== 夜白过检测 ===");
    AddLog(L"请启动游戏...");
    unsigned tid = 0;
    g_hMonThread = (HANDLE)_beginthreadex(NULL, 0, MonThrd, NULL, 0, &tid);
    if (!g_hMonThread) { AddLog(L"[!] 线程启动失败"); InterlockedExchange(&g_Running, 0); }
}

static void StopMon() {
    if (g_Running) InterlockedExchange(&g_Running, 0);
}

// ====== 主窗口 ======
static LRESULT CALLBACK MainProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HFONT hFTitle = 0, hFNorm = 0;
    if (msg == WM_CREATE) {
        hFTitle = CreateFontW(22, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
        hFNorm = CreateFontW(13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
        CreateWindowW(L"static", L"夜白过检测 1.0",
            WS_CHILD | WS_VISIBLE | SS_CENTER, 60, 8, 300, 35, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"static", L"Log:",
            WS_CHILD | WS_VISIBLE, 15, 50, 40, 20, hwnd, NULL, NULL, NULL);
        g_hStatus = CreateWindowW(L"edit", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            15, 72, WIN_WIDTH - 30, WIN_HEIGHT - 160, hwnd, (HMENU)10, NULL, NULL);
        g_hBtnStart = CreateWindowW(L"button", L"开始过检测",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 30, WIN_HEIGHT - 75, 150, 35, hwnd, (HMENU)20, NULL, NULL);
        g_hBtnExit = CreateWindowW(L"button", L"退出程序",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, WIN_WIDTH - 180, WIN_HEIGHT - 75, 150, 35, hwnd, (HMENU)21, NULL, NULL);
        SendMessageW(GetDlgItem(hwnd, 10), WM_SETFONT, (WPARAM)hFTitle, TRUE);
        SendMessageW(GetDlgItem(hwnd, 11), WM_SETFONT, (WPARAM)hFNorm, TRUE);
        SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)hFNorm, TRUE);
        SendMessageW(g_hBtnStart, WM_SETFONT, (WPARAM)hFNorm, TRUE);
        SendMessageW(g_hBtnExit, WM_SETFONT, (WPARAM)hFNorm, TRUE);
        AddLog(L"=== 夜白过检测 1.0 ===");
        AddLog(L"点击【开始过检测】按钮");
        AddLog(L"然后启动游戏即可");
        return 0;
    }
    if (msg == WM_COMMAND) {
        if (LOWORD(wp) == 20) {  // 开始/停止过检测
            if (!g_Running) {
                StartMon();
                SetWindowTextW(g_hBtnStart, L"停止过检测");
            } else {
                AddLog(L"正在清理...");
                UnlockFolder();
                DelFolder();
                KillGame();
                StopMon();
                SetWindowTextW(g_hBtnStart, L"开始过检测");
            }
        }
        if (LOWORD(wp) == 21) {  // 退出程序
            AddLog(L"正在清理...");
            UnlockFolder();
            DelFolder();
            KillGame();
            if (g_Running) StopMon();
            Sleep(200);
            DestroyWindow(hwnd);
        }
    }
    if (msg == WM_CLOSE) {
        AddLog(L"正在清理...");
        UnlockFolder();
        DelFolder();
        KillGame();
        if (g_Running) StopMon();
        Sleep(200);
        DestroyWindow(hwnd);
        return 0;
    }
    if (msg == WM_DESTROY) { DeleteObject(hFTitle); DeleteObject(hFNorm); PostQuitMessage(0); return 0; }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ====== 权限 ======
static int IsAdmin() {
    HANDLE hToken = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return 0;
    TOKEN_GROUPS* tg = (TOKEN_GROUPS*)malloc(1024);
    DWORD sz = 1024;
    int isAdm = 0;
    if (GetTokenInformation(hToken, TokenGroups, tg, 1024, &sz)) {
        for (DWORD i = 0; i < tg->GroupCount; i++) {
            if (!tg->Groups[i].Sid) continue;
            SID_NAME_USE snu;
            WCHAR name[256] = {0}, dom[256] = {0};
            DWORD nsz = 256, dsz = 256;
            if (LookupAccountSidW(NULL, tg->Groups[i].Sid, name, &nsz, dom, &dsz, &snu)) {
                if (wcscmp(name, L"Administrators") == 0 || wcscmp(name, L"Admin") == 0) { isAdm = 1; break; }
            }
        }
    }
    free(tg);
    CloseHandle(hToken);
    return isAdm;
}

static int RequestElevation() {
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    SHELLEXECUTEINFOW sei = {sizeof(sei), SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI};
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.nShow = SW_SHOWNORMAL;
    return ShellExecuteExW(&sei);
}

// ====== WinMain ======
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hp, LPWSTR cl, int ns) {
    (void)hp; (void)cl; (void)ns;

    // 请求管理员权限
    if (!IsAdmin()) {
        if (RequestElevation()) return 0;
    }

    InitializeCriticalSection(&g_csLog);

    WNDCLASSEXW mwc = {0};
    mwc.cbSize = sizeof(WNDCLASSEXW);
    mwc.style = CS_HREDRAW | CS_VREDRAW;
    mwc.lpfnWndProc = MainProc;
    mwc.hInstance = hInst;
    mwc.hCursor = LoadCursor(NULL, IDC_ARROW);
    mwc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    mwc.lpszClassName = L"YeBaiMain";
    if (!RegisterClassExW(&mwc)) { MessageBoxW(NULL, L"注册失败", L"错误", MB_OK); return 1; }

    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    HWND hMain = CreateWindowExW(0, L"YeBaiMain", L"夜白过检测 1.0",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        (sw - WIN_WIDTH) / 2, (sh - WIN_HEIGHT) / 2,
        WIN_WIDTH, WIN_HEIGHT, NULL, NULL, hInst, NULL);
    if (!hMain) { MessageBoxW(NULL, L"创建窗口失败", L"错误", MB_OK); return 1; }
    g_hMainWnd = hMain;
    ShowWindow(hMain, SW_SHOW);
    UpdateWindow(hMain);

    MSG m;
    while (GetMessage(&m, NULL, 0, 0)) {
        TranslateMessage(&m);
        DispatchMessage(&m);
    }
    DeleteCriticalSection(&g_csLog);
    return 0;
}
