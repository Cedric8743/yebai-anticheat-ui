/*
 * 夜白过检测 1.0 - 微验版
 * Compile: x86_64-w64-mingw32-g++ -mwindows -municode -static -o YebaiAntiCheat.exe main.cpp -lwininet -ladvapi32 -lcomctl32 -lshell32
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
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

// ====== 微验配置 ======
#define WY_HOST      "wy.llua.cn"
#define WY_APPID     "61572"
#define WY_APPKEY   "g11eaea18d487e7b40ab6a53926"
#define WY_TOKEN     "798a0ece954c6998664325b00d18de37"
#define WY_RC4_KEY1 "i4a8fef6a76b5680c6bf697"
#define ACE_FOLDER   L"C:\\Program Files\\AntiCheatExpert"
#define GAME_PROC    L"NRC-Win64-Shipping.exe"

// ====== 全局 ======
static HWND g_hStatus = NULL;
static HWND g_hBtnStart = NULL;
static HWND g_hBtnExit = NULL;
static HWND g_hMainWnd = NULL;
static volatile LONG g_Running = 0;
static HANDLE g_hMonThread = NULL;
static WCHAR g_szLog[8192] = {0};
static CRITICAL_SECTION g_csLog;
static int g_LoginOK = 0;

// ====== UI 日志 ======
static void AddLog(const WCHAR* fmt, ...) {
    WCHAR buf[512];
    va_list ap; va_start(ap, fmt); vswprintf(buf, 512, fmt, ap); va_end(ap);
    EnterCriticalSection(&g_csLog);
    int l = (int)wcslen(g_szLog);
    if (l > 6000) memmove(g_szLog, g_szLog + 2000, sizeof(WCHAR)*6000);
    wcscat(g_szLog, buf); wcscat(g_szLog, L"\r\n");
    if (g_hStatus) { SetWindowTextW(g_hStatus, g_szLog); SendMessageW(g_hStatus, EM_SETSEL, -1, -1); SendMessageW(g_hStatus, EM_SCROLLCARET, 0, 0); }
    LeaveCriticalSection(&g_csLog);
}
static void ClsLog() { EnterCriticalSection(&g_csLog); g_szLog[0]=0; if(g_hStatus) SetWindowTextW(g_hStatus,L""); LeaveCriticalSection(&g_csLog); }

// ====== 进程检测 ======
static int IsRunning(const WCHAR* n) {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {sizeof(PROCESSENTRY32W)};
    BOOL ok = Process32FirstW(h, &pe);
    int f = 0;
    while (ok) { if (wcsicmp(pe.szExeFile, n)==0){f=1;break;} ok=Process32Next(h,&pe); }
    CloseHandle(h); return f;
}

// ====== 杀游戏进程 ======
static void KillGame() {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = {sizeof(PROCESSENTRY32W)};
    BOOL ok = Process32FirstW(h, &pe);
    while (ok) {
        if (wcsicmp(pe.szExeFile, GAME_PROC)==0) {
            HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (hp){TerminateProcess(hp,0);CloseHandle(hp);} break;
        }
        ok = Process32Next(h,&pe);
    }
    CloseHandle(h);
}

// ====== RC4 ======
static void RC4_crypt(unsigned char* data, int len, const unsigned char* key, int keylen) {
    unsigned char s[256], k[256], temp;
    int i, j = 0;
    for (i = 0; i < 256; i++) { s[i] = i; k[i] = key[j % keylen]; j++; }
    j = 0;
    for (i = 0; i < 256; i++) { j = (j + s[i] + k[i]) % 256; temp = s[i]; s[i] = s[j]; s[j] = temp; }
    int a = 0; j = 0;
    for (i = 0; i < (int)len; i++) {
        a = (a + 1) % 256; j = (j + s[a]) % 256;
        temp = s[a]; s[a] = s[j]; s[j] = temp;
        data[i] ^= s[(s[a] + s[j]) % 256];
    }
}
static void rc4_crypt(unsigned char* data, int len, const char* key) {
    RC4_crypt(data, len, (unsigned char*)key, (int)strlen(key));
}

// ====== hex 编解码 ======
static void hex_encode(const unsigned char* in, int len, char* out) {
    for (int i = 0; i < len; i++) sprintf(out + i*2, "%02x", in[i]);
}
static int hex_decode(const char* hex_str, unsigned char* out) {
    int len = (int)strlen(hex_str) / 2;
    for (int i = 0; i < len; i++) {
        char c[3] = {hex_str[i*2], hex_str[i*2+1], 0};
        out[i] = (char)strtol(c, NULL, 16);
    }
    return len;
}

// ====== MD5 ======
typedef struct { unsigned long s[4]; unsigned long c[2]; unsigned char b[64]; } MD5_CTX;
static void MD5_Init(MD5_CTX* c){c->s[0]=0x67452301;c->s[1]=0xefcdab89;c->s[2]=0x98badcfe;c->s[3]=0x10325476;c->c[0]=c->c[1]=0;}
static void MD5_Up(MD5_CTX* c,const void*d,unsigned long len);
static void MD5_Fin(unsigned char* o,MD5_CTX* c);
static void MD5_Tr(unsigned long s[4],const unsigned char b[64]);
static const unsigned char PAD[64]={0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static void MD5_Up(MD5_CTX* c,const void* data,unsigned long len){
    unsigned long i,index,partLen; const unsigned char* input=(const unsigned char*)data;
    index=(unsigned long)((c->c[0]>>3)&0x3F);
    if((c->c[0]+=((unsigned long)len<<3))<((unsigned long)len<<3))c->c[1]++;
    c->c[1]+=((unsigned long)len>>29); partLen=64-index;
    if(len>=partLen){memcpy(&c->b[index],input,partLen);MD5_Tr(c->s,c->b);for(i=partLen;i+63<len;i+=64)MD5_Tr(c->s,&input[i]);index=0;}else i=0;
    memcpy(&c->b[index],&input[i],len-i);
}
static void MD5_Fin(unsigned char o[16],MD5_CTX* c){
    unsigned char bits[8]; unsigned long index,padLen;
    *(unsigned long*)bits=c->c[0];*(unsigned long*)(bits+4)=c->c[1];
    index=(unsigned long)((c->c[0]>>3)&0x3f);padLen=(index<56)?(56-index):(120-index);
    MD5_Up(c,PAD,padLen);MD5_Up(c,bits,8);memcpy(o,c->s,16);
}
static void MD5_Tr(unsigned long s[4],const unsigned char b[64]){
    unsigned long a=s[0],bb=s[1],cc=s[2],d=s[3],x[16]; int i;
    for(i=0;i<16;i++) x[i]=((unsigned long)b[i*4])|((unsigned long)b[i*4+1]<<8)|((unsigned long)b[i*4+2]<<16)|((unsigned long)b[i*4+3]<<24);
    #define FF(a,b,c,d,x,s,ac) a+=((c)^((b)&((d)^(c))))+x+(unsigned long)(ac);a=((a)<<(s))|((a)>>(32-(s)));a+=b;
    #define GG(a,b,c,d,x,s,ac) a+=((d)^((c)&((b)^(d))))+x+(unsigned long)(ac);a=((a)<<(s))|((a)>>(32-(s)));a+=b;
    #define HH(a,b,c,d,x,s,ac) a+=((b)^(c)^(d))+x+(unsigned long)(ac);a=((a)<<(s))|((a)>>(32-(s)));a+=b;
    #define II(a,b,c,d,x,s,ac) a+=((c)^((b)|(~(d))))+x+(unsigned long)(ac);a=((a)<<(s))|((a)>>(32-(s)));a+=b;
    FF(a,bb,cc,d,x[0],7,0xd76aa478);FF(d,a,bb,cc,x[1],12,0xe8c7b756);FF(cc,d,a,bb,x[2],17,0x242070db);FF(bb,cc,d,a,x[3],22,0xc1bdceee);
    FF(a,bb,cc,d,x[4],7,0xf57c0faf);FF(d,a,bb,cc,x[5],12,0x4787c62a);FF(cc,d,a,bb,x[6],17,0xa8304613);FF(bb,cc,d,a,x[7],22,0xfd469501);
    FF(a,bb,cc,d,x[8],7,0x698098d8);FF(d,a,bb,cc,x[9],12,0x8b44f7af);FF(cc,d,a,bb,x[10],17,0xffff5bb1);FF(bb,cc,d,a,x[11],22,0x895cd7be);
    FF(a,bb,cc,d,x[12],7,0x6b901122);FF(d,a,bb,cc,x[13],12,0xfd987193);FF(cc,d,a,bb,x[14],17,0xa679438e);FF(bb,cc,d,a,x[15],22,0x49b40821);
    GG(a,bb,cc,d,x[1],5,0xf61e2562);GG(d,a,bb,cc,x[6],9,0xc040b340);GG(cc,d,a,bb,x[11],14,0x265e5a51);GG(bb,cc,d,a,x[0],20,0xe9b6c7aa);
    GG(a,bb,cc,d,x[5],5,0xd62f105d);GG(d,a,bb,cc,x[10],9,0x2441453);GG(cc,d,a,bb,x[15],14,0xd8a1e681);GG(bb,cc,d,a,x[4],20,0xe7d3fbc8);
    GG(a,bb,cc,d,x[9],5,0x21e1cde6);GG(d,a,bb,cc,x[14],9,0xc33707d6);GG(cc,d,a,bb,x[3],14,0xf4d50d87);GG(bb,cc,d,a,x[8],20,0x455a14ed);
    GG(a,bb,cc,d,x[13],5,0xa9e3e905);GG(d,a,bb,cc,x[2],9,0xfcefa3f8);GG(cc,d,a,bb,x[7],14,0x676f02d9);GG(bb,cc,d,a,x[12],20,0x8d2a4c8a);
    HH(a,bb,cc,d,x[5],4,0xfffa3942);HH(d,a,bb,cc,x[8],11,0x8771f681);HH(cc,d,a,bb,x[11],16,0x6d9d6122);HH(bb,cc,d,a,x[14],23,0xfde5380c);
    HH(a,bb,cc,d,x[1],4,0xa4beea44);HH(d,a,bb,cc,x[4],11,0x4bdecfa9);HH(cc,d,a,bb,x[7],16,0xf6bb4b60);HH(bb,cc,d,a,x[10],23,0xbebfbc70);
    HH(a,bb,cc,d,x[13],4,0x289b7ec6);HH(d,a,bb,cc,x[0],11,0xeaa127fa);HH(cc,d,a,bb,x[3],16,0xd4ef3085);HH(bb,cc,d,a,x[6],23,0x0481d05);
    HH(a,bb,cc,d,x[9],4,0xd9d4d039);HH(d,a,bb,cc,x[12],11,0xe6db99e5);HH(cc,d,a,bb,x[15],16,0x1fa27cf8);HH(bb,cc,d,a,x[2],23,0xc4ac5665);
    II(a,bb,cc,d,x[0],6,0xf4292244);II(d,a,bb,cc,x[7],10,0x432aff97);II(cc,d,a,bb,x[14],15,0xab9423a7);II(bb,cc,d,a,x[5],21,0xfc93a039);
    II(a,bb,cc,d,x[12],6,0x655b59c3);II(d,a,bb,cc,x[3],10,0x8f0ccc92);II(cc,d,a,bb,x[10],15,0xffeff47d);II(bb,cc,d,a,x[1],21,0x85845dd1);
    II(a,bb,cc,d,x[6],6,0x6fa87e4f);II(d,a,bb,cc,x[13],10,0xfe2ce6e0);II(cc,d,a,bb,x[4],15,0xa3014314);II(bb,cc,d,a,x[11],21,0x4e0811a1);
    II(a,bb,cc,d,x[2],6,0xf7537e82);II(d,a,bb,cc,x[9],10,0xbd3af235);II(cc,d,a,bb,x[16],15,0x2ad7d2bb);II(bb,cc,d,a,x[7],21,0xeb86d391);
    s[0]+=a;s[1]+=bb;s[2]+=cc;s[3]+=d;
}
static void CalcMD5(const char* in, char* out) {
    MD5_CTX c; unsigned char d[16];
    MD5_Init(&c); MD5_Up(&c,in,(unsigned long)strlen(in)); MD5_Fin(d,&c);
    for(int i=0;i<16;i++) sprintf(out+i*2,"%02x",d[i]); out[32]=0;
}

// ====== 设备码 ======
static void GetMarkcode(char* out) {
    char cpu_id[64] = {0}, disk_id[64] = {0};
    HKEY h_key; char buf[256] = {0}; DWORD buf_size = sizeof(buf);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &h_key) == ERROR_SUCCESS) {
        RegQueryValueExA(h_key, "ProcessorId", NULL, NULL, (LPBYTE)buf, &buf_size);
        strncpy(cpu_id, buf, 63);
        RegCloseKey(h_key);
    }
    DWORD serial = 0;
    if (GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0)) {
        sprintf(disk_id, "%08X", serial);
    }
    char raw[128]; sprintf(raw, "%s%s", cpu_id, disk_id);
    CalcMD5(raw, out);
}

// ====== HTTP POST ======
static int HttpPost(const char* host, const char* path, const char* postdata, char* resp, int respsize) {
    HINTERNET hi = InternetOpenA("YeBaiAC/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hi) return -1;
    char url[512]; sprintf(url, "http://%s%s", host, path);
    HINTERNET hc = InternetOpenUrlA(hi, url, NULL, 0, INTERNET_FLAG_NO_CACHE_WRITE|INTERNET_FLAG_RELOAD, 0);
    if (!hc) { InternetCloseHandle(hi); return -1; }
    char hdrs[256] = "Content-Type: application/x-www-form-urlencoded";
    BOOL ok = HttpSendRequestA(hc, hdrs, (DWORD)strlen(hdrs), (LPVOID)postdata, (DWORD)strlen(postdata));
    if (!ok) { InternetCloseHandle(hc); InternetCloseHandle(hi); return -1; }
    char buf[4096]; DWORD br = 0; int tot = 0;
    while (InternetReadFile(hc, buf, sizeof(buf)-1, &br) && br > 0) {
        if (tot + (int)br >= respsize-1) br = (DWORD)(respsize - tot - 1);
        memcpy(resp + tot, buf, br); tot += (int)br; resp[tot] = 0;
        if (tot >= respsize-1) break;
    }
    InternetCloseHandle(hc); InternetCloseHandle(hi);
    return (tot > 0) ? 0 : -1;
}

// ====== 微验登录 ======
static int WyLogin(const char* kami) {
    char markcode[64]; GetMarkcode(markcode);
    char timestamp[32]; sprintf(timestamp, "%lld", (long long)time(NULL));
    char randval[16]; sprintf(randval, "%d", 100000 + rand() % 900000);
    char sign_raw[512]; sprintf(sign_raw, "kami=%s&markcode=%s&t=%s&%s", kami, markcode, timestamp, WY_APPKEY);
    char sign[33]; CalcMD5(sign_raw, sign);
    char data[1024]; sprintf(data, "kami=%s&markcode=%s&t=%s&sign=%s&value=%s", kami, markcode, timestamp, sign, randval);
    unsigned char data_bin[1024]; memcpy(data_bin, data, strlen(data));
    rc4_crypt(data_bin, (int)strlen(data), WY_RC4_KEY1);
    char hex_data[8192]; hex_encode(data_bin, (int)strlen(data), hex_data);
    char postdata[16384]; sprintf(postdata, "app=%s&data=%s", WY_APPID, hex_data);
    char resp[8192] = {0};
    if (HttpPost(WY_HOST, "/api/?id=kmlogon", postdata, resp, sizeof(resp)-1) != 0) {
        AddLog(L"[微验] 网络请求失败");
        return -1;
    }
    unsigned char resp_bin[8192];
    int resp_len = hex_decode(resp, resp_bin);
    if (resp_len > 0) {
        rc4_crypt(resp_bin, resp_len, WY_RC4_KEY1);
        resp_bin[resp_len] = 0;
    }
    if (strstr((char*)resp_bin, "\"code\":200")) {
        AddLog(L"[微验] 登录成功!");
        return 0;
    }
    char* msg = strstr((char*)resp_bin, "\"msg\":\"");
    if (msg) {
        msg += 7; char* end = strchr(msg, '"'); if (end) *end = 0;
        AddLog(L"[微验] 登录失败: %hs", msg);
    } else {
        AddLog(L"[微验] 登录失败");
    }
    return -1;
}

// ====== 异步执行命令 ======
static void RunCmdAsync(const WCHAR* cmd) {
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    CreateProcessW(NULL, (LPWSTR)cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
}

// ====== 删除文件夹 ======
static int DelFolder() {
    WCHAR cmd[1024];
    wsprintfW(cmd, L"cmd /c takeown /F \"C:\\Program Files\\AntiCheatExpert\" /R /D Y 2>nul & icacls \"C:\\Program Files\\AntiCheatExpert\" /T /grant Users:F /C 2>nul & cmd /c rmdir /S /Q \"C:\\Program Files\\AntiCheatExpert\" 2>nul");
    RunCmdAsync(cmd);
    return 0;
}

// ====== 锁文件夹 ======
static int LockFolder() {
    WCHAR cmd[1024];
    wsprintfW(cmd, L"icacls \"C:\\Program Files\\AntiCheatExpert\" /T /grant:r Administrators:(F) /C 2>nul");
    RunCmdAsync(cmd);
    wsprintfW(cmd, L"icacls \"C:\\Program Files\\AntiCheatExpert\" /T /inheritance:r /deny Everyone:(F) /C 2>nul");
    RunCmdAsync(cmd);
    return 0;
}

// ====== 解锁文件夹 ======
static int UnlockFolder() {
    WCHAR cmd[1024];
    wsprintfW(cmd, L"cmd /c takeown /F \"C:\\Program Files\\AntiCheatExpert\" /R /D Y 2>nul & icacls \"C:\\Program Files\\AntiCheatExpert\" /T /reset /C 2>nul");
    RunCmdAsync(cmd);
    return 0;
}

// ====== 监控线程 ======
static unsigned __stdcall MonThrd(void* a) {
    (void)a;
    AddLog(L"[微验] 正在验证卡密...");
    // 弹出卡密输入
    WCHAR kamiBuf[256] = {0};
    HWND hInput = CreateWindowExW(0, L"EDIT", L"", WS_OVERLAPPEDWINDOW|WS_VISIBLE, 
        (GetSystemMetrics(SM_CXSCREEN)-300)/2, (GetSystemMetrics(SM_CYSCREEN)-80)/2, 300, 80, NULL, NULL, NULL, NULL);
    HWND hLabel = CreateWindowExW(0, L"STATIC", L"请输入卡密:", WS_CHILD|WS_VISIBLE, 10, 10, 280, 20, hInput, NULL, NULL, NULL);
    HWND hBtn = CreateWindowExW(0, L"BUTTON", L"确定", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 110, 45, 80, 25, hInput, (HMENU)1, NULL, NULL);
    MSG msg2; BOOL bRet;
    while ((bRet = GetMessage(&msg2, NULL, 0, 0)) != 0) {
        if (bRet == -1) break;
        if (msg2.hwnd == hInput || IsChild(hInput, msg2.hwnd)) {
            if (msg2.message == WM_COMMAND && LOWORD(msg2.wParam) == 1) {
                GetWindowTextW(GetDlgItem(hInput, 2), kamiBuf, 255);
                DestroyWindow(hInput);
                break;
            }
            TranslateMessage(&msg2);
            DispatchMessage(&msg2);
        } else {
            TranslateMessage(&msg2);
            DispatchMessage(&msg2);
        }
    }
    if (wcslen(kamiBuf) == 0) {
        AddLog(L"[微验] 未输入卡密，取消");
        InterlockedExchange(&g_Running, 0);
        if (g_hBtnStart) { EnableWindow(g_hBtnStart, 1); SetWindowTextW(g_hBtnStart, L"开始过检测"); }
        _endthreadex(0); return 0;
    }
    char kamiA[256]; WideCharToMultiByte(CP_ACP, 0, kamiBuf, -1, kamiA, sizeof(kamiA), NULL, NULL);
    if (WyLogin(kamiA) != 0) {
        MessageBoxW(NULL, L"微验登录失败", L"错误", MB_OK);
        InterlockedExchange(&g_Running, 0);
        if (g_hBtnStart) { EnableWindow(g_hBtnStart, 1); SetWindowTextW(g_hBtnStart, L"开始过检测"); }
        _endthreadex(0); return 0;
    }
    g_LoginOK = 1;
    
    AddLog(L"【1/4】正在清理残留...");
    DelFolder();
    AddLog(L"【1/4】清理完成");
    AddLog(L"【2/4】等待游戏启动...");
    while (g_Running) {
        if (IsRunning(GAME_PROC)) { AddLog(L"【2/4】检测到游戏进程!"); break; }
        Sleep(500);
    }
    if (!g_Running) { _endthreadex(0); return 0; }
    AddLog(L"【3/4】过检测执行中...");
    Sleep(5000);
    LockFolder();
    AddLog(L"【3/4】过检测执行成功!");
    AddLog(L"【4/4】监控中...");
    while (g_Running) {
        if (!IsRunning(GAME_PROC)) {
            Sleep(1500);
            if (!IsRunning(GAME_PROC)) { AddLog(L"【4/4】游戏已退出!"); break; }
        }
        Sleep(1000);
    }
    if (g_Running) {
        UnlockFolder();
        DelFolder();
        KillGame();
    }
    AddLog(L"=== 完成 ===");
    InterlockedExchange(&g_Running, 0);
    if (g_hBtnStart) { EnableWindow(g_hBtnStart, 1); SetWindowTextW(g_hBtnStart, L"开始过检测"); }
    Sleep(800);
    if (g_hMainWnd) PostMessageW(g_hMainWnd, WM_CLOSE, 0, 0);
    _endthreadex(0); return 0;
}

static void StartMon() {
    if (g_hMonThread) { CloseHandle(g_hMonThread); g_hMonThread = NULL; }
    InterlockedExchange(&g_Running, 1);
    ClsLog();
    AddLog(L"=== 夜白过检测 ==="); AddLog(L"正在验证卡密...");
    unsigned tid = 0;
    g_hMonThread = (HANDLE)_beginthreadex(NULL, 0, MonThrd, NULL, 0, &tid);
    if (!g_hMonThread) { AddLog(L"[!] 线程启动失败"); InterlockedExchange(&g_Running, 0); }
}

static void StopMon() {
    if (g_Running) InterlockedExchange(&g_Running, 0);
}

static unsigned __stdcall CleanupThrd(void* a) {
    (void)a;
    Sleep(300);
    UnlockFolder();
    DelFolder();
    KillGame();
    Sleep(300);
    PostQuitMessage(0);
    return 0;
}

// ====== 主窗口 ======
static LRESULT CALLBACK MainProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HFONT hFTitle = 0, hFNorm = 0;
    if (msg == WM_CREATE) {
        hFTitle = CreateFontW(22,0,0,0,FW_BOLD,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Microsoft YaHei UI");
        hFNorm = CreateFontW(13,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Microsoft YaHei UI");
        CreateWindowW(L"static",L"夜白过检测 1.0",WS_CHILD|WS_VISIBLE|SS_CENTER,60,8,300,35,hwnd,NULL,NULL,NULL);
        CreateWindowW(L"static",L"Log:",WS_CHILD|WS_VISIBLE,15,50,40,20,hwnd,NULL,NULL,NULL);
        g_hStatus = CreateWindowW(L"edit",L"",WS_CHILD|WS_VISIBLE|WS_BORDER|ES_READONLY|ES_MULTILINE|ES_AUTOVSCROLL|WS_VSCROLL,15,72,390,215,hwnd,(HMENU)10,NULL,NULL);
        g_hBtnStart = CreateWindowW(L"button",L"开始过检测",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,30,295,150,35,hwnd,(HMENU)20,NULL,NULL);
        g_hBtnExit = CreateWindowW(L"button",L"退出程序",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,240,295,150,35,hwnd,(HMENU)21,NULL,NULL);
        SendMessageW(g_hStatus,WM_SETFONT,(WPARAM)hFNorm,TRUE);
        SendMessageW(g_hBtnStart,WM_SETFONT,(WPARAM)hFNorm,TRUE);
        SendMessageW(g_hBtnExit,WM_SETFONT,(WPARAM)hFNorm,TRUE);
        AddLog(L"=== 夜白过检测 1.0 ==="); AddLog(L"点击【开始过检测】按钮"); AddLog(L"然后启动游戏即可");
        return 0;
    }
    if (msg == WM_COMMAND) {
        if (LOWORD(wp) == 20) {
            if (!g_Running) {
                StartMon();
                SetWindowTextW(g_hBtnStart, L"停止过检测");
            } else {
                StopMon();
                SetWindowTextW(g_hBtnStart, L"开始过检测");
                CloseHandle((HANDLE)_beginthreadex(NULL, 0, CleanupThrd, NULL, 0, NULL));
            }
        }
        if (LOWORD(wp) == 21) {
            StopMon();
            CloseHandle((HANDLE)_beginthreadex(NULL, 0, CleanupThrd, NULL, 0, NULL));
        }
    }
    if (msg == WM_CLOSE) {
        StopMon();
        CloseHandle((HANDLE)_beginthreadex(NULL, 0, CleanupThrd, NULL, 0, NULL));
        DestroyWindow(hwnd); return 0;
    }
    if (msg == WM_DESTROY) { DeleteObject(hFTitle); DeleteObject(hFNorm); PostQuitMessage(0); return 0; }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ====== 管理员检测 ======
static int IsAdmin() {
    HANDLE hToken = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return 0;
    TOKEN_GROUPS* tg = (TOKEN_GROUPS*)malloc(1024);
    DWORD sz = 1024; int isAdm = 0;
    if (GetTokenInformation(hToken, TokenGroups, tg, 1024, &sz)) {
        for (DWORD i = 0; i < tg->GroupCount; i++) {
            if (!tg->Groups[i].Sid) continue;
            WCHAR name[256]={0}, dom[256]={0}; DWORD nsz=256, dsz=256; SID_NAME_USE snu;
            if (LookupAccountSidW(NULL, tg->Groups[i].Sid, name, &nsz, dom, &dsz, &snu)) {
                if (wcscmp(name, L"Administrators")==0 || wcscmp(name, L"Admin")==0) { isAdm = 1; break; }
            }
        }
    }
    free(tg); CloseHandle(hToken); return isAdm;
}

static int RequestElevation() {
    WCHAR exePath[MAX_PATH]; GetModuleFileNameW(NULL, exePath, MAX_PATH);
    SHELLEXECUTEINFOW sei = {sizeof(sei), SEE_MASK_NOCLOSEPROCESS|SEE_MASK_FLAG_NO_UI};
    sei.lpVerb = L"runas"; sei.lpFile = exePath; sei.nShow = SW_SHOWNORMAL;
    return ShellExecuteExW(&sei);
}

// ====== WinMain ======
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hp, LPWSTR cl, int ns) {
    (void)hp; (void)cl; (void)ns;
    if (!IsAdmin()) {
        if (RequestElevation()) return 0;
    }
    InitializeCriticalSection(&g_csLog);
    WNDCLASSEXW mwc = {0}; mwc.cbSize = sizeof(WNDCLASSEXW);
    mwc.style = CS_HREDRAW|CS_VREDRAW; mwc.lpfnWndProc = MainProc; mwc.hInstance = hInst;
    mwc.hCursor = LoadCursor(NULL, IDC_ARROW); mwc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
    mwc.lpszClassName = L"YeBaiMain";
    if (!RegisterClassExW(&mwc)) { MessageBoxW(NULL, L"注册失败", L"错误", MB_OK); return 1; }
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    HWND hMain = CreateWindowExW(0, L"YeBaiMain", L"夜白过检测 1.0",
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
        (sw-420)/2, (sh-355)/2, 420, 355, NULL, NULL, hInst, NULL);
    if (!hMain) { MessageBoxW(NULL, L"创建窗口失败", L"错误", MB_OK); return 1; }
    g_hMainWnd = hMain;
    ShowWindow(hMain, SW_SHOW); UpdateWindow(hMain);
    MSG m;
    while (GetMessage(&m, NULL, 0, 0)) { TranslateMessage(&m); DispatchMessage(&m); }
    DeleteCriticalSection(&g_csLog);
    return 0;
}
