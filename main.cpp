/*
 * 夜白过检测 1.0 - Debug Build
 * Compile: x86_64-w64-mingw32-g++ -mwindows -municode -static -o YebaiAntiCheat.exe main.cpp -lwininet -ladvapi32 -lcomctl32
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <aclapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <process.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

// 日志已禁用
static void Log(const char* fmt, ...) { (void)fmt; }
static void LogW(const WCHAR* fmt, ...) { (void)fmt; }

// ====== 配置 ======
#define WIN_TITLE_W    L"夜白过检测 1.0"
#define WIN_WIDTH      420
#define WIN_HEIGHT     355
#define ACE_FOLDER     L"C:\\Program Files\\AntiCheatExpert"
#define GAME_PROC      L"NRC-Win64-Shipping.exe"

// ====== 全局 ======
static HWND g_hStatus = NULL;
static HWND g_hBtnStart = NULL;
static HWND g_hBtn退出程序 = NULL;
static volatile LONG g_Running = 0;
static HANDLE g_hMonThread = NULL;
static WCHAR g_szLog[8192] = {0};
static CRITICAL_SECTION g_csLog;

// ====== MD5 ======
typedef struct { unsigned long s[4]; unsigned long c[2]; unsigned char b[64]; } MD5_CTX;
static void MD5_Init(MD5_CTX* c){c->s[0]=0x67452301;c->s[1]=0xefcdab89;c->s[2]=0x98badcfe;c->s[3]=0x10325476;c->c[0]=c->c[1]=0;}
static void MD5_Up(MD5_CTX* c,const void*d,unsigned long len);
static void MD5_Fin(unsigned char* o,MD5_CTX* c);
static void MD5_Tr(unsigned long s[4],const unsigned char b[64]);
static const unsigned char PAD[64]={0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
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
static int CalcMD5(const char* in,char* out){
    MD5_CTX c; unsigned char d[16];
    MD5_Init(&c); MD5_Up(&c,in,(unsigned long)strlen(in)); MD5_Fin(d,&c);
    for(int i=0;i<16;i++) sprintf(out+i*2,"%02x",d[i]); out[32]=0; return 0;
}

// ====== HTTP GET ======
static int HttpGet(const char* url,char* resp,int size){
    URL_COMPONENTSA uc={0}; uc.dwStructSize=sizeof(uc);
    char host[256]={0},path[2048]={0};
    const char* p=strstr(url,"://"); const char* hs=p?p+3:url;
    const char* ps=strchr(hs,'/');
    if(ps){strncpy(host,hs,(int)(ps-hs));strncpy(path,ps,sizeof(path)-1);}
    else {strncpy(host,hs,sizeof(host)-1);strcpy(path,"/");}
    uc.lpszHostName=host; uc.dwHostNameLength=(DWORD)strlen(host);
    uc.lpszUrlPath=path; uc.dwUrlPathLength=(DWORD)strlen(path);
    HINTERNET hi=InternetOpenA("YeBaiAC/1.0",INTERNET_OPEN_TYPE_DIRECT,NULL,NULL,0);
    if(!hi) return -1;
    HINTERNET hc=InternetOpenUrlA(hi,url,NULL,0,INTERNET_FLAG_NO_CACHE_WRITE|INTERNET_FLAG_RELOAD|INTERNET_FLAG_NO_COOKIES,0);
    if(!hc){InternetCloseHandle(hi);return -1;}
    char buf[8192]; DWORD br=0; int tot=0;
    while(InternetReadFile(hc,buf,sizeof(buf)-1,&br)&&br>0){
        if(tot+(int)br>=size-1)br=(DWORD)(size-tot-1);
        memcpy(resp+tot,buf,br);tot+=(int)br;resp[tot]=0;if(tot>=size-1)break;
    }
    InternetCloseHandle(hc);InternetCloseHandle(hi);return 0;
}

// ====== JSON ======
static int JInt(const char* j,const char* k){
    char p[128];sprintf(p,"\"%s\"",k);const char* x=strstr(j,p);if(!x)return -1;
    x=strchr(x,':');if(!x)return -1;x++;while(*x&&(*x==' '||*x=='\t'||*x=='\n'||*x=='\r'))x++;return atoi(x);
}
static int JStr(const char* j,const char* k,char* o,int osz){
    char p[128];sprintf(p,"\"%s\"",k);const char* x=strstr(j,p);if(!x)return -1;
    x=strchr(x,':');if(!x)return -1;x++;while(*x&&(*x==' '||*x=='\t'||*x=='\n'||*x=='\r'))x++;
    if(*x=='"')x++;const char* e=x;while(*e&&*e!='"')e++;
    int l=(int)(e-x);if(l>=osz)l=osz-1;strncpy(o,x,l);o[l]=0;return 0;
}

// ====== 文件 ======
static int PathExistsW(const WCHAR* p){return GetFileAttributesW(p)!=INVALID_FILE_ATTRIBUTES;}
static int DelFolderW(const WCHAR* p){
    // 先用 takeown 获取所有权
    WCHAR cmd[1024];
    wsprintfW(cmd, L"takeown /F \"%S\" /R /D Y 2>nul", p);
    STARTUPINFOW si={sizeof(si)}; PROCESS_INFORMATION pi={0};
    si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
    if(CreateProcessW(NULL,cmd,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        WaitForSingleObject(pi.hProcess,5000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    // 再用 icacls 移除限制
    wsprintfW(cmd, L"icacls \"%S\" /T /grant Users:F /C 2>nul", p);
    if(CreateProcessW(NULL,cmd,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        WaitForSingleObject(pi.hProcess,5000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    // 最后强制删除
    wsprintfW(cmd, L"cmd /c rmdir /S /Q \"%S\" 2>nul", p);
    if(CreateProcessW(NULL,cmd,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        WaitForSingleObject(pi.hProcess,5000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
    return 0;
}

// ====== 进程 ======
static int IsRunning(const WCHAR* n){
    HANDLE h=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(h==INVALID_HANDLE_VALUE)return 0;
    PROCESSENTRY32W pe={sizeof(PROCESSENTRY32W)};BOOL ok=Process32FirstW(h,&pe);
    int f=0;while(ok){if(wcsicmp(pe.szExeFile,n)==0){f=1;break;}ok=Process32NextW(h,&pe);}
    CloseHandle(h);return f;
}

// ====== 权限（使用 icacls 命令）======
static void KillGame(){
    HANDLE h=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(h==INVALID_HANDLE_VALUE)return;
    PROCESSENTRY32W pe={sizeof(PROCESSENTRY32W)};BOOL ok=Process32FirstW(h,&pe);
    while(ok){
        if(wcsicmp(pe.szExeFile,GAME_PROC)==0){
            HANDLE hp=OpenProcess(PROCESS_TERMINATE,FALSE,pe.th32ProcessID);
            if(hp){TerminateProcess(hp,0);CloseHandle(hp);}
            break;
        }
        ok=Process32Next(h,&pe);
    }
    CloseHandle(h);
}
// ====== 权限修复版 ======
static void AddLog(const WCHAR* fmt, ...);
static int LockACE(){
    
    
    if(!PathExistsW(ACE_FOLDER)){
            return -1;
    }
    
    WCHAR cmd[1024];
    
    // 第一步：移除继承，强制只保留当前显式权限
    wsprintfW(cmd, L"icacls \"%S\" /inheritance:r", ACE_FOLDER);
    
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if(!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)){
        return -1;
    }
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    // 第二步：拒绝所有用户的完全控制（用正确语法）
    wsprintfW(cmd, L"icacls \"%S\" /deny Everyone:(F)", ACE_FOLDER);
    
    si = {sizeof(si)};
    pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if(!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)){
        return -1;
    }
    WaitForSingleObject(pi.hProcess, 5000);
    
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    
    if(exitCode != 0){
            DelFolderW(ACE_FOLDER);
        return -1;
    }
    
    return 0;
}

static int UnlockACE(){
    
    if(!PathExistsW(ACE_FOLDER)){
            return 0;
    }
    
    WCHAR cmd[1024];
    
    // 先移除拒绝ACE
    wsprintfW(cmd, L"icacls \"%S\" /remove:d Everyone", ACE_FOLDER);
    
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if(!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)){
        return -1;
    }
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    // 恢复继承
    wsprintfW(cmd, L"icacls \"%S\" /inheritance:e", ACE_FOLDER);
    
    si = {sizeof(si)};
    pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if(!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)){
        return -1;
    }
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return 0;
}


// ====== UI 日志 ======
static void AddLog(const WCHAR* fmt,...){
    WCHAR buf[512];va_list ap;va_start(ap,fmt);vswprintf(buf,512,fmt,ap);va_end(ap);
    EnterCriticalSection(&g_csLog);
    int l=(int)wcslen(g_szLog);
    if(l>6000)memmove(g_szLog,g_szLog+2000,sizeof(WCHAR)*6000);
    wcscat(g_szLog,buf);wcscat(g_szLog,L"\r\n");
    if(g_hStatus){SetWindowTextW(g_hStatus,g_szLog);SendMessageW(g_hStatus,EM_SETSEL,-1,-1);SendMessageW(g_hStatus,EM_SCROLLCARET,0,0);}
    LeaveCriticalSection(&g_csLog);
}
static void ClsLog(){EnterCriticalSection(&g_csLog);g_szLog[0]=0;if(g_hStatus)SetWindowTextW(g_hStatus,L"");LeaveCriticalSection(&g_csLog);}

// ====== 监控线程 ======
static unsigned __stdcall MonThrd(void* a){
    (void)a;
    Log("监控线程启动");
    AddLog(L"【1/6】正在清理辅助残留...");
    DelFolderW(ACE_FOLDER);
    AddLog(L"【1/6】清理完成");
    AddLog(L"【2/6】等待游戏启动...");
    DWORD st=GetTickCount();
    while(g_Running){
        if(IsRunning(GAME_PROC)){AddLog(L"【2/6】检测到游戏进程!");break;}
        if(GetTickCount()-st>600000){AddLog(L"【2/6】等待超时");InterlockedExchange(&g_Running,0);
            if(g_hBtnStart){EnableWindow(g_hBtnStart,1);SetWindowTextW(g_hBtnStart,L"开始过检测");}
            _endthreadex(0);return 0;}
        Sleep(500);
    }
    if(!g_Running){AddLog(L"【2/6】用户取消");_endthreadex(0);return 0;}
    AddLog(L"【3/6】等待辅助加载中...");Sleep(5000);
    AddLog(L"【4/6】过检测执行中...");
    if(LockACE() == 0){
        AddLog(L"【4/6】过检测执行成功!");
    } else {
        AddLog(L"【4/6】过检测执行失败!");
    }
    AddLog(L"【5/6】监控游戏中......");
    while(g_Running){
        if(!IsRunning(GAME_PROC)){
            // 确认一次，避免误报
            Sleep(1000);
            if(!IsRunning(GAME_PROC)){
                AddLog(L"【5/6】检测到游戏已退出!");
                break;
            }
            AddLog(L"【5/6】游戏进程恢复，重新监控...");
        }
        Sleep(1000);
    }
    AddLog(L"【6/6】正在清理残留...");UnlockACE();DelFolderW(ACE_FOLDER);
    AddLog(L"=== Anti-cheat done! ===");
    InterlockedExchange(&g_Running,0);
    if(g_hBtnStart){EnableWindow(g_hBtnStart,1);SetWindowTextW(g_hBtnStart,L"开始过检测");}
    Log("监控线程结束");
    _endthreadex(0);return 0;
}
static void StartMon(){
    if(g_hMonThread){CloseHandle(g_hMonThread);g_hMonThread=NULL;}
    InterlockedExchange(&g_Running,1);
    ClsLog();AddLog(L"=== 夜白过检测 ===");AddLog(L"请启动游戏...");
    unsigned tid=0;
    g_hMonThread=(HANDLE)_beginthreadex(NULL,0,MonThrd,NULL,0,&tid);
    if(!g_hMonThread){AddLog(L"[!] 线程启动失败");InterlockedExchange(&g_Running,0);}
}
static void StopMon(){
    if(g_Running){InterlockedExchange(&g_Running,0);}
}

// 登录验证已移除



// ====== 主窗口 ======
static LRESULT CALLBACK MainProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){
    static HFONT hFTitle=0,hFNorm=0;
    if(msg==WM_CREATE){
        hFTitle=CreateFontW(22,0,0,0,FW_BOLD,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Microsoft YaHei UI");
        hFNorm=CreateFontW(13,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Microsoft YaHei UI");
        CreateWindowW(L"static",L"夜白过检测 1.0",
            WS_CHILD|WS_VISIBLE|SS_CENTER,60,8,300,35,hwnd,NULL,NULL,NULL);
        CreateWindowW(L"static",L"Log:",
            WS_CHILD|WS_VISIBLE,15,50,40,20,hwnd,NULL,NULL,NULL);
        g_hStatus=CreateWindowW(L"edit",L"",
            WS_CHILD|WS_VISIBLE|WS_BORDER|ES_READONLY|ES_MULTILINE|ES_AUTOVSCROLL|WS_VSCROLL,
            15,72,WIN_WIDTH-30,WIN_HEIGHT-160,hwnd,(HMENU)10,NULL,NULL);
        g_hBtnStart=CreateWindowW(L"button",L"开始过检测",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,30,WIN_HEIGHT-75,150,35,hwnd,(HMENU)20,NULL,NULL);
        g_hBtn退出程序=CreateWindowW(L"button",L"退出程序",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,WIN_WIDTH-180,WIN_HEIGHT-75,150,35,hwnd,(HMENU)21,NULL,NULL);
        SendMessageW(GetDlgItem(hwnd,10),WM_SETFONT,(WPARAM)hFTitle,TRUE);
        SendMessageW(GetDlgItem(hwnd,11),WM_SETFONT,(WPARAM)hFNorm,TRUE);
        SendMessageW(g_hStatus,WM_SETFONT,(WPARAM)hFNorm,TRUE);
        SendMessageW(g_hBtnStart,WM_SETFONT,(WPARAM)hFNorm,TRUE);
        SendMessageW(g_hBtn退出程序,WM_SETFONT,(WPARAM)hFNorm,TRUE);
        AddLog(L"=== 夜白过检测 1.0 ===");
        AddLog(L"点击【开始过检测】按钮");
        AddLog(L"然后启动游戏即可");
        Log("主窗口已创建");
        return 0;
    }
    if(msg==WM_COMMAND){
        if(LOWORD(wp)==20){
            if(!g_Running){StartMon();SetWindowTextW(g_hBtnStart,L"停止过检测");}
            else{
                AddLog(L"正在清理...");
                UnlockACE();
                DelFolderW(ACE_FOLDER);
                KillGame();
                if(g_Running)StopMon();
                SetWindowTextW(g_hBtnStart,L"开始过检测");
            }
        }
        if(LOWORD(wp)==21){
            AddLog(L"正在清理...");
            UnlockACE();
            DelFolderW(ACE_FOLDER);
            KillGame();
            if(g_Running)StopMon();
            Sleep(200);
            DestroyWindow(hwnd);
        }
    }
    if(msg==WM_CLOSE){
        AddLog(L"正在清理...");
        UnlockACE();
        DelFolderW(ACE_FOLDER);
        KillGame();
        if(g_Running)StopMon();
        Sleep(200);
        DestroyWindow(hwnd);return 0;
    }
    if(msg==WM_DESTROY){DeleteObject(hFTitle);DeleteObject(hFNorm);PostQuitMessage(0);return 0;}
    return DefWindowProcW(hwnd,msg,wp,lp);
}

// ====== WinMain ======
// 检查并请求管理员权限
static int RequestAdmin(){
    HANDLE hToken=0;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken)) return 0;
    TOKEN_PRIVILEGES tp={1,{0,0,SE_PRIVILEGE_ENABLED}};
    if(!LookupPrivilegeValueW(NULL,SE_SECURITY_NAME,&tp.Privileges[0].Luid)){CloseHandle(hToken);return 0;}
    if(!AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,0)){CloseHandle(hToken);return 0;}
    CloseHandle(hToken); return 1;
}
static int IsAdmin(){
    HANDLE hToken=0;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&hToken)) return 0;
    TOKEN_GROUPS* tg=(TOKEN_GROUPS*)malloc(1024);
    DWORD sz=1024; int isAdm=0;
    if(GetTokenInformation(hToken,TokenGroups,tg,1024,&sz)){
        for(DWORD i=0;i<tg->GroupCount;i++){
            if(tg->Groups[i].Sid==NULL) continue;
            SID_NAME_USE snu;
            WCHAR name[256]={0},dom[256]={0};
            DWORD nsz=256,dsz=256;
            if(LookupAccountSidW(NULL,tg->Groups[i].Sid,name,&nsz,dom,&dsz,&snu)){
                if(wcscmp(name,L"Administrators")==0 || wcscmp(name,L"Admin")==0){
                    isAdm=1; break;
                }
            }
        }
    }
    free(tg); CloseHandle(hToken); return isAdm;
}
static int RequestElevation(){
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(NULL,exePath,MAX_PATH);
    SHELLEXECUTEINFOW sei={sizeof(sei),SEE_MASK_NOCLOSEPROCESS|SEE_MASK_FLAG_NO_UI};
    sei.lpVerb=L"runas";
    sei.lpFile=exePath;
    sei.nShow=SW_SHOWNORMAL;
    return ShellExecuteExW(&sei);
}

int WINAPI wWinMain(HINSTANCE hInst,HINSTANCE hp,LPWSTR cl,int ns){
    (void)hp;(void)cl;(void)ns;
    Log("=== 程序启动 ===");

    // 检查管理员权限，没有则请求提权
    if(!IsAdmin()){
        Log("非管理员，正在请求提权...");
        if(RequestElevation()){
            Log("提权成功，正在重启");
            return 0;
        }
        Log("提权被拒绝，继续运行");
    } else {
        Log("以管理员身份运行");
    }
    RequestAdmin(); // 启用 SE_SECURITY_NAME 特权
    Log("=== 程序启动 ===");
    InitializeCriticalSection(&g_csLog);

    // 注册主窗口类
    WNDCLASSEXW mwc={0};mwc.cbSize=sizeof(WNDCLASSEXW);
    mwc.style=CS_HREDRAW|CS_VREDRAW;mwc.lpfnWndProc=MainProc;mwc.hInstance=hInst;
    mwc.hCursor=LoadCursor(NULL,IDC_ARROW);mwc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
    mwc.lpszClassName=L"YeBaiMain";
    if(!RegisterClassExW(&mwc)){Log("RegisterClassExW main FAILED");MessageBoxW(NULL,L"Reg failed",L"Error",MB_OK);return 1;}
    Log("Main class registered");

    int sw=GetSystemMetrics(SM_CXSCREEN),sh=GetSystemMetrics(SM_CYSCREEN);
    HWND hMain=CreateWindowExW(0,L"YeBaiMain",L"夜白过检测 1.0",
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
        (sw-WIN_WIDTH)/2,(sh-WIN_HEIGHT)/2,
        WIN_WIDTH,WIN_HEIGHT,NULL,NULL,hInst,NULL);
    if(!hMain){Log("CreateWindowExW main FAILED");MessageBoxW(NULL,L"Main window failed",L"Error",MB_OK);return 1;}
    Log("Main window created, showing");
    ShowWindow(hMain,SW_SHOW);UpdateWindow(hMain);

    MSG m;
    while(GetMessage(&m,NULL,0,0)){
        TranslateMessage(&m);DispatchMessage(&m);
    }
    DeleteCriticalSection(&g_csLog);
    Log("=== wWinMain END ===");
    return 0;
}
