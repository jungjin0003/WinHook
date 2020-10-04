# WinHook
WinHook


English

The above library is a library that hooks Windows API functions. Hooking targets may also be subject to processes other than the current ones.


Korean

위 라이브러리는 윈도우 API 함수를 후킹해주는 라이브러리이다. 후킹대상은 현재 프로세스가 아닌 다른 프로세스를 대상으로도 진행 할 수 있다.

# How to used
```
#include <stdio.h>
#include <windows.h>
#include "WinHook.h"

typedef int(__stdcall* MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

typedef struct {
    MESSAGEBOXA pFunc;
    char Text[10];
} data;

int NewMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCation, UINT uType)
{
    #ifdef _WIN64
    volatile data *Data = 0xCCCCCCCCCCCCCCCC;
    #else
    volatile data *Data = 0xCCCCCCCC;
    #endif
    return ((MESSAGEBOXA)Data->pFunc)(hWnd, Data->Text, Data->Text, uType);
}
int AtherFunc() {}

int main()
{
    data Data;
    strcpy(Data.Text, "Hooked!");
    WINAPI_BASIC_HOOK_DATAA WinApi_Basic_Hook_Data;
    strcpy(WinApi_Basic_Hook_Data.DLLName, "user32.dll");
    WinApi_Basic_Hook_Data.lpOrigin = MessageBoxA;
    WinApi_Basic_Hook_Data.lpNewFunction = NewMessageBox;
    WinApi_Basic_Hook_Data.lpParameter = &Data;
    WinApi_Basic_Hook_Data.Parameter = TRUE;
    WinApi_Basic_Hook_Data.dwParameterSize = sizeof(data);
    WinApi_Basic_Hook_Data.dwNewFuncSize = (Address)AtherFunc - (Address)NewMessageBox;
    WinApi_Basic_Hook_Data.lpCopyOrigin = &Data.pFunc;

    // DWORD PID;
    // scanf("%d", &PID);
    // HookA(&WinApi_Basic_Hook_Data, NULL, "TEST.exe");
    // HookA(&WinApi_Basic_Hook_Data, PID, NULL);
}
```
## Structs
ASCII Struct
```
typedef struct _WINAPI_BASIC_HOOK_DATAA
{
    PVOID lpOrigin;
    PVOID *lpCopyOrigin;
    PVOID lpNewFunction;
    PVOID lpParameter;
    BOOL Parameter;
    DWORD dwParameterSize;
    DWORD dwNewFuncSize;
    char DLLName[MAX_PATH]; 
} WINAPI_BASIC_HOOK_DATAA, *PWINAPI_BASIC_HOOK_DATAA;
```
```
typedef struct _WINAPI_HOOK_DATAA 
{
    HANDLE hProcess;
    HMODULE hModule;
    _require_ PVOID lpOrigin; // Address of function to hook
    _caller_ PVOID *lpCopyOrigin; // Return replicated function address values (Option)
    PVOID lpCopyBaseOfCode;
    _require_ PVOID lpNewFunction; // (new) function address to be jumped
    PVOID lpNewFunctionEx;
    PVOID lpParameter; // Parameter address of (new) function (Option)
    PVOID lpParameterEx;
    BOOL Parameter; // True is Parameter enabled and False is disable
    DWORD dwParameterSize;
    _require_ DWORD dwNewFuncSize; // Size of (new) function address to be jumped
    BYTE jmpCode[sizeof(Instruction)];
    _require_ char DLLName[MAX_PATH]; // DLL name of function to be hook
} WINAPI_HOOK_DATAA, *PWINAPI_HOOK_DATAA;
```
Wide Char Struct
```
typedef struct _WINAPI_BASIC_HOOK_DATAW 
{
    PVOID lpOrigin;
    PVOID *lpCopyOrigin;
    PVOID lpNewFunction;
    PVOID lpParameter;
    BOOL Parameter;
    DWORD dwParameterSize;
    DWORD dwNewFuncSize;
    WCHAR DLLName[MAX_PATH]; 
} WINAPI_BASIC_HOOK_DATAW, *PWINAPI_BASIC_HOOK_DATAW;
```
```
typedef struct _WINAPI_HOOK_DATAW
{
    HANDLE hProcess;
    HMODULE hModule;
    _require_ PVOID lpOrigin; // Address of function to hook
    _caller_ PVOID *lpCopyOrigin; // Return replicated function address values (Option)
    PVOID lpCopyBaseOfCode;
    _require_ PVOID lpNewFunction; // (new) function address to be jumped
    PVOID lpNewFunctionEx;
    PVOID lpParameter; // Parameter address of (new) function (Option)
    PVOID lpParameterEx;
    BOOL Parameter; // True is Parameter enabled and False is disable
    DWORD dwParameterSize;
    _require_ DWORD dwNewFuncSize; // Size of (new) function address to be jumped
    BYTE jmpCode[sizeof(Instruction)];
    _require_ WCHAR DLLName[MAX_PATH]; // DLL name of function to be hook
} WINAPI_HOOK_DATAW, *PWINAPI_HOOK_DATAW;
```
