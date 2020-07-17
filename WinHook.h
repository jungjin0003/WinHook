/* Example Code :
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
    volatile data *Data = 0xCCCCCCCC;
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
*/
#pragma once
#ifndef __WINHOOK_H__
#define __WINHOOK_H__
#define _one_is_require_
#define _require_
#define _caller_
#define _option_

#ifdef _M_AMD64
    typedef ULONGLONG Address;
    extern const BYTE Instruction[12];
#else
    typedef ULONG Address;
    extern const BYTE Instruction[7];
#endif

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

typedef struct _WINAPI_HOOK_DATAW 
{
    HANDLE hProcess;
    HMODULE hModule;
    _require_ PVOID lpOrigin;
    _caller_ PVOID *lpCopyOrigin;
    PVOID lpCopyBaseOfCode;
    _require_ PVOID lpNewFunction;
    PVOID lpNewFunctionEx;
    PVOID lpParameter;
    PVOID lpParameterEx;
    BOOL Parameter;
    DWORD dwParameterSize;
    _require_ DWORD dwNewFuncSize;
    BYTE jmpCode[sizeof(Instruction)];
    _require_ WCHAR DLLName[MAX_PATH]; 
} WINAPI_HOOK_DATAW, *PWINAPI_HOOK_DATAW;

typedef struct _WINAPI_HOOK_DATAA 
{
    HANDLE hProcess;
    HMODULE hModule;
    _require_ PVOID lpOrigin;
    _caller_ PVOID *lpCopyOrigin;
    PVOID lpCopyBaseOfCode;
    _require_ PVOID lpNewFunction;
    PVOID lpNewFunctionEx;
    PVOID lpParameter;
    PVOID lpParameterEx;
    BOOL Parameter;
    DWORD dwParameterSize;
    _require_ DWORD dwNewFuncSize;
    BYTE jmpCode[sizeof(Instruction)];
    _require_ char DLLName[MAX_PATH]; 
} WINAPI_HOOK_DATAA, *PWINAPI_HOOK_DATAA;

#ifdef UNICODE
    typedef WINAPI_BASIC_HOOK_DATAW WINAPI_BASIC_HOOK_DATA;
    typedef PWINAPI_BASIC_HOOK_DATAW PWINAPI_BASIC_HOOK_DATA;
    typedef WINAPI_HOOK_DATAW WINAPI_HOOK_DATA;
    typedef PWINAPI_HOOK_DATAW PWINAPI_HOOK_DATA;
    #define Hook HookW
    #define WriteNewFunction WriteNewFunctionW
    #define CopyDLLCode CopyDLLCodeW
    #define SetAssemblyInstruction SetAssemblyInstructionW
    #define SetCopyFunction SetCopyFunctionW
    #define WriteParameter WriteParameterW
    #define CodePatch CodePatchW
    #define Set_WINAPI_Struct Set_WINAPI_StructW;
#else
    typedef WINAPI_BASIC_HOOK_DATAA WINAPI_BASIC_HOOK_DATA;
    typedef PWINAPI_BASIC_HOOK_DATAA PWINAPI_BASIC_HOOK_DATA;
    typedef WINAPI_HOOK_DATAA WINAPI_HOOK_DATA;
    typedef PWINAPI_HOOK_DATAA PWINAPI_HOOK_DATA;
    #define Hook HookA
    #define WriteNewFunction WriteNewFunctionA
    #define CopyDLLCode CopyDLLCodeA
    #define SetAssemblyInstruction SetAssemblyInstructionA
    #define SetCopyFunction SetCopyFunctionA
    #define WriteParameter WriteParameterA
    #define CodePatch CodePatchA
    #define Set_WINAPI_Struct Set_WINAPI_StructA;
#endif

HANDLE GetProcessHandleByFileNameA(char* name);
HANDLE GetProcessHandleByFileNameW(WCHAR* name);
BOOL HookA(PWINAPI_BASIC_HOOK_DATAA lpWinApi_Basic_Hook_Data, DWORD PID, char *ProcessName);
BOOL HookW(PWINAPI_BASIC_HOOK_DATAW lpWinApi_Basic_Hook_Data, DWORD PID, wchar_t *ProcessName);
BOOL WriteNewFunctionA(PWINAPI_HOOK_DATAA lpWinApi_Hook_Data);
BOOL WriteNewFunctionW(PWINAPI_HOOK_DATAW lpWinApi_Hook_Data);
BOOL CopyDLLCodeA(PWINAPI_HOOK_DATAA lpWinApi_Hook_Data);
BOOL CopyDLLCodeW(PWINAPI_HOOK_DATAW lpWinApi_Hook_Data);
BOOL SetAssemblyInstructionA(PWINAPI_HOOK_DATAA lpWinApi_Hook_Data);
BOOL SetAssemblyInstructionW(PWINAPI_HOOK_DATAW lpWinApi_Hook_Data);
BOOL SetCopyFunctionA(PWINAPI_HOOK_DATAA lpWinApi_Hook_Data);
BOOL SetCopyFunctionW(PWINAPI_HOOK_DATAW lpWinApi_Hook_Data);
BOOL WriteParameterA(PWINAPI_HOOK_DATAA lpWinApi_Hook_Data);
BOOL WriteParameterW(PWINAPI_HOOK_DATAW lpWinApi_Hook_Data);
BOOL CodePatchA(PWINAPI_HOOK_DATAA lpWinApi_Hook_Data);
BOOL CodePatchW(PWINAPI_HOOK_DATAW lpWinApi_Hook_Data);
BOOL Set_WINAPI_StructA(PWINAPI_HOOK_DATAA lpWinApi_Hook_Data, PWINAPI_BASIC_HOOK_DATAA lpWinApi_Basic_Hook_Data);
BOOL Set_WINAPI_StructW(PWINAPI_HOOK_DATAW lpWinApi_Hook_Data, PWINAPI_BASIC_HOOK_DATAW lpWinApi_Basic_Hook_Data);

#endif
