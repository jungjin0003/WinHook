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
    data *Data = 0xCCCCCCCC;
    return ((MESSAGEBOXA)Data->pFunc)(hWnd, Data->Text, Data->Text, uType);
}
int AtherFunc() {}

int main()
{
    WINAPI_HOOK_DATAA WAHD;
    data Data;
    scanf("%d", &WAHD.dwPID);
    WAHD.lpNewFunction = NewMessageBox;
    WAHD.dwNewFuncSize = (ULONG)AtherFunc - (ULONG)NewMessageBox;
    WAHD.lpOrigin = MessageBoxA;
    WAHD.lpCopyOrigin = &Data.pFunc;
    strcpy(WAHD.DLLName, "user32.dll");
    strcpy(Data.Text, "Hooked!");
    WAHD.Parameter = TRUE;
    WAHD.lpParameter = &Data;
    WAHD.dwParameterSize = sizeof(data);
    HookA(&WAHD)
}
*/
#pragma once
#ifndef __WINHOOK_H__
#define __WINHOOK_H__
#define _one_is_require_
#define _require_
#define _caller_

#ifdef _M_AMD64
    typedef ULONGLONG Address;
    extern const BYTE Instruction[12];
#else
    typedef ULONG Address;
    extern const BYTE Instruction[7];
#endif

typedef struct _WINAPI_HOOK_DATAW {
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
    _one_is_require_ DWORD dwPID;
    BYTE jmpCode[sizeof(Instruction)];
    _require_ WCHAR DLLName[MAX_PATH]; 
    _one_is_require_ WCHAR ProcessName[MAX_PATH];
} WINAPI_HOOK_DATAW, *PWINAPI_HOOK_DATAW;

typedef struct _WINAPI_HOOK_DATAA {
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
    _one_is_require_ DWORD dwPID;
    BYTE jmpCode[sizeof(Instruction)];
    _require_ char DLLName[MAX_PATH]; 
    _one_is_require_ char ProcessName[MAX_PATH];
} WINAPI_HOOK_DATAA, *PWINAPI_HOOK_DATAA;

#ifdef UNICODE
    typedef WINAPI_HOOK_DATAW WINAPI_HOOK_DATA;
    typedef PWINAPI_HOOK_DATAW PWINAPI_HOOK_DATA;
    #define Hook HookW
    #define WriteNewFunction WriteNewFunctionW
    #define CopyDLLCode CopyDLLCodeW
    #define SetAssemblyInstruction SetAssemblyInstructionW
    #define SetCopyFunction SetCopyFunctionW
    #define WriteParameter WriteParameterW
    #define CodePatch CodePatchW
#else
    typedef WINAPI_HOOK_DATAA WINAPI_HOOK_DATA;
    typedef PWINAPI_HOOK_DATAA PWINAPI_HOOK_DATA;
    #define Hook HookA
    #define WriteNewFunction WriteNewFunctionA
    #define CopyDLLCode CopyDLLCodeA
    #define SetAssemblyInstruction SetAssemblyInstructionA
    #define SetCopyFunction SetCopyFunctionA
    #define WriteParameter WriteParameterA
    #define CodePatch CodePatchA
#endif

HANDLE GetProcessHandleByFileNameA(char*);
HANDLE GetProcessHandleByFileNameW(WCHAR*);
BOOL HookA(PWINAPI_HOOK_DATAA);
BOOL HookW(PWINAPI_HOOK_DATAW);
BOOL WriteNewFunctionA(PWINAPI_HOOK_DATAA);
BOOL WriteNewFunctionW(PWINAPI_HOOK_DATAW);
BOOL CopyDLLCodeA(PWINAPI_HOOK_DATAA);
BOOL CopyDLLCodeW(PWINAPI_HOOK_DATAW);
BOOL SetAssemblyInstructionA(PWINAPI_HOOK_DATAA);
BOOL SetAssemblyInstructionW(PWINAPI_HOOK_DATAW);
BOOL SetCopyFunctionA(PWINAPI_HOOK_DATAA);
BOOL SetCopyFunctionW(PWINAPI_HOOK_DATAW);
BOOL WriteParameterA(PWINAPI_HOOK_DATAA);
BOOL WriteParameterW(PWINAPI_HOOK_DATAW);
BOOL CodePatchA(PWINAPI_HOOK_DATAA);
BOOL CodePatchW(PWINAPI_HOOK_DATAW);

#endif