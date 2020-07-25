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
    // volatile data *Data = 0xCCCCCCCC; //32bit
    // volatile data *Data = 0xCCCCCCCCCCCCCCCC; //64bit
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
