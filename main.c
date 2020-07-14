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
    
    HookA(&WAHD);
}