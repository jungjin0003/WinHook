#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include "WinHook.h"

#ifdef _M_AMD64
    typedef ULONGLONG Address;
    const BYTE Instruction[12] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};
#else
    typedef ULONG Address;
    const BYTE Instruction[7] = {0xb8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};
#endif

void Error(char[]);

HANDLE GetProcessHandleByFileNameA(char* name)
{
    DWORD process_id_array[1024];
    DWORD bytes_returned;
    DWORD num_processes;
    HANDLE hProcess;
    char image_name[MAX_PATH];
    EnumProcesses(process_id_array, 256*sizeof(DWORD), &bytes_returned);
    num_processes = (bytes_returned/sizeof(DWORD));
    for (int i = 0; i < num_processes; i++) 
    {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, process_id_array[i]);
        if(GetModuleBaseNameA(hProcess, 0, image_name, MAX_PATH))
        {
            if(!stricmp(image_name, name))
            {
                return hProcess;
            }
        }
        CloseHandle(hProcess);
    }
    return NULL;
}

HANDLE GetProcessHandleByFileNameW(WCHAR* name)
{
    DWORD process_id_array[1024];
    DWORD bytes_returned;
    DWORD num_processes;
    HANDLE hProcess;
    WCHAR image_name[MAX_PATH];
    EnumProcesses(process_id_array, 256*sizeof(DWORD), &bytes_returned);
    num_processes = (bytes_returned/sizeof(DWORD));
    for (int i = 0; i < num_processes; i++) 
    {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, process_id_array[i]);
        if(GetModuleBaseNameW(hProcess, 0, image_name, MAX_PATH))
        {
            if(!wcscmp(image_name, name))
            {
                return hProcess;
            }
        }
        CloseHandle(hProcess);
    }
    return NULL;
}

BOOL HookA(PWINAPI_BASIC_HOOK_DATAA lpWinApi_Basic_Hook_Data, DWORD PID, char *ProcessName)
{
    WINAPI_HOOK_DATAA WinApi_Hook_Data;

    if (Set_WINAPI_StructA(&WinApi_Hook_Data, lpWinApi_Basic_Hook_Data) == FALSE)
    {
        Error("Set_WINAPI_StructA");
        return FALSE;
    }

    if (PID == NULL)
    {
        WinApi_Hook_Data.hProcess = GetProcessHandleByFileNameA(ProcessName);
    }
    else
    {
        WinApi_Hook_Data.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    }

    if (WinApi_Hook_Data.hProcess == NULL)
    {
        Error("OpenProcess");
        return FALSE;
    }

    if (!WriteNewFunctionA(&WinApi_Hook_Data))
    {
        printf("WriteNewFunction\n");
        return FALSE;
    }
    if (!CopyDLLCodeA(&WinApi_Hook_Data))
    {
        printf("CopyDLLCode\n");
        return FALSE;
    }
    if (!SetAssemblyInstructionA(&WinApi_Hook_Data))
    {
        printf("SetAssemblyInstruction\n");
        return FALSE;
    }
    if (!SetCopyFunctionA(&WinApi_Hook_Data))
    {
        printf("SetCopyFunction\n");
        return FALSE;
    }
    if (WinApi_Hook_Data.Parameter)
    {
        if (!WriteParameterA(&WinApi_Hook_Data))
        {
            printf("WriteParameter\n");
            return FALSE;
        }
    }
    if (!CodePatchA(&WinApi_Hook_Data))
    {
        printf("CodePatch\n");
        return FALSE;
    }
}

BOOL HookW(PWINAPI_BASIC_HOOK_DATAW lpWinApi_Basic_Hook_Data, DWORD PID, wchar_t *ProcessName)
{
    WINAPI_HOOK_DATAW WinApi_Hook_Data;

    if (Set_WINAPI_StructW(&WinApi_Hook_Data, lpWinApi_Basic_Hook_Data) == FALSE)
    {
        Error("Set_WINAPI_StructW");
        return FALSE;
    }

    if (PID == NULL)
    {
        WinApi_Hook_Data.hProcess = GetProcessHandleByFileNameW(ProcessName);
    }
    else
    {
        WinApi_Hook_Data.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    }

    if (WinApi_Hook_Data.hProcess == NULL)
    {
        Error("OpenProcess");
        return FALSE;
    }

    if (!WriteNewFunctionW(&WinApi_Hook_Data))
    {
        printf("WriteNewFunction\n");
        return FALSE;
    }
    if (!CopyDLLCodeW(&WinApi_Hook_Data))
    {
        printf("CopyDLLCode\n");
        return FALSE;
    }
    if (!SetAssemblyInstructionW(&WinApi_Hook_Data))
    {
        printf("SetAssemblyInstruction\n");
        return FALSE;
    }
    if (!SetCopyFunctionW(&WinApi_Hook_Data))
    {
        printf("SetCopyFunction\n");
        return FALSE;
    }
    if (WinApi_Hook_Data.Parameter)
    {
        if (!WriteParameterW(&WinApi_Hook_Data))
        {
            printf("WriteParameter\n");
            return FALSE;
        }
    }
    if (!CodePatchW(&WinApi_Hook_Data))
    {
        printf("CodePatch\n");
        return FALSE;
    }
}

BOOL WriteNewFunctionA(PWINAPI_HOOK_DATAA lpWinApi_Hook_Data)
{
    lpWinApi_Hook_Data->lpNewFunctionEx = VirtualAllocEx(lpWinApi_Hook_Data->hProcess, NULL, lpWinApi_Hook_Data->dwNewFuncSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (lpWinApi_Hook_Data->lpNewFunctionEx == NULL)
    {
        Error("VirtualAllocEx");
        return FALSE;
    }

    if (WriteProcessMemory(lpWinApi_Hook_Data->hProcess, lpWinApi_Hook_Data->lpNewFunctionEx, lpWinApi_Hook_Data->lpNewFunction, lpWinApi_Hook_Data->dwNewFuncSize, NULL) == FALSE)
    {
        Error("WriteProcessMemory");
        return FALSE;
    }

    return TRUE;
}

BOOL WriteNewFunctionW(PWINAPI_HOOK_DATAW lpWinApi_Hook_Data)
{
    lpWinApi_Hook_Data->lpNewFunctionEx = VirtualAllocEx(lpWinApi_Hook_Data->hProcess, NULL, lpWinApi_Hook_Data->dwNewFuncSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (lpWinApi_Hook_Data->lpNewFunctionEx == NULL)
    {
        Error("VirtualAllocEx");
        return FALSE;
    }

    if (WriteProcessMemory(lpWinApi_Hook_Data->hProcess, lpWinApi_Hook_Data->lpNewFunctionEx, lpWinApi_Hook_Data->lpNewFunction, lpWinApi_Hook_Data->dwNewFuncSize, NULL) == FALSE)
    {
        Error("WriteProcessMemory");
        return FALSE;
    }

    return TRUE;
}

BOOL CopyDLLCodeA(PWINAPI_HOOK_DATAA lpWinApi_Hook_Data)
{
    BYTE *Data;
    lpWinApi_Hook_Data->hModule = LoadLibraryA(lpWinApi_Hook_Data->DLLName);

    if (lpWinApi_Hook_Data->hModule == NULL)
    {
        Error("LoadLibraryA");
        return FALSE;
    }

    PIMAGE_NT_HEADERS pinth = ImageNtHeader(lpWinApi_Hook_Data->hModule);

    if (pinth == NULL)
    {
        Error("ImageNtHeader");
        return FALSE;
    }

    Data = malloc(pinth->OptionalHeader.SizeOfImage);

    memcpy(Data, (Address)lpWinApi_Hook_Data->hModule + (Address)pinth->OptionalHeader.BaseOfCode, (Address)pinth->OptionalHeader.SizeOfImage - (Address)pinth->OptionalHeader.BaseOfCode);

    if(memcmp(Data, (Address)lpWinApi_Hook_Data->hModule + (Address)pinth->OptionalHeader.BaseOfCode, (Address)pinth->OptionalHeader.SizeOfImage - (Address)pinth->OptionalHeader.BaseOfCode) != 0)
    {
        Error("memcpy");
        return FALSE;
    }

	lpWinApi_Hook_Data->lpCopyBaseOfCode = VirtualAllocEx(lpWinApi_Hook_Data->hProcess, NULL, (Address)pinth->OptionalHeader.SizeOfImage - (Address)pinth->OptionalHeader.BaseOfCode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (lpWinApi_Hook_Data->lpCopyBaseOfCode == NULL)
    {
        Error("VirtualAllocEx");
        return FALSE;
    }

	if (WriteProcessMemory(lpWinApi_Hook_Data->hProcess, lpWinApi_Hook_Data->lpCopyBaseOfCode, Data, (Address)pinth->OptionalHeader.SizeOfImage - (Address)pinth->OptionalHeader.BaseOfCode, NULL) == NULL)
    {
        Error("WriteProcessMemory");
        return FALSE;
    }

    free(Data);

    return TRUE;
}

BOOL CopyDLLCodeW(PWINAPI_HOOK_DATAW lpWinApi_Hook_Data)
{
    BYTE *Data;
    lpWinApi_Hook_Data->hModule = LoadLibraryW(lpWinApi_Hook_Data->DLLName);

    if (lpWinApi_Hook_Data->hModule == NULL)
    {
        Error("LoadLibraryA");
        return FALSE;
    }

    PIMAGE_NT_HEADERS pinth = ImageNtHeader(lpWinApi_Hook_Data->hModule);

    if (pinth == NULL)
    {
        Error("ImageNtHeader");
        return FALSE;
    }

    Data = malloc(pinth->OptionalHeader.SizeOfImage);

    memcpy(Data, (Address)lpWinApi_Hook_Data->hModule + (Address)pinth->OptionalHeader.BaseOfCode, (Address)pinth->OptionalHeader.SizeOfImage - (Address)pinth->OptionalHeader.BaseOfCode);

    if(memcmp(Data, (Address)lpWinApi_Hook_Data->hModule + (Address)pinth->OptionalHeader.BaseOfCode, (Address)pinth->OptionalHeader.SizeOfImage - (Address)pinth->OptionalHeader.BaseOfCode) != 0)
    {
        Error("memcpy");
        return FALSE;
    }

	lpWinApi_Hook_Data->lpCopyBaseOfCode = VirtualAllocEx(lpWinApi_Hook_Data->hProcess, NULL, (Address)pinth->OptionalHeader.SizeOfImage - (Address)pinth->OptionalHeader.BaseOfCode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (lpWinApi_Hook_Data->lpCopyBaseOfCode == NULL)
    {
        Error("VirtualAllocEx");
        return FALSE;
    }

	if (WriteProcessMemory(lpWinApi_Hook_Data->hProcess, lpWinApi_Hook_Data->lpCopyBaseOfCode, Data, (Address)pinth->OptionalHeader.SizeOfImage - (Address)pinth->OptionalHeader.BaseOfCode, NULL) == NULL)
    {
        Error("WriteProcessMemory");
        return FALSE;
    }

    free(Data);

    return TRUE;
}

BOOL SetAssemblyInstructionA(PWINAPI_HOOK_DATAA lpWinApi_Hook_Data)
{
    memcpy(lpWinApi_Hook_Data->jmpCode, Instruction, sizeof(Instruction));
    int i = 0;

    for (; i < sizeof(Instruction); i++)
    {
        if (lpWinApi_Hook_Data->jmpCode[i] == 0x00)
        {
            memcpy(&lpWinApi_Hook_Data->jmpCode[i], &lpWinApi_Hook_Data->lpNewFunctionEx, sizeof(Address));
            break;
        }
    }

    if (i == sizeof(Instruction))
    {
        Error("memcpy");
        return FALSE;
    }

    return TRUE;
}

BOOL SetAssemblyInstructionW(PWINAPI_HOOK_DATAW lpWinApi_Hook_Data)
{
    memcpy(lpWinApi_Hook_Data->jmpCode, Instruction, sizeof(Instruction));
    int i = 0;

    for (; i < sizeof(Instruction); i++)
    {
        if (lpWinApi_Hook_Data->jmpCode[i] == 0x00)
        {
            memcpy(&lpWinApi_Hook_Data->jmpCode[i], &lpWinApi_Hook_Data->lpNewFunctionEx, sizeof(Address));
            break;
        }
    }

    if (i == sizeof(Instruction))
    {
        Error("memcpy");
        return FALSE;
    }

    return TRUE;
}

BOOL SetCopyFunctionA(PWINAPI_HOOK_DATAA lpWinApi_Hook_Data)
{
    Address Offset;

    PIMAGE_NT_HEADERS pinth = ImageNtHeader(lpWinApi_Hook_Data->hModule);
    Offset = (Address)lpWinApi_Hook_Data->lpOrigin - (Address)pinth->OptionalHeader.ImageBase - (Address)pinth->OptionalHeader.BaseOfCode;
    *lpWinApi_Hook_Data->lpCopyOrigin = (Address)lpWinApi_Hook_Data->lpCopyBaseOfCode + Offset;

    return TRUE;
}

BOOL SetCopyFunctionW(PWINAPI_HOOK_DATAW lpWinApi_Hook_Data)
{
    Address Offset;

    PIMAGE_NT_HEADERS pinth = ImageNtHeader(lpWinApi_Hook_Data->hModule);
    Offset = (Address)lpWinApi_Hook_Data->lpOrigin - (Address)pinth->OptionalHeader.ImageBase - (Address)pinth->OptionalHeader.BaseOfCode;
    *lpWinApi_Hook_Data->lpCopyOrigin = (Address)lpWinApi_Hook_Data->lpCopyBaseOfCode + Offset;

    return TRUE;
}

BOOL WriteParameterA(PWINAPI_HOOK_DATAA lpWinApi_Hook_Data)
{
    lpWinApi_Hook_Data->lpParameterEx = VirtualAllocEx(lpWinApi_Hook_Data->hProcess, NULL, lpWinApi_Hook_Data->dwParameterSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (lpWinApi_Hook_Data->lpParameterEx == NULL)
    {
        Error("VirtualAllocEx");
        return FALSE;
    }

    if (WriteProcessMemory(lpWinApi_Hook_Data->hProcess, lpWinApi_Hook_Data->lpParameterEx, lpWinApi_Hook_Data->lpParameter, lpWinApi_Hook_Data->dwParameterSize, NULL) == FALSE)
    {
        Error("WriteProcessMemory");
        return FALSE;
    }

    return TRUE;
}

BOOL WriteParameterW(PWINAPI_HOOK_DATAW lpWinApi_Hook_Data)
{
    lpWinApi_Hook_Data->lpParameterEx = VirtualAllocEx(lpWinApi_Hook_Data->hProcess, NULL, lpWinApi_Hook_Data->dwParameterSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (lpWinApi_Hook_Data->lpParameterEx == NULL)
    {
        Error("VirtualAllocEx");
        return FALSE;
    }

    if (WriteProcessMemory(lpWinApi_Hook_Data->hProcess, lpWinApi_Hook_Data->lpParameterEx, lpWinApi_Hook_Data->lpParameter, lpWinApi_Hook_Data->dwParameterSize, NULL) == FALSE)
    {
        Error("WriteProcessMemory");
        return FALSE;
    }

    return TRUE;
}

BOOL CodePatchA(PWINAPI_HOOK_DATAA lpWinApi_Hook_Data)
{
    DWORD dwOldProtect;
    if (VirtualProtectEx(lpWinApi_Hook_Data->hProcess, lpWinApi_Hook_Data->lpOrigin, sizeof(Instruction), PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
    {
        Error("VirtualProtectEx");
        return FALSE;
    }

    if (WriteProcessMemory(lpWinApi_Hook_Data->hProcess, lpWinApi_Hook_Data->lpOrigin, lpWinApi_Hook_Data->jmpCode, sizeof(Instruction), NULL) == FALSE)
    {
        Error("WriteProcessMemory");
        return FALSE;
    }

    if (VirtualProtectEx(lpWinApi_Hook_Data->hProcess, lpWinApi_Hook_Data->lpOrigin, sizeof(Instruction), dwOldProtect, &dwOldProtect) == FALSE)
    {
        Error("VirtualProtectEx");
        return FALSE;
    }

    if (lpWinApi_Hook_Data->Parameter)
    {
        BYTE Check;
        for (int i = 1; i < INFINITE; i++)
        {
            ReadProcessMemory(lpWinApi_Hook_Data->hProcess, (Address)lpWinApi_Hook_Data->lpNewFunctionEx + i, &Check, 1, NULL);
            if (Check == 0xCC)
            {
                if (WriteProcessMemory(lpWinApi_Hook_Data->hProcess, (Address)lpWinApi_Hook_Data->lpNewFunctionEx + i, &lpWinApi_Hook_Data->lpParameterEx, sizeof(Address), NULL) == FALSE)
                {
                    Error("WriteProcessMemory");
                    return FALSE;
                }
                break;
            }
        }
    }

    return TRUE;
}

BOOL CodePatchW(PWINAPI_HOOK_DATAW lpWinApi_Hook_Data)
{
    DWORD dwOldProtect;
    if (VirtualProtectEx(lpWinApi_Hook_Data->hProcess, lpWinApi_Hook_Data->lpOrigin, sizeof(Instruction), PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
    {
        Error("VirtualProtectEx");
        return FALSE;
    }

    if (WriteProcessMemory(lpWinApi_Hook_Data->hProcess, lpWinApi_Hook_Data->lpOrigin, lpWinApi_Hook_Data->jmpCode, sizeof(Instruction), NULL) == FALSE)
    {
        Error("WriteProcessMemory");
        return FALSE;
    }

    if (VirtualProtectEx(lpWinApi_Hook_Data->hProcess, lpWinApi_Hook_Data->lpOrigin, sizeof(Instruction), dwOldProtect, &dwOldProtect) == FALSE)
    {
        Error("VirtualProtectEx");
        return FALSE;
    }

    if (lpWinApi_Hook_Data->Parameter)
    {
        BYTE Check;
        for (int i = 1; i < INFINITE; i++)
        {
            ReadProcessMemory(lpWinApi_Hook_Data->hProcess, (Address)lpWinApi_Hook_Data->lpNewFunctionEx + i, &Check, 1, NULL);
            if (Check == 0xCC)
            {
                if (WriteProcessMemory(lpWinApi_Hook_Data->hProcess, (Address)lpWinApi_Hook_Data->lpNewFunctionEx + i, &lpWinApi_Hook_Data->lpParameterEx, sizeof(Address), NULL) == FALSE)
                {
                    Error("WriteProcessMemory");
                    return FALSE;
                }
                break;
            }
        }
    }

    return TRUE;
}

BOOL Set_WINAPI_StructA(PWINAPI_HOOK_DATAA lpWinApi_Hook_Data, PWINAPI_BASIC_HOOK_DATAA lpWinApi_Basic_Hook_Data)
{
    lpWinApi_Hook_Data->lpOrigin = lpWinApi_Basic_Hook_Data->lpOrigin;
    lpWinApi_Hook_Data->lpCopyOrigin = lpWinApi_Basic_Hook_Data->lpCopyOrigin;
    lpWinApi_Hook_Data->lpNewFunction = lpWinApi_Basic_Hook_Data->lpNewFunction;
    lpWinApi_Hook_Data->lpParameter = lpWinApi_Basic_Hook_Data->lpParameter;
    lpWinApi_Hook_Data->Parameter = lpWinApi_Basic_Hook_Data->Parameter;
    lpWinApi_Hook_Data->dwParameterSize = lpWinApi_Basic_Hook_Data->dwParameterSize;
    lpWinApi_Hook_Data->dwNewFuncSize = lpWinApi_Basic_Hook_Data->dwNewFuncSize;
    strcpy(lpWinApi_Hook_Data->DLLName, lpWinApi_Basic_Hook_Data->DLLName);
    return TRUE;
}

BOOL Set_WINAPI_StructW(PWINAPI_HOOK_DATAW lpWinApi_Hook_Data, PWINAPI_BASIC_HOOK_DATAW lpWinApi_Basic_Hook_Data)
{
    lpWinApi_Hook_Data->lpOrigin = lpWinApi_Basic_Hook_Data->lpOrigin;
    lpWinApi_Hook_Data->lpCopyOrigin = lpWinApi_Basic_Hook_Data->lpCopyOrigin;
    lpWinApi_Hook_Data->lpNewFunction = lpWinApi_Basic_Hook_Data->lpNewFunction;
    lpWinApi_Hook_Data->lpParameter = lpWinApi_Basic_Hook_Data->lpParameter;
    lpWinApi_Hook_Data->Parameter = lpWinApi_Basic_Hook_Data->Parameter;
    lpWinApi_Hook_Data->dwParameterSize = lpWinApi_Basic_Hook_Data->dwParameterSize;
    lpWinApi_Hook_Data->dwNewFuncSize = lpWinApi_Basic_Hook_Data->dwNewFuncSize;
    wcscpy(lpWinApi_Hook_Data->DLLName, lpWinApi_Basic_Hook_Data->DLLName);
    return TRUE;
}

void Error(char FunctionName[])
{
    printf("%s() Failed!\n", FunctionName);
    printf("Error Code : %d\n", GetLastError());
}