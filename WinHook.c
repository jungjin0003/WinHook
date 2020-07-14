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
        hProcess = OpenProcess(PROCESS_ALL_ACCESS,TRUE,process_id_array[i]);
        if(GetModuleBaseNameA(hProcess, 0, image_name, MAX_PATH))
        {
            if(!stricmp(image_name,name))
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

BOOL HookA(PWINAPI_HOOK_DATAA lpWinApi_Hook_Data)
{
    if (lpWinApi_Hook_Data->dwPID == NULL)
    {
        lpWinApi_Hook_Data->hProcess = GetProcessHandleByFileNameA(lpWinApi_Hook_Data->ProcessName);
    }
    else
    {
        lpWinApi_Hook_Data->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lpWinApi_Hook_Data->dwPID);
    }

    if (lpWinApi_Hook_Data->hProcess == NULL)
    {
        Error("OpenProcess");
        return FALSE;
    }

    if (!WriteNewFunctionA(lpWinApi_Hook_Data))
    {
        printf("WriteNewFunction\n");
        return FALSE;
    }
    if (!CopyDLLCodeA(lpWinApi_Hook_Data))
    {
        printf("CopyDLLCode\n");
        return FALSE;
    }
    if (!SetAssemblyInstructionA(lpWinApi_Hook_Data))
    {
        printf("SetAssemblyInstruction\n");
        return FALSE;
    }
    if (!SetCopyFunctionA(lpWinApi_Hook_Data))
    {
        printf("SetCopyFunction\n");
        return FALSE;
    }
    if (lpWinApi_Hook_Data->Parameter)
    {
        if (!WriteParameterA(lpWinApi_Hook_Data))
        {
            printf("WriteParameter\n");
            return FALSE;
        }
    }
    if (!CodePatchA(lpWinApi_Hook_Data))
    {
        printf("CodePatch\n");
        return FALSE;
    }
}

BOOL HookW(PWINAPI_HOOK_DATAW lpWinApi_Hook_Data)
{
    if (lpWinApi_Hook_Data->dwPID == NULL)
    {
        lpWinApi_Hook_Data->hProcess = GetProcessHandleByFileNameW(lpWinApi_Hook_Data->ProcessName);
    }
    else
    {
        lpWinApi_Hook_Data->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lpWinApi_Hook_Data->dwPID);
    }

    if (lpWinApi_Hook_Data->hProcess == NULL)
    {
        Error("OpenProcess");
        return FALSE;
    }

    if (!WriteNewFunctionW(lpWinApi_Hook_Data))
    {
        printf("WriteNewFunction\n");
        return FALSE;
    }
    if (!CopyDLLCodeW(lpWinApi_Hook_Data))
    {
        printf("CopyDLLCode\n");
        return FALSE;
    }
    if (!SetAssemblyInstructionW(lpWinApi_Hook_Data))
    {
        printf("SetAssemblyInstruction\n");
        return FALSE;
    }
    if (!SetCopyFunctionW(lpWinApi_Hook_Data))
    {
        printf("SetCopyFunction\n");
        return FALSE;
    }
    if (lpWinApi_Hook_Data->Parameter)
    {
        if (!WriteParameterW(lpWinApi_Hook_Data))
        {
            printf("WriteParameter\n");
            return FALSE;
        }
    }
    if (!CodePatchW(lpWinApi_Hook_Data))
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

    if (ReadProcessMemory(lpWinApi_Hook_Data->hProcess, (Address)pinth->OptionalHeader.ImageBase + (Address)pinth->OptionalHeader.BaseOfCode, Data, (Address)pinth->OptionalHeader.SizeOfImage - (Address)pinth->OptionalHeader.SizeOfCode, NULL) == FALSE)
    {
        Error("ReadProcessMemory");
        return FALSE;
    }

	lpWinApi_Hook_Data->lpCopyBaseOfCode = VirtualAllocEx(lpWinApi_Hook_Data->hProcess, NULL, pinth->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (lpWinApi_Hook_Data->lpCopyBaseOfCode == NULL)
    {
        Error("VirtualAllocEx");
        return FALSE;
    }

	if (WriteProcessMemory(lpWinApi_Hook_Data->hProcess, lpWinApi_Hook_Data->lpCopyBaseOfCode, Data, (Address)pinth->OptionalHeader.SizeOfImage - (Address)pinth->OptionalHeader.SizeOfCode, NULL) == NULL)
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

    if (ReadProcessMemory(lpWinApi_Hook_Data->hProcess, (Address)pinth->OptionalHeader.ImageBase + (Address)pinth->OptionalHeader.BaseOfCode, Data, pinth->OptionalHeader.SizeOfImage, NULL) == FALSE)
    {
        Error("ReadProcessMemory");
        return FALSE;
    }

	lpWinApi_Hook_Data->lpCopyBaseOfCode = VirtualAllocEx(lpWinApi_Hook_Data->hProcess, NULL, pinth->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (lpWinApi_Hook_Data->lpCopyBaseOfCode == NULL)
    {
        Error("VirtualAllocEx");
        return FALSE;
    }

	if (WriteProcessMemory(lpWinApi_Hook_Data->hProcess, lpWinApi_Hook_Data->lpCopyBaseOfCode, Data, pinth->OptionalHeader.SizeOfImage, NULL) == NULL)
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

void Error(char FunctionName[])
{
    printf("%s() Failed!\n", FunctionName);
    printf("Error Code : %d\n", GetLastError());
}