# WinHook
WinHook


English

The above library is a library that hooks Windows API functions. Hooking targets may also be subject to processes other than the current ones.


Korean

위 라이브러리는 윈도우 API 함수를 후킹해주는 라이브러리이다. 후킹대상은 현재 프로세스가 아닌 다른 프로세스를 대상으로도 진행 할 수 있다.

# How to used
<img src="https://github.com/jungjin0003/WinHook/blob/master/Example%20Code.png"></img>
## Struct Explanation
ASCII Struct
```
typedef struct _WINAPI_HOOK_DATAA {
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
    _require_ DWORD dwNewFuncSize; Size of (new) function address to be jumped
    _one_is_require_ DWORD dwPID; // Target process PID (Set PID or Process Name)
    BYTE jmpCode[sizeof(Instruction)];
    _require_ char DLLName[MAX_PATH]; // DLL name of function to be hook
    _one_is_require_ char ProcessName[MAX_PATH]; // Target process name (Set PID or Process Name)
} WINAPI_HOOK_DATAA, *PWINAPI_HOOK_DATAA;
```
Set to NULL if PID is not used. 

Wide Char Struct
```
typedef struct _WINAPI_HOOK_DATAW {
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
    _require_ DWORD dwNewFuncSize; Size of (new) function address to be jumped
    _one_is_require_ DWORD dwPID; // Target process PID (Set PID or Process Name)
    BYTE jmpCode[sizeof(Instruction)];
    _require_ char DLLName[MAX_PATH]; // DLL name of function to be hook
    _one_is_require_ WCHAR ProcessName[MAX_PATH]; // Target process name (Set PID or Process Name)
} WINAPI_HOOK_DATAW, *PWINAPI_HOOK_DATAW;
```
