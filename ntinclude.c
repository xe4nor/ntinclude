#include "ntinclude.h"
#include <stdio.h>

pNtAllocateVirtualMemory NtAllocateVirtualMemory = NULL;
pNtFreeVirtualMemory NtFreeVirtualMemory = NULL;
pNtProtectVirtualMemory NtProtectVirtualMemory = NULL;
pNtReadVirtualMemory NtReadVirtualMemory = NULL;
pNtWriteVirtualMemory NtWriteVirtualMemory = NULL;
pNtQueryVirtualMemory NtQueryVirtualMemory = NULL;
pNtLockVirtualMemory NtLockVirtualMemory = NULL;
pNtUnlockVirtualMemory NtUnlockVirtualMemory = NULL;
pNtFlushVirtualMemory NtFlushVirtualMemory = NULL;
pNtMapViewOfSection NtMapViewOfSection = NULL;
pNtUnmapViewOfSection NtUnmapViewOfSection = NULL;
pNtCreateSection NtCreateSection = NULL;

pNtCreateThreadEx NtCreateThreadEx = NULL;
pNtSuspendThread NtSuspendThread = NULL;
pNtResumeThread NtResumeThread = NULL;
pNtTerminateThread NtTerminateThread = NULL;
pNtOpenThread NtOpenThread = NULL;
pNtQueryInformationThread NtQueryInformationThread = NULL;
pNtSetInformationThread NtSetInformationThread = NULL;
pNtGetContextThread NtGetContextThread = NULL;
pNtSetContextThread NtSetContextThread = NULL;
pNtQueueApcThread NtQueueApcThread = NULL;

pNtCreateProcess NtCreateProcess = NULL;
pNtOpenProcess NtOpenProcess = NULL;
pNtTerminateProcess NtTerminateProcess = NULL;
pNtQueryInformationProcess NtQueryInformationProcess = NULL;
pNtSetInformationProcess NtSetInformationProcess = NULL;
pNtResumeProcess NtResumeProcess = NULL;
pNtSuspendProcess NtSuspendProcess = NULL;

pNtOpenProcessToken NtOpenProcessToken = NULL;
pNtOpenThreadToken NtOpenThreadToken = NULL;
pNtDuplicateToken NtDuplicateToken = NULL;
pNtAdjustPrivilegesToken NtAdjustPrivilegesToken = NULL;
pNtQueryInformationToken NtQueryInformationToken = NULL;
pNtDuplicateObject NtDuplicateObject = NULL;
pNtClose NtClose = NULL;
pNtQueryObject NtQueryObject = NULL;

//pLdrLoadDll NtLoadDll = NULL;
//pLdrUnloadDll NtUnloadDll = NULL;
pNtQuerySection NtQuerySection = NULL;

pNtCreateFile NtCreateFile = NULL;
pNtOpenFile NtOpenFile = NULL;
pNtReadFile NtReadFile = NULL;
pNtWriteFile NtWriteFile = NULL;
pNtDeleteFile NtDeleteFile = NULL;
pNtQueryInformationFile NtQueryInformationFile = NULL;
pNtSetInformationFile NtSetInformationFile = NULL;
pNtQueryAttributesFile NtQueryAttributesFile = NULL;

pNtCreateKey NtCreateKey = NULL;
pNtOpenKey NtOpenKey = NULL;
pNtDeleteKey NtDeleteKey = NULL;
pNtSetValueKey NtSetValueKey = NULL;
pNtQueryValueKey NtQueryValueKey = NULL;

pNtQuerySystemInformation NtQuerySystemInformation = NULL;
pNtSetSystemInformation NtSetSystemInformation = NULL;
pNtDelayExecution NtDelayExecution = NULL;
pNtWaitForSingleObject NtWaitForSingleObject = NULL;
pNtWaitForMultipleObjects NtWaitForMultipleObjects = NULL;
pNtTestAlert NtTestAlert = NULL;
pNtContinue NtContinue = NULL;
pNtRaiseHardError NtRaiseHardError = NULL;

#define RESOLVE(name)                                                     \
    do {                                                                  \
        name = (p##name)GetProcAddress(ntdll, #name);                     \
        if (!(name)) {                                                    \
            printf("[!] %s nicht gefunden!\n", #name);                    \
            return FALSE;                                                 \
        }                                                                 \
    } while (0)



BOOL ResolveNtFunctions() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("[!] ntdll.dll nicht gefunden!\n");
        return FALSE;
    }

    RESOLVE(NtAllocateVirtualMemory);
    RESOLVE(NtFreeVirtualMemory);
    RESOLVE(NtProtectVirtualMemory);
    RESOLVE(NtReadVirtualMemory);
    RESOLVE(NtWriteVirtualMemory);
    RESOLVE(NtQueryVirtualMemory);
    RESOLVE(NtLockVirtualMemory);
    RESOLVE(NtUnlockVirtualMemory);
    RESOLVE(NtFlushVirtualMemory);
    RESOLVE(NtMapViewOfSection);
    RESOLVE(NtUnmapViewOfSection);
    RESOLVE(NtCreateSection);

    RESOLVE(NtCreateThreadEx);
    RESOLVE(NtSuspendThread);
    RESOLVE(NtResumeThread);
    RESOLVE(NtTerminateThread);
    RESOLVE(NtOpenThread);
    RESOLVE(NtQueryInformationThread);
    RESOLVE(NtSetInformationThread);
    RESOLVE(NtGetContextThread);
    RESOLVE(NtSetContextThread);
    RESOLVE(NtQueueApcThread);

    RESOLVE(NtCreateProcess);
    RESOLVE(NtOpenProcess);
    RESOLVE(NtTerminateProcess);
    RESOLVE(NtQueryInformationProcess);
    RESOLVE(NtSetInformationProcess);
    RESOLVE(NtResumeProcess);
    RESOLVE(NtSuspendProcess);

    RESOLVE(NtOpenProcessToken);
    RESOLVE(NtOpenThreadToken);
    RESOLVE(NtDuplicateToken);
    RESOLVE(NtAdjustPrivilegesToken);
    RESOLVE(NtQueryInformationToken);
    RESOLVE(NtDuplicateObject);
    RESOLVE(NtClose);
    RESOLVE(NtQueryObject);

    //RESOLVE(LdrLoadDll);
    //RESOLVE(LdrUnloadDll);
    RESOLVE(NtQuerySection);

    RESOLVE(NtCreateFile);
    RESOLVE(NtOpenFile);
    RESOLVE(NtReadFile);
    RESOLVE(NtWriteFile);
    RESOLVE(NtDeleteFile);
    RESOLVE(NtQueryInformationFile);
    RESOLVE(NtSetInformationFile);
    RESOLVE(NtQueryAttributesFile);

    RESOLVE(NtCreateKey);
    RESOLVE(NtOpenKey);
    RESOLVE(NtDeleteKey);
    RESOLVE(NtSetValueKey);
    RESOLVE(NtQueryValueKey);

    RESOLVE(NtQuerySystemInformation);
    RESOLVE(NtSetSystemInformation);
    RESOLVE(NtDelayExecution);
    RESOLVE(NtWaitForSingleObject);
    RESOLVE(NtWaitForMultipleObjects);
    RESOLVE(NtTestAlert);
    RESOLVE(NtContinue);
    RESOLVE(NtRaiseHardError);

    return TRUE;
}
