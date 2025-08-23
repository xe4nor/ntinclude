#pragma once
#include <Windows.h>

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
typedef NTSTATUS (NTAPI *pNtFreeVirtualMemory)(HANDLE,PVOID*,PSIZE_T,ULONG);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);
typedef NTSTATUS (NTAPI *pNtReadVirtualMemory)(HANDLE,PVOID,PVOID,ULONG,PULONG);
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(HANDLE,PVOID,PVOID,ULONG,PULONG);
typedef NTSTATUS (NTAPI *pNtQueryVirtualMemory)(HANDLE,PVOID,ULONG,PVOID,SIZE_T,PSIZE_T);
typedef NTSTATUS (NTAPI *pNtLockVirtualMemory)(HANDLE,PVOID*,PSIZE_T,ULONG);
typedef NTSTATUS (NTAPI *pNtUnlockVirtualMemory)(HANDLE,PVOID*,PSIZE_T,ULONG);
typedef NTSTATUS (NTAPI *pNtFlushVirtualMemory)(HANDLE,PVOID*,PSIZE_T,PIO_STATUS_BLOCK);
typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,DWORD,ULONG,ULONG);
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE,PVOID);
typedef NTSTATUS (NTAPI *pNtCreateSection)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PLARGE_INTEGER,ULONG,ULONG,HANDLE);

typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
typedef NTSTATUS (NTAPI *pNtSuspendThread)(HANDLE,PULONG);
typedef NTSTATUS (NTAPI *pNtResumeThread)(HANDLE,PULONG);
typedef NTSTATUS (NTAPI *pNtTerminateThread)(HANDLE,NTSTATUS);
typedef NTSTATUS (NTAPI *pNtOpenThread)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PCLIENT_ID);
typedef NTSTATUS (NTAPI *pNtQueryInformationThread)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS (NTAPI *pNtSetInformationThread)(HANDLE,ULONG,PVOID,ULONG);
typedef NTSTATUS (NTAPI *pNtGetContextThread)(HANDLE,PCONTEXT);
typedef NTSTATUS (NTAPI *pNtSetContextThread)(HANDLE,PCONTEXT);
typedef NTSTATUS (NTAPI *pNtQueueApcThread)(HANDLE,PVOID,PVOID,PVOID,PVOID);

typedef NTSTATUS (NTAPI *pNtCreateProcess)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,BOOLEAN,HANDLE,HANDLE,HANDLE);
typedef NTSTATUS (NTAPI *pNtOpenProcess)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PCLIENT_ID);
typedef NTSTATUS (NTAPI *pNtTerminateProcess)(HANDLE,NTSTATUS);
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(HANDLE,ULONG,PVOID,ULONG);
typedef NTSTATUS (NTAPI *pNtResumeProcess)(HANDLE);
typedef NTSTATUS (NTAPI *pNtSuspendProcess)(HANDLE);

typedef NTSTATUS (NTAPI *pNtOpenProcessToken)(HANDLE,ACCESS_MASK,PHANDLE);
typedef NTSTATUS (NTAPI *pNtOpenThreadToken)(HANDLE,ACCESS_MASK,BOOLEAN,PHANDLE);
typedef NTSTATUS (NTAPI *pNtDuplicateToken)(HANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,BOOLEAN,TOKEN_TYPE,PHANDLE);
typedef NTSTATUS (NTAPI *pNtAdjustPrivilegesToken)(HANDLE,BOOLEAN,PTOKEN_PRIVILEGES,ULONG,PTOKEN_PRIVILEGES,PULONG);
typedef NTSTATUS (NTAPI *pNtQueryInformationToken)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS (NTAPI *pNtDuplicateObject)(HANDLE,HANDLE,PHANDLE,HANDLE,ACCESS_MASK,ULONG,ULONG);
typedef NTSTATUS (NTAPI *pNtClose)(HANDLE);
typedef NTSTATUS (NTAPI *pNtQueryObject)(HANDLE,ULONG,PVOID,ULONG,PULONG);

typedef NTSTATUS (NTAPI *pNtLoadDll)(PWSTR,PULONG,PUNICODE_STRING,PHANDLE);
typedef NTSTATUS (NTAPI *pNtUnloadDll)(HANDLE);
typedef NTSTATUS (NTAPI *pNtQuerySection)(HANDLE,ULONG,PVOID,SIZE_T,PSIZE_T);

typedef NTSTATUS (NTAPI *pNtCreateFile)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
typedef NTSTATUS (NTAPI *pNtOpenFile)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,ULONG,ULONG);
typedef NTSTATUS (NTAPI *pNtReadFile)(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG);
typedef NTSTATUS (NTAPI *pNtWriteFile)(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG);
typedef NTSTATUS (NTAPI *pNtDeleteFile)(POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *pNtQueryInformationFile)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,ULONG);
typedef NTSTATUS (NTAPI *pNtSetInformationFile)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,ULONG);
typedef NTSTATUS (NTAPI *pNtQueryAttributesFile)(POBJECT_ATTRIBUTES,PFILE_BASIC_INFORMATION);

typedef NTSTATUS (NTAPI *pNtCreateKey)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,ULONG,PUNICODE_STRING,ULONG,PULONG);
typedef NTSTATUS (NTAPI *pNtOpenKey)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *pNtDeleteKey)(HANDLE);
typedef NTSTATUS (NTAPI *pNtSetValueKey)(HANDLE,PUNICODE_STRING,ULONG,ULONG,PVOID,ULONG);
typedef NTSTATUS (NTAPI *pNtQueryValueKey)(HANDLE,PUNICODE_STRING,ULONG,PVOID,ULONG,PULONG);

typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS (NTAPI *pNtSetSystemInformation)(ULONG,PVOID,ULONG);
typedef NTSTATUS (NTAPI *pNtDelayExecution)(BOOLEAN,PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *pNtWaitForSingleObject)(HANDLE,BOOLEAN,PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *pNtWaitForMultipleObjects)(ULONG,PHANDLE,BOOLEAN,BOOLEAN,PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *pNtTestAlert)(VOID);
typedef NTSTATUS (NTAPI *pNtContinue)(PCONTEXT,BOOLEAN);
typedef NTSTATUS (NTAPI *pNtRaiseHardError)(NTSTATUS,ULONG,ULONG,PULONG_PTR,PULONG,PULONG);

extern pNtAllocateVirtualMemory NtAllocateVirtualMemory;
extern pNtFreeVirtualMemory NtFreeVirtualMemory;
extern pNtProtectVirtualMemory NtProtectVirtualMemory;
extern pNtReadVirtualMemory NtReadVirtualMemory;
extern pNtWriteVirtualMemory NtWriteVirtualMemory;
extern pNtQueryVirtualMemory NtQueryVirtualMemory;
extern pNtCreateThreadEx NtCreateThreadEx;
extern pNtOpenProcess NtOpenProcess;
extern pNtQuerySystemInformation NtQuerySystemInformation;
extern pNtDelayExecution NtDelayExecution;

extern pNtCreateThreadEx NtCreateThreadEx;
extern pNtSuspendThread NtSuspendThread;
extern pNtResumeThread NtResumeThread;
extern pNtTerminateThread NtTerminateThread;
extern pNtOpenThread NtOpenThread;
extern pNtQueryInformationThread NtQueryInformationThread;
extern pNtSetInformationThread NtSetInformationThread;
extern pNtGetContextThread NtGetContextThread;
extern pNtSetContextThread NtSetContextThread;
extern pNtQueueApcThread NtQueueApcThread;

extern pNtCreateProcess NtCreateProcess;
extern pNtOpenProcess NtOpenProcess;
extern pNtTerminateProcess NtTerminateProcess;
extern pNtQueryInformationProcess NtQueryInformationProcess;
extern pNtSetInformationProcess NtSetInformationProcess;
extern pNtResumeProcess NtResumeProcess;
extern pNtSuspendProcess NtSuspendProcess;

extern pNtOpenProcessToken NtOpenProcessToken;
extern pNtOpenThreadToken NtOpenThreadToken;
extern pNtDuplicateToken NtDuplicateToken;
extern pNtAdjustPrivilegesToken NtAdjustPrivilegesToken;
extern pNtQueryInformationToken NtQueryInformationToken;
extern pNtDuplicateObject NtDuplicateObject;
extern pNtClose NtClose;
extern pNtQueryObject NtQueryObject;

extern pNtLoadDll NtLoadDll;
extern pNtUnloadDll NtUnloadDll;
extern pNtQuerySection NtQuerySection;

extern pNtCreateFile NtCreateFile;
extern pNtOpenFile NtOpenFile;
extern pNtReadFile NtReadFile;
extern pNtWriteFile NtWriteFile;
extern pNtDeleteFile NtDeleteFile;
extern pNtQueryInformationFile NtQueryInformationFile;
extern pNtSetInformationFile NtSetInformationFile;
extern pNtQueryAttributesFile NtQueryAttributesFile;

extern pNtCreateKey NtCreateKey;
extern pNtOpenKey NtOpenKey;
extern pNtDeleteKey NtDeleteKey;
extern pNtSetValueKey NtSetValueKey;
extern pNtQueryValueKey NtQueryValueKey;

extern pNtQuerySystemInformation NtQuerySystemInformation;
extern pNtSetSystemInformation NtSetSystemInformation;
extern pNtDelayExecution NtDelayExecution;
extern pNtWaitForSingleObject NtWaitForSingleObject;
extern pNtWaitForMultipleObjects NtWaitForMultipleObjects;
extern pNtTestAlert NtTestAlert;
extern pNtContinue NtContinue;
extern pNtRaiseHardError NtRaiseHardError;

BOOL ResolveNtFunctions();
