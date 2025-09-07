#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        
    PVOID SecurityQualityOfService;  
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p,n,a,r,s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;


typedef VOID(NTAPI* PIO_APC_ROUTINE)(
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG Reserved
    );

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessQuotaLimits = 1,
    ProcessIoCounters = 2,
    ProcessVmCounters = 3,
    ProcessTimes = 4,
    ProcessBasePriority = 5,
    ProcessRaisePriority = 6,
    ProcessDebugPort = 7,
    ProcessExceptionPort = 8,
    ProcessAccessToken = 9,
    ProcessLdtInformation = 10,
    ProcessLdtSize = 11,
    ProcessDefaultHardErrorMode = 12,
    ProcessIoPortHandlers = 13,
    ProcessPooledUsageAndLimits = 14,
    ProcessWorkingSetWatch = 15,
    ProcessUserModeIOPL = 16,
    ProcessEnableAlignmentFaultFixup = 17,
    ProcessPriorityClass = 18,
    ProcessWx86Information = 19,
    ProcessHandleCount = 20,
    ProcessAffinityMask = 21,
    ProcessPriorityBoost = 22,
    ProcessDeviceMap = 23,
    ProcessSessionInformation = 24,
    ProcessForegroundInformation = 25,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessLUIDDeviceMapsEnabled = 28,
    ProcessBreakOnTermination = 29,
    ProcessDebugObjectHandle = 30,
    ProcessDebugFlags = 31,
    ProcessHandleTracing = 32,
    ProcessIoPriority = 33,
    ProcessExecuteFlags = 34,
    ProcessTlsInformation = 35,
    ProcessCookie = 36,
    ProcessImageInformation = 37,
    ProcessCycleTime = 38,
    ProcessPagePriority = 39,
    ProcessInstrumentationCallback = 40,
    ProcessThreadStackAllocation = 41,
    ProcessWorkingSetWatchEx = 42,
    ProcessImageFileNameWin32 = 43,
    ProcessImageFileMapping = 44,
    ProcessAffinityUpdateMode = 45,
    ProcessMemoryAllocationMode = 46,
    ProcessGroupInformation = 47,
    ProcessTokenVirtualizationEnabled = 48,
    ProcessConsoleHostProcess = 49,
    ProcessWindowInformation = 50,
    ProcessHandleInformation = 51,
    ProcessMitigationPolicy = 52,
    ProcessDynamicFunctionTableInformation = 53,
    ProcessHandleCheckingMode = 54,
    ProcessKeepAliveCount = 55,
    ProcessRevokeFileHandles = 56,
    ProcessWorkingSetControl = 57,
    ProcessHandleTable = 58,
    ProcessCheckStackExtentsMode = 59,
    ProcessCommandLineInformation = 60,
    ProcessProtectionInformation = 61,
    ProcessMemoryExhaustion = 62,
    ProcessFaultInformation = 63,
    ProcessTelemetryIdInformation = 64,
    ProcessCommitReleaseInformation = 65,
    ProcessDefaultCpuSetsInformation = 66,
    ProcessAllowedCpuSetsInformation = 67,
    ProcessSubsystemProcess = 68,
    ProcessJobMemoryInformation = 69,
    ProcessInPrivate = 70,
    ProcessRaiseUMExceptionOnInvalidHandleClose = 71,
    ProcessIumChallengeResponse = 72,
    ProcessChildProcessInformation = 73,
    ProcessHighGraphicsPriorityInformation = 74,
    ProcessSubsystemInformation = 75,
    ProcessEnergyValues = 76,
    ProcessActivityThrottleState = 77,
    ProcessActivityThrottlePolicy = 78,
    ProcessWin32kSyscallFilterInformation = 79,
    ProcessDisableSystemAllowedCpuSets = 80,
    ProcessWakeInformation = 81,
    ProcessEnergyTrackingState = 82,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0,
    ThreadTimes = 1,
    ThreadPriority = 2,
    ThreadBasePriority = 3,
    ThreadAffinityMask = 4,
    ThreadImpersonationToken = 5,
    ThreadDescriptorTableEntry = 6,
    ThreadEnableAlignmentFaultFixup = 7,
    ThreadEventPair = 8,
    ThreadQuerySetWin32StartAddress = 9,
    ThreadZeroTlsCell = 10,
    ThreadPerformanceCount = 11,
    ThreadAmILastThread = 12,
    ThreadIdealProcessor = 13,
    ThreadPriorityBoost = 14,
    ThreadSetTlsArrayAddress = 15,
    ThreadIsIoPending = 16,
    ThreadHideFromDebugger = 17,
    ThreadBreakOnTermination = 18,
    ThreadSwitchLegacyState = 19,
    ThreadIsTerminated = 20,
    ThreadLastSystemCall = 21,
    ThreadIoPriority = 22,
    ThreadCycleTime = 23,
    ThreadPagePriority = 24,
    ThreadActualBasePriority = 25,
    ThreadTebInformation = 26,
    ThreadCSwitchMon = 27,
    ThreadCSwitchPmu = 28,
    ThreadWow64Context = 29,
    ThreadGroupInformation = 30,
    ThreadUmsInformation = 31,
    ThreadCounterProfiling = 32,
    ThreadIdealProcessorEx = 33,
    ThreadCpuAccountingInformation = 34,
    ThreadSuspendCount = 35,
    ThreadHeterogeneousCpuPolicy = 36,
    ThreadContainerId = 37,
    ThreadNameInformation = 38,
    ThreadSelectedCpuSets = 39,
    ThreadSystemThreadInformation = 40,
    ThreadActualGroupAffinity = 41,
    ThreadDynamicCodePolicyInfo = 42,
    ThreadExplicitCaseSensitivity = 43,
    ThreadWorkOnBehalfTicket = 44,
    ThreadSubsystemInformation = 45,
    ThreadDbgkWerReportActive = 46,
    ThreadAttachContainer = 47,
    ThreadManageWritesToExecutableMemory = 48,
    ThreadPowerThrottlingState = 49,
    ThreadWorkloadClass = 50,
    MaxThreadInfoClass
} THREADINFOCLASS;

//Virtueller Speicher

/**
 * The NtAllocateVirtualMemory routine reserves, commits, or both, a region of pages within the user-mode virtual address space of a specified process.
 *
 * \param ProcessHandle Ein Handle für den Prozess wo das Mapping stattfinden soll.
 * \param BaseAddress A pointer to a variable that will receive the base address of the allocated region of pages. If the initial value is not zero, the region is allocated at the specified virtual address.
 * \param ZeroBits The number of high-order address bits that must be zero in the base address of the section view. This value must be less than 21 and the initial value of BaseAddress must be zero.
 * \param RegionSize A pointer to a variable that will receive the actual size, in bytes, of the allocated region of pages.
 * \param AllocationType A bitmask containing flags that specify the type of allocation to be performed.
 * \param PageProtection A bitmask containing page protection flags that specify the protection desired for the committed region of pages.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwallocatevirtualmemory
 */
typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
    );

typedef NTSTATUS (NTAPI *pNtFreeVirtualMemory)(
    HANDLE,
    PVOID*,
    PSIZE_T,
    ULONG
    );

typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE,
    PVOID*,
    PSIZE_T,
    ULONG,
    PULONG
    );

typedef NTSTATUS (NTAPI *pNtReadVirtualMemory)(
    HANDLE,
    PVOID,
    PVOID,
    ULONG,
    PULONG
    );

typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE,
    PVOID,
    PVOID,
    ULONG,
    PULONG
    );

typedef NTSTATUS (NTAPI *pNtQueryVirtualMemory)(
    HANDLE,
    PVOID,
    ULONG,
    PVOID,
    SIZE_T,
    PSIZE_T
    );

typedef NTSTATUS (NTAPI *pNtLockVirtualMemory)(
    HANDLE,
    PVOID*,
    PSIZE_T,
    ULONG
    );

typedef NTSTATUS (NTAPI *pNtUnlockVirtualMemory)(
    HANDLE,
    PVOID*,
    PSIZE_T,
    ULONG
    );

typedef NTSTATUS (NTAPI *pNtFlushVirtualMemory)(
    HANDLE,
    PVOID*,
    PSIZE_T,
    PIO_STATUS_BLOCK
    );

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE,
    HANDLE,
    PVOID*,
    ULONG_PTR,
    SIZE_T,
    PLARGE_INTEGER,
    PSIZE_T,
    DWORD,
    ULONG,
    ULONG
    );

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
    HANDLE,
    PVOID
    );

typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PLARGE_INTEGER,
    ULONG,
    ULONG,
    HANDLE
    );

//Threads

typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE,
    ACCESS_MASK,
    PVOID,
    HANDLE,
    PVOID,
    PVOID,
    ULONG,
    SIZE_T,
    SIZE_T,
    SIZE_T,
    PVOID
    );

typedef NTSTATUS (NTAPI *pNtSuspendThread)(
    HANDLE,
    PULONG
    );

typedef NTSTATUS (NTAPI *pNtResumeThread)(
    HANDLE,
    PULONG
    );

typedef NTSTATUS (NTAPI *pNtTerminateThread)(
    HANDLE,
    NTSTATUS
    );

typedef NTSTATUS (NTAPI *pNtOpenThread)(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PCLIENT_ID
    );

typedef NTSTATUS (NTAPI *pNtQueryInformationThread)(
    HANDLE,
    ULONG,
    PVOID,
    ULONG,
    PULONG
    );

typedef NTSTATUS (NTAPI *pNtSetInformationThread)(
    HANDLE,
    ULONG,
    PVOID,
    ULONG
    );

typedef NTSTATUS (NTAPI *pNtGetContextThread)(
    HANDLE,
    PCONTEXT
    );

typedef NTSTATUS (NTAPI *pNtSetContextThread)(
    HANDLE,
    PCONTEXT
    );

typedef NTSTATUS (NTAPI *pNtQueueApcThread)(
    HANDLE,
    PVOID,
    PVOID,
    PVOID,
    PVOID
    );

//Prozesse

typedef NTSTATUS (NTAPI *pNtCreateProcess)(
    PHANDLE,
    ACCESS_MASK,
    PVOID,HANDLE,
    BOOLEAN,
    HANDLE,
    HANDLE,
    HANDLE
    );

typedef NTSTATUS (NTAPI *pNtOpenProcess)(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PCLIENT_ID
    );

typedef NTSTATUS (NTAPI *pNtTerminateProcess)(
    HANDLE,
    NTSTATUS
    );

typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE,
    ULONG,
    PVOID,
    ULONG,
    PULONG
    );

typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(
    HANDLE,
    ULONG,
    PVOID,
    ULONG
    );

typedef NTSTATUS (NTAPI *pNtResumeProcess)(
    HANDLE
    );

typedef NTSTATUS (NTAPI *pNtSuspendProcess)(
    HANDLE
    );

//

typedef NTSTATUS (NTAPI *pNtOpenProcessToken)(
    HANDLE,
    ACCESS_MASK,
    PHANDLE
    );

typedef NTSTATUS (NTAPI *pNtOpenThreadToken)(
    HANDLE,
    ACCESS_MASK,
    BOOLEAN,
    PHANDLE
    );

typedef NTSTATUS (NTAPI *pNtDuplicateToken)(
    HANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    BOOLEAN,
    TOKEN_TYPE,
    PHANDLE
    );

typedef NTSTATUS (NTAPI *pNtAdjustPrivilegesToken)(
    HANDLE,
    BOOLEAN,
    PTOKEN_PRIVILEGES,
    ULONG,
    PTOKEN_PRIVILEGES,
    PULONG
    );

typedef NTSTATUS (NTAPI *pNtQueryInformationToken)(
    HANDLE,
    ULONG,
    PVOID,
    ULONG,
    PULONG
    );

typedef NTSTATUS (NTAPI *pNtDuplicateObject)(
    HANDLE,
    HANDLE,
    PHANDLE,
    HANDLE,
    ACCESS_MASK,
    ULONG,
    ULONG
    );

typedef NTSTATUS (NTAPI *pNtClose)(
    HANDLE
    );

typedef NTSTATUS (NTAPI *pNtQueryObject)(
    HANDLE,
    ULONG,
    PVOID,
    ULONG,
    PULONG
    );

//

typedef NTSTATUS (NTAPI *pNtLoadDll)(
    PWSTR,
    PULONG,
    PUNICODE_STRING,
    PHANDLE
    );

typedef NTSTATUS (NTAPI *pNtUnloadDll)(
    HANDLE
    );

typedef NTSTATUS (NTAPI *pNtQuerySection)(
    HANDLE,
    ULONG,
    PVOID,
    SIZE_T,
    PSIZE_T
    );

//

typedef NTSTATUS (NTAPI *pNtCreateFile)(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK,
    PLARGE_INTEGER,
    ULONG,
    ULONG,
    ULONG,
    ULONG,
    PVOID,
    ULONG
    );

typedef NTSTATUS (NTAPI *pNtOpenFile)(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK,
    ULONG,
    ULONG
    );

typedef NTSTATUS (NTAPI *pNtReadFile)(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    PLARGE_INTEGER,
    PULONG
    );

typedef NTSTATUS (NTAPI *pNtWriteFile)(
    HANDLE,
    HANDLE,
    PIO_APC_ROUTINE,
    PVOID,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    PLARGE_INTEGER,
    PULONG
    );

typedef NTSTATUS (NTAPI *pNtDeleteFile)(
    POBJECT_ATTRIBUTES
    );

typedef NTSTATUS (NTAPI *pNtQueryInformationFile)(
    HANDLE,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    ULONG
    );

typedef NTSTATUS (NTAPI *pNtSetInformationFile)(
    HANDLE,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    ULONG
    );

typedef NTSTATUS (NTAPI *pNtQueryAttributesFile)(
    POBJECT_ATTRIBUTES,
    PFILE_BASIC_INFORMATION
    );

//

typedef NTSTATUS (NTAPI *pNtCreateKey)(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    ULONG,
    PUNICODE_STRING,
    ULONG,
    PULONG
    );

typedef NTSTATUS (NTAPI *pNtOpenKey)(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES
    );

typedef NTSTATUS (NTAPI *pNtDeleteKey)(
    HANDLE
    );

typedef NTSTATUS (NTAPI *pNtSetValueKey)(
    HANDLE,
    PUNICODE_STRING,
    ULONG,
    ULONG,
    PVOID,
    ULONG
    );

typedef NTSTATUS (NTAPI *pNtQueryValueKey)(
    HANDLE,
    PUNICODE_STRING,
    ULONG,
    PVOID,
    ULONG,
    PULONG
    );

//

typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(
    ULONG,
    PVOID,
    ULONG,
    PULONG
    );

typedef NTSTATUS (NTAPI *pNtSetSystemInformation)(
    ULONG,
    PVOID,
    ULONG
    );

typedef NTSTATUS (NTAPI *pNtDelayExecution)(
    BOOLEAN,
    PLARGE_INTEGER
    );

typedef NTSTATUS (NTAPI *pNtWaitForSingleObject)(
    HANDLE,
    BOOLEAN,
    PLARGE_INTEGER
    );

typedef NTSTATUS (NTAPI *pNtWaitForMultipleObjects)(
    ULONG,
    PHANDLE,
    BOOLEAN,
    BOOLEAN,
    PLARGE_INTEGER
    );

typedef NTSTATUS (NTAPI *pNtTestAlert)(
    VOID
    );

typedef NTSTATUS (NTAPI *pNtContinue)(
    PCONTEXT,
    BOOLEAN
    );

typedef NTSTATUS (NTAPI *pNtRaiseHardError)(
    NTSTATUS,
    ULONG,
    ULONG,
    PULONG_PTR,
    PULONG,
    PULONG
    );

//

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

//

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

//

extern pNtCreateProcess NtCreateProcess;
extern pNtOpenProcess NtOpenProcess;
extern pNtTerminateProcess NtTerminateProcess;
extern pNtQueryInformationProcess NtQueryInformationProcess;
extern pNtSetInformationProcess NtSetInformationProcess;
extern pNtResumeProcess NtResumeProcess;
extern pNtSuspendProcess NtSuspendProcess;

//

extern pNtOpenProcessToken NtOpenProcessToken;
extern pNtOpenThreadToken NtOpenThreadToken;
extern pNtDuplicateToken NtDuplicateToken;
extern pNtAdjustPrivilegesToken NtAdjustPrivilegesToken;
extern pNtQueryInformationToken NtQueryInformationToken;
extern pNtDuplicateObject NtDuplicateObject;
extern pNtClose NtClose;
extern pNtQueryObject NtQueryObject;

//

extern pNtLoadDll NtLoadDll;
extern pNtUnloadDll NtUnloadDll;
extern pNtQuerySection NtQuerySection;

//

extern pNtCreateFile NtCreateFile;
extern pNtOpenFile NtOpenFile;
extern pNtReadFile NtReadFile;
extern pNtWriteFile NtWriteFile;
extern pNtDeleteFile NtDeleteFile;
extern pNtQueryInformationFile NtQueryInformationFile;
extern pNtSetInformationFile NtSetInformationFile;
extern pNtQueryAttributesFile NtQueryAttributesFile;

//

extern pNtCreateKey NtCreateKey;
extern pNtOpenKey NtOpenKey;
extern pNtDeleteKey NtDeleteKey;
extern pNtSetValueKey NtSetValueKey;
extern pNtQueryValueKey NtQueryValueKey;

//

extern pNtQuerySystemInformation NtQuerySystemInformation;
extern pNtSetSystemInformation NtSetSystemInformation;
extern pNtDelayExecution NtDelayExecution;
extern pNtWaitForSingleObject NtWaitForSingleObject;
extern pNtWaitForMultipleObjects NtWaitForMultipleObjects;
extern pNtTestAlert NtTestAlert;
extern pNtContinue NtContinue;
extern pNtRaiseHardError NtRaiseHardError;

BOOL ResolveNtFunctions();

#ifdef __cplusplus
}
#endif
