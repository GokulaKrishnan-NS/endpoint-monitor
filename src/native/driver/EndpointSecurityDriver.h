/**
 * EndpointSecurityDriver.h
 * Windows Native Kernel Minifilter / Process & Network Enforcement Driver Header
 * (Phase 2 Native Windows Architecture)
 */

#ifndef ENDPOINT_SECURITY_DRIVER_H
#define ENDPOINT_SECURITY_DRIVER_H

#include <ntddk.h>
#include <wdf.h>
#include <fwpmk.h>
#include <fwpsk.h>

#define DEVICE_NAME         L"\\Device\\EndpointSecurityDriver"
#define SYMBOLIC_LINK_NAME  L"\\DosDevices\\EndpointSecurityDriver"

#define ENDPOINT_SECURITY_DEVICE_TYPE 0x8000

// Control codes for User-Mode Privileged Service <-> Driver IPC
#define IOCTL_ENDPOINT_SECURITY_HEARTBEAT \
    CTL_CODE(ENDPOINT_SECURITY_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ENDPOINT_SECURITY_GET_STATUS \
    CTL_CODE(ENDPOINT_SECURITY_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ENDPOINT_SECURITY_UPDATE_POLICY \
    CTL_CODE(ENDPOINT_SECURITY_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ENDPOINT_SECURITY_PENDING_EVENT \
    CTL_CODE(ENDPOINT_SECURITY_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ENDPOINT_SECURITY_SUBMIT_DECISION \
    CTL_CODE(ENDPOINT_SECURITY_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)

typedef struct _DRIVER_STATUS_PAYLOAD {
    ULONG DriverVersion;
    BOOLEAN ProcessEnforcementActive;
    BOOLEAN WfpEnforcementActive;
    ULONG TotalProcessesEvaluated;
    ULONG TotalProcessesBlocked;
    ULONG TotalConnectionsEvaluated;
    ULONG TotalConnectionsBlocked;
    ULONG ServiceConnected;
} DRIVER_STATUS_PAYLOAD, *PDRIVER_STATUS_PAYLOAD;

typedef struct _PROCESS_EVAL_REQUEST {
    ULONG RequestId;
    ULONG ProcessId;
    ULONG ParentProcessId;
    WCHAR ImageFileName[260];
    WCHAR CommandLine[512];
} PROCESS_EVAL_REQUEST, *PPROCESS_EVAL_REQUEST;

typedef struct _DECISION_RESPONSE {
    ULONG RequestId;
    ULONG Decision;       // 0 = ALLOW, 1 = REQUIRE_APPROVAL (Deny & Retry), 2 = BLOCK
    ULONG ExpirySeconds;
} DECISION_RESPONSE, *PDECISION_RESPONSE;

#pragma pack(pop)

// Driver lifecycle functions
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
);

// Process Notify Routine (PsSetCreateProcessNotifyRoutineEx)
VOID ProcessNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

// WFP Callout Functions
NTSTATUS RegisterWfpCallouts(_In_ PDEVICE_OBJECT DeviceObject);
VOID UnregisterWfpCallouts(VOID);

#endif // ENDPOINT_SECURITY_DRIVER_H
