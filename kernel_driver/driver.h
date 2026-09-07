#ifndef _MOMO_TRAINER_DRIVER_H_
#define _MOMO_TRAINER_DRIVER_H_

#include <ntifs.h>
#include <wdm.h>

// ============================================================
//  MomoTrainerStudio Kernel Driver v1.0
//  Minimal WDM driver providing ring0 memory access
//  via IOCTL interface for hybrid user/kernel scanning.
//
//  Made by Momo aka Steav Beoung Salang
// ============================================================

#define DRIVER_TAG 'OMOM'  // 'MOMO' reversed for pool tagging

// Device type — use FILE_DEVICE_UNKNOWN to avoid conflicts
#define MOMO_DEVICE_TYPE 0x00000022  // FILE_DEVICE_UNKNOWN

// ============================================================
//  IOCTL Definitions
// ============================================================
// Method: METHOD_BUFFERED (simplest, safest for variable data)
// Required: FILE_ANY_ACCESS

#define IOCTL_MOMO_READ_MEMORY \
    CTL_CODE(MOMO_DEVICE_TYPE, 0x01, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MOMO_WRITE_MEMORY \
    CTL_CODE(MOMO_DEVICE_TYPE, 0x02, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MOMO_QUERY_MEMORY \
    CTL_CODE(MOMO_DEVICE_TYPE, 0x03, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MOMO_OPEN_PROCESS \
    CTL_CODE(MOMO_DEVICE_TYPE, 0x04, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MOMO_CLOSE_PROCESS \
    CTL_CODE(MOMO_DEVICE_TYPE, 0x05, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MOMO_GET_VERSION \
    CTL_CODE(MOMO_DEVICE_TYPE, 0x06, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MOMO_DISABLE_PROTECTION \
    CTL_CODE(MOMO_DEVICE_TYPE, 0x07, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================
//  Data Structures (must match Python ctypes layouts)
// ============================================================

#pragma pack(push, 1)

// Read/Write memory request
typedef struct _MEMORY_REQUEST {
    HANDLE ProcessId;       // Target process ID
    PVOID  Address;         // Target memory address
    ULONG  Size;            // Number of bytes to read/write
    UCHAR  Data[1];         // Variable-length data buffer (for METHOD_BUFFERED)
} MEMORY_REQUEST, *PMEMORY_REQUEST;

// Query memory request
typedef struct _QUERY_MEMORY_REQUEST {
    HANDLE ProcessId;       // Target process ID
    PVOID  Address;         // Starting address to query
    ULONG  Size;            // Size of MEMORY_BASIC_INFORMATION to return
} QUERY_MEMORY_REQUEST, *PQUERY_MEMORY_REQUEST;

// Open process request (simplified — just needs PID)
typedef struct _OPEN_PROCESS_REQUEST {
    HANDLE ProcessId;
    HANDLE ProcessHandle;   // Returned handle (kernel-mode handle, opaque)
} OPEN_PROCESS_REQUEST, *POPEN_PROCESS_REQUEST;

// Version info
typedef struct _DRIVER_VERSION {
    ULONG Major;
    ULONG Minor;
    ULONG Build;
    UCHAR Reserved[256];
} DRIVER_VERSION, *PDRIVER_VERSION;

#pragma pack(pop)

// ============================================================
//  Function Prototypes
// ============================================================

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
    );

NTSTATUS DispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    );

NTSTATUS DispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    );

#endif // _MOMO_TRAINER_DRIVER_H_
