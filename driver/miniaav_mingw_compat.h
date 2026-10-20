/*++
miniaav_mingw_compat.h —— 用 TDM-GCC/mingw 构建 MiniAVProt.sys 时补齐
mingw-w64 DDK 头相对微软 WDK 的缺口。仅 MinGW 构建使用（gcc -include 注入），
WDK 构建路径（build.ps1）不受影响。
--*/
#ifndef MINIAAV_MINGW_COMPAT_H
#define MINIAAV_MINGW_COMPAT_H

#include <ddk/ntddk.h>
#include <ddk/wdmsec.h>

#ifndef RTL_CONSTANT_STRING
#define RTL_CONSTANT_STRING(s)                                         \
    { (USHORT)(sizeof(s) - sizeof((s)[0])), (USHORT)(sizeof(s)), (PWSTR)(s) }
#endif

/* mingw ddk 头不含 winnt.h 的进程权限常量（wdm.h 有部分，逐符号防重定义） */
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif
#ifndef PROCESS_SET_SESSIONID
#define PROCESS_SET_SESSIONID 0x0004
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE 0x0040
#endif
#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS 0x0080
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA 0x0100
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION 0x0200
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

/* mingw wdmsec.h 缺 SDDL 常量：等价字符串 D:P(A;;GA;;;SY)(A;;GA;;;BA)。
   定义为对象（值语义），与微软头一致——调用处写 &SDDL_... 取地址 */
#ifndef SDDL_DEVOBJ_SYS_ADMIN_ADM
static const UNICODE_STRING MINIAVP_SDDL_OBJ =
    RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
#define SDDL_DEVOBJ_SYS_ADMIN_ADM MINIAVP_SDDL_OBJ
#endif

/* mingw wdmsec.h 把 IoCreateDeviceSecure 转发为 WdmlibIoCreateDeviceSecure
   （wdmsec.lib 历史名）；内核真实导出名是 IoCreateDeviceSecure */
#undef IoCreateDeviceSecure
#ifdef __cplusplus
extern "C" {
#endif
NTKERNELAPI
NTSTATUS
NTAPI
IoCreateDeviceSecure(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ ULONG DeviceExtensionSize,
                     _In_opt_ PUNICODE_STRING DeviceName,
                     _In_ DEVICE_TYPE DeviceType,
                     _In_ ULONG DeviceCharacteristics,
                     _In_ BOOLEAN Exclusive,
                     _In_ PCUNICODE_STRING DefaultSDDLString,
                     _In_opt_ LPCGUID DeviceClassGuid,
                     _Out_ PDEVICE_OBJECT *DeviceObject);
#ifdef __cplusplus
}
#endif

/* mingw wdm.h 未声明（ntoskrnl 有导出） */
#ifndef PsGetProcessImageFileName
NTKERNELAPI
PUCHAR
NTAPI
PsGetProcessImageFileName(_In_ PEPROCESS Process);
#endif

#endif /* MINIAAV_MINGW_COMPAT_H */
