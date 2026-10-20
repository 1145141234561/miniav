/*++
MiniAVProt.sys —— MiniAV 进程自保护驱动（教学级 WDM 单文件实现）

功能（纯防御性自保护，不做隐藏/注入/持久化）：
  通过 ObRegisterCallbacks 拦截对受保护镜像名（默认 MiniAV.exe）进程的
  句柄打开与复制操作，剥离危险权限（终止/写内存/创建线程/挂起等），
  使用户态恶意软件无法杀死或篡改杀软进程。内核句柄与 System 除外。

控制设备：
  \\.\MiniAVProt（DACL 仅 SYSTEM/管理员可读写）
    IOCTL_SET_NAME  输入 CHAR[16]   受保护镜像名（仅限 [A-Za-z0-9._-]）
    IOCTL_ENABLE    输入 ULONG      1=启用 0=停用
    IOCTL_STATUS    输出 STATUS     {ULONG Enabled; ULONG Mask; CHAR Name[16];}

构建（需 WDK + MSVC，见 build.ps1）：
  cl /W4 /WX /O2 /kernel /GS ... MiniAVProt.c
  link /driver /subsystem:native /entry:DriverEntry MiniAVProt.sys

安装（测试签名模式，管理员）：
  1. bcdedit /set testsigning on            （重启生效）
  2. 关闭"内核隔离/内存完整性"（HVCI 会阻止测试签名驱动加载）
  3. signtool sign /fd sha256 /a MiniAVProt.sys（证书需入 受信任的根/发布者）
  4. sc create MiniAVProt type= kernel binPath= C:\path\MiniAVProt.sys
  5. sc start MiniAVProt
卸载：
  sc stop MiniAVProt && sc delete MiniAVProt
--*/

#include <ntddk.h>
#include <wdmsec.h>

#define PROTECT_NAME_LEN 16

static const GUID MINIAVP_DEVCLASS =
    {0x6f1c2a34, 0x5b7d, 0x4e28, {0x9a, 0xc1, 0xd2, 0xe3, 0xf4, 0x55, 0x66, 0x77}};

#define MINIAVP_DEVICE_NAME  L"\\Device\\MiniAVProt"
#define MINIAVP_SYMLINK_NAME L"\\DosDevices\\MiniAVProt"

#define IOCTL_MINIAVP_SET_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MINIAVP_ENABLE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MINIAVP_STATUS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _MINIAVP_STATUS {
    ULONG Enabled;      /* 1=保护开启 */
    ULONG Mask;         /* 被剥离的权限掩码 */
    CHAR  Name[16];     /* 受保护镜像名（ANSI） */
} MINIAVP_STATUS, *PMINIAVP_STATUS;

/* 对外剥离的危险权限；保留 查询/同步 等，任务管理器仍可查看基本属性 */
#define MINIAVP_STRIPPED_ACCESS ( \
    PROCESS_TERMINATE       | \
    PROCESS_CREATE_THREAD   | \
    PROCESS_SET_SESSIONID   | \
    PROCESS_VM_OPERATION    | \
    PROCESS_VM_READ         | \
    PROCESS_VM_WRITE        | \
    PROCESS_DUP_HANDLE      | \
    PROCESS_CREATE_PROCESS  | \
    PROCESS_SET_QUOTA       | \
    PROCESS_SET_INFORMATION | \
    PROCESS_SUSPEND_RESUME)

static PDEVICE_OBJECT g_Device = NULL;
static PVOID g_RegHandle = NULL;
static BOOLEAN g_Enabled = TRUE;
static CHAR g_ProtectedName[PROTECT_NAME_LEN] = "MiniAV.exe";

/* ImageFileName 是 15 字节（可能无 NUL 结尾），复制后强制补 NUL 再比较 */
static BOOLEAN NameMatches(const UCHAR *ImageFileName)
{
    CHAR buf[PROTECT_NAME_LEN];
    ULONG i;

    RtlCopyMemory(buf, ImageFileName, PROTECT_NAME_LEN - 1);
    buf[PROTECT_NAME_LEN - 1] = '\0';

    for (i = 0; i < PROTECT_NAME_LEN; i++) {
        CHAR a = buf[i], b = g_ProtectedName[i];
        if (a >= 'A' && a <= 'Z') a = (CHAR)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (CHAR)(b + ('a' - 'A'));
        if (a != b) return FALSE;
        if (a == '\0') return TRUE;
    }
    return TRUE;
}

static BOOLEAN CallerIsProtected(void)
{
    return NameMatches(PsGetProcessImageFileName(PsGetCurrentProcess()));
}

static OB_PREOP_CALLBACK_STATUS PreOpCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION Info)
{
    PEPROCESS caller, target;
    ACCESS_MASK mask;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!g_Enabled)
        return OB_PREOP_SUCCESS;
    if (Info->ObjectType != *PsProcessType)
        return OB_PREOP_SUCCESS;
    if (Info->KernelHandle)
        return OB_PREOP_SUCCESS;                 /* 内核句柄不受限 */

    caller = PsGetCurrentProcess();
    target = (PEPROCESS)Info->Object;
    if (caller == target || caller == PsInitialSystemProcess)
        return OB_PREOP_SUCCESS;                 /* 自己与 System 保留全权 */
    if (CallerIsProtected())
        return OB_PREOP_SUCCESS;                 /* 受保护进程间的管理操作放行 */
    if (!NameMatches(PsGetProcessImageFileName(target)))
        return OB_PREOP_SUCCESS;                 /* 目标不是受保护镜像 */

    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        mask = Info->Parameters->CreateHandleInformation.DesiredAccess;
        if (mask & MINIAVP_STRIPPED_ACCESS)
            Info->Parameters->CreateHandleInformation.DesiredAccess =
                mask & ~MINIAVP_STRIPPED_ACCESS;
    } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        mask = Info->Parameters->DuplicateHandleInformation.DesiredAccess;
        if (mask & MINIAVP_STRIPPED_ACCESS)
            Info->Parameters->DuplicateHandleInformation.DesiredAccess =
                mask & ~MINIAVP_STRIPPED_ACCESS;
    }
    return OB_PREOP_SUCCESS;
}

static NTSTATUS SetNameFromInput(PVOID Buf, ULONG Len)
{
    CHAR tmp[PROTECT_NAME_LEN];
    ULONG n = (Len < PROTECT_NAME_LEN) ? Len : (PROTECT_NAME_LEN - 1);
    ULONG i;

    if (n == 0)
        return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(tmp, Buf, n);
    tmp[n] = '\0';
    if (tmp[0] == '\0')
        return STATUS_INVALID_PARAMETER;

    for (i = 0; tmp[i] != '\0'; i++) {
        CHAR c = tmp[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return STATUS_INVALID_PARAMETER;     /* 仅允许纯文件名字符 */
    }
    RtlZeroMemory(g_ProtectedName, PROTECT_NAME_LEN);
    RtlCopyMemory(g_ProtectedName, tmp, PROTECT_NAME_LEN - 1);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchCreateClose(PDEVICE_OBJECT Dev, PIRP Irp)
{
    UNREFERENCED_PARAMETER(Dev);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT Dev, PIRP Irp)
{
    PIO_STACK_LOCATION st;
    PVOID sysBuf;
    NTSTATUS status;
    ULONG outLen = 0;

    UNREFERENCED_PARAMETER(Dev);
    st = IoGetCurrentIrpStackLocation(Irp);
    sysBuf = Irp->AssociatedIrp.SystemBuffer;

    switch (st->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_MINIAVP_SET_NAME:
        status = SetNameFromInput(
            sysBuf, st->Parameters.DeviceIoControl.InputBufferLength);
        break;

    case IOCTL_MINIAVP_ENABLE:
        if (st->Parameters.DeviceIoControl.InputBufferLength != sizeof(ULONG)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        g_Enabled = (*(PULONG)sysBuf != 0);
        status = STATUS_SUCCESS;
        break;

    case IOCTL_MINIAVP_STATUS:
        if (st->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(MINIAVP_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        } else {
            PMINIAVP_STATUS out = (PMINIAVP_STATUS)sysBuf;
            out->Enabled = g_Enabled ? 1 : 0;
            out->Mask = MINIAVP_STRIPPED_ACCESS;
            RtlCopyMemory(out->Name, g_ProtectedName, sizeof(out->Name));
            outLen = sizeof(MINIAVP_STATUS);
        }
        status = STATUS_SUCCESS;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = outLen;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlink = RTL_CONSTANT_STRING(MINIAVP_SYMLINK_NAME);

    if (g_RegHandle) {
        ObUnRegisterCallbacks(g_RegHandle);
        g_RegHandle = NULL;
    }
    IoDeleteSymbolicLink(&symlink);
    if (g_Device) {
        IoDeleteDevice(g_Device);
        g_Device = NULL;
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING devName = RTL_CONSTANT_STRING(MINIAVP_DEVICE_NAME);
    UNICODE_STRING symName = RTL_CONSTANT_STRING(MINIAVP_SYMLINK_NAME);
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"321000");
    static OB_OPERATION_REGISTRATION opReg[1];
    static OB_CALLBACK_REGISTRATION cbReg;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    /* DACL 仅 SYSTEM/管理员：用户态恶意软件无法改保护名或停用保护 */
    status = IoCreateDeviceSecure(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN, FALSE,
                                  &SDDL_DEVOBJ_SYS_ADMIN_ADM, &MINIAVP_DEVCLASS,
                                  &g_Device);
    if (!NT_SUCCESS(status))
        return status;

    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_Device);
        g_Device = NULL;
        return status;
    }

    opReg[0].ObjectType = PsProcessType;
    opReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[0].PreOperation = PreOpCallback;
    opReg[0].PostOperation = NULL;
    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    cbReg.Altitude = altitude;
    cbReg.RegistrationContext = NULL;
    cbReg.OperationRegistration = opReg;

    status = ObRegisterCallbacks(&cbReg, &g_RegHandle);
    if (!NT_SUCCESS(status)) {
        /* 常见 0xC0000022：未开测试签名模式 / 驱动签名不被接受 */
        IoDeleteSymbolicLink(&symName);
        IoDeleteDevice(g_Device);
        g_Device = NULL;
        return status;
    }
    return STATUS_SUCCESS;
}
