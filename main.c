#include "h.h"

OB_PREOP_CALLBACK_STATUS Callback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	PUCHAR curProcessName = PsGetProcessImageFileName((PEPROCESS)OperationInformation->Object);
	if (!strcmp((PCHAR)RegistrationContext, curProcessName))
	{
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
			// 进程的句柄的访问权限
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			// 线程的句柄的访问权限
			OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
	}
	return OB_PREOP_SUCCESS;
}

VOID Protection1(PCHAR procName, PDRIVER_OBJECT pDriverObject)
{
	/*
	* 环境win10
	* ObRegisterCallbacks 内部有 MmVerifyCallbackFunctionCheckFlags 进行校验通过才可以注册成功
	* E8 A5 52 BE FF 85 C0 0F 84 BF 72 09 00
	*
	* MmVerifyCallbackFunctionCheckFlags:
	* ...
	* ldrData = MiLookupDataTableEntry(PINT64, 0);
	* v2 = 32
	* 函数内部通过 if ( ldrData && (!v2 || *(_DWORD *)(ldrData + 104) & v2) ) 进行校验
	* 所以这里直接 ldrData|=0x20
	*/
	*(PLONG)((PUCHAR)pDriverObject->DriverSection + 104) |= 0x20;

	OB_OPERATION_REGISTRATION or ;
	or .ObjectType = PsProcessType;
	or .Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	or .PreOperation = (POB_PRE_OPERATION_CALLBACK)&Callback;
	or .PostOperation = NULL;

	OB_CALLBACK_REGISTRATION callbackRegistration = { 0 };
	callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	callbackRegistration.OperationRegistrationCount = 1;
	UNICODE_STRING  altitude = RTL_CONSTANT_STRING(L"20202");
	callbackRegistration.Altitude = altitude;
	callbackRegistration.RegistrationContext = procName;
	callbackRegistration.OperationRegistration = &or ;

	PVOID h;
	ObRegisterCallbacks(&callbackRegistration, &h);
	// DriverUnload 时调用 ObUnRegisterCallbacks 取消回调
}





PCHAR g_proc;
PVOID g_p1;
UCHAR g_oBytes[12] = { 0 };
UCHAR g_nBytes[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };

typedef NTSTATUS(*_Proc)(
	OUT			PHANDLE            ProcessHandle,
	IN			ACCESS_MASK        DesiredAccess,
	IN			POBJECT_ATTRIBUTES ObjectAttributes,
	IN OPTIONAL PCLIENT_ID         ClientId);

NTSTATUS Proc(
	OUT			PHANDLE            ProcessHandle,
	IN			ACCESS_MASK        DesiredAccess,
	IN			POBJECT_ATTRIBUTES ObjectAttributes,
	IN OPTIONAL PCLIENT_ID         ClientId)
{
	PEPROCESS Process;
	if (NT_SUCCESS(PsLookupProcessByProcessId(ClientId->UniqueProcess, &Process)))
	{
		if (!strcmp(g_proc, PsGetProcessImageFileName(Process)))
			return STATUS_INVALID_CID;
		ObfDereferenceObject(Process);
	}

	EnableWrite();
	memcpy(g_p1, g_oBytes, 12);
	DisableWrite();
	NTSTATUS status = ((_Proc)g_p1)(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	EnableWrite();
	memcpy(g_p1, g_nBytes, 12);
	DisableWrite();
	return status;
}

UINT64 GetSSDTAddr()
{
	// fffff800`393fc079 e9426c0100      jmp     nt!KiServiceInternal(fffff800`39412cc0)
	UINT64 KiServiceInternal = 0;
	for (UINT64 i = (UINT64)ZwOpenProcess; i < (UINT64)ZwOpenProcess + 0x1E; i++)
	{
		if (MmIsAddressValid((PVOID)i))
		{
			if (*(PUCHAR)i == 0xE9)
			{
				for (UCHAR j = 1; j < 5; j++)
				{
					if (!MmIsAddressValid((PVOID)(i + j)))
					{
						KdPrint(("fail 0x02"));
						return 0;
					}
				}
				KiServiceInternal = i + *(PULONG)(i + 1) + 5;
			}
		}
	}
	if (!KiServiceInternal)
	{
		KdPrint(("fail 0x03"));
		return 0;
	}

	// fffff800`39412d1a 4c8d1d7f030000  lea     r11,[nt!KiSystemServiceStart (fffff800`394130a0)]
	UINT64 KiSystemServiceStart = 0;
	for (UINT64 i = KiServiceInternal; i < KiServiceInternal + 0x67; i++)
	{
		if (MmIsAddressValid((PVOID)i))
		{
			if (MmIsAddressValid((PVOID)(i + 1))
				&& MmIsAddressValid((PVOID)(i + 2))
				&& *(PUSHORT)i == 0x8D4C
				&& *(PUCHAR)(i + 2) == 0x1D)
			{
				for (UCHAR j = 3; j < 7; j++)
				{
					if (!MmIsAddressValid((PVOID)(i + j)))
					{
						KdPrint(("fail 0x05"));
						return 0;
					}
				}
				KiSystemServiceStart = i + *(PULONG)(i + 3) + 7;
			}
		}
	}
	if (!KiSystemServiceStart)
	{
		KdPrint(("fail 0x06"));
		return 0;
	}

	// fffff800`394130b4 4c8d1505089f00  lea     r10,[nt!KeServiceDescriptorTable (fffff800`39e038c0)]
	// fffff800`394130bb 4c8d1d7eb98e00  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff800`39cfea40)]
	UINT64 KeServiceDescriptorTable = 0;
	for (UINT64 i = KiSystemServiceStart; i < KiSystemServiceStart + 0x34; i++)
	{
		if (MmIsAddressValid((PVOID)i))
		{
			if (MmIsAddressValid((PVOID)(i + 1))
				&& MmIsAddressValid((PVOID)(i + 2))
				&& *(PUSHORT)i == 0x8D4C
				&& *(PUCHAR)(i + 2) == 0x15)
			{
				for (UCHAR j = 3; j < 7; j++)
				{
					if (!MmIsAddressValid((PVOID)(i + j)))
					{
						KdPrint(("fail 0x05"));
						return 0;
					}
				}
				KeServiceDescriptorTable = i + *(PULONG)(i + 3) + 7;
			}
		}
	}
	if (!KeServiceDescriptorTable)
	{
		KdPrint(("fail 0x06"));
		return 0;
	}

	return *(PUINT64)KeServiceDescriptorTable;
}

VOID Protection2(PCHAR procName)
{
	g_proc = procName;
	*(PUINT64)(g_nBytes + 2) = (UINT64)Proc;
	UINT64 base = GetSSDTAddr();
	g_p1 = (PVOID)(base + (*(PULONG)(base + 0x26 * 4) >> 4));
	memcpy(g_oBytes, g_p1, 12);
	EnableWrite();
	memcpy(g_p1, g_nBytes, 12);
	DisableWrite();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	// 方法1:通过官方提供注册回调 ObRegisterCallbacks 实现
	//Protection1("notepad.exe", pDriverObject);

	// 方法2:通过 hook nt!NtOpenProcess 实现
	Protection2("notepad.exe");

	return STATUS_SUCCESS;
}

