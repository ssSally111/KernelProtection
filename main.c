#include "h.h"

OB_PREOP_CALLBACK_STATUS Callback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	PUCHAR curProcessName = PsGetProcessImageFileName((PEPROCESS)OperationInformation->Object);
	if (strcmp((PCHAR)RegistrationContext, curProcessName) == 0)
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
	* *(_DWORD *)(ldrData + 104) 其实就是 pDriverObject->DriverSection->Flags
	* 所以这里直接 Flags|=0x20
	*/
	((PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection)->Flags |= 0x20;


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

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	// 方法1:通过官方提供注册回调 ObRegisterCallbacks 实现
	// Protection1("notepad.exe", pDriverObject);

	// 方法2:通过hook KiFastSystemCall
	Protection2("notepad.exe");

	return STATUS_SUCCESS;
}

