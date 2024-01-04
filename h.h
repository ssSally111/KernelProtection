#pragma once
#include <ntddk.h>

NTSYSAPI
UCHAR*
NTAPI
PsGetProcessImageFileName(
	IN  PEPROCESS process
);

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
	IN  HANDLE    ProcessId,
	OUT PEPROCESS* Process
);

extern VOID DisableWrite();
extern VOID EnableWrite();