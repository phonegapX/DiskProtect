#include "std.h"
#include "HookDisk.h"
#include "ProtectObjectInfo.h"

BOOLEAN bDisableAccess;
ULONG uSessionID;
ULONG CallIndexTable[IRP_MJ_MAXIMUM_FUNCTION + 1];
PDRIVER_DISPATCH OldMajorRouterTable[IRP_MJ_MAXIMUM_FUNCTION + 1];
PDRIVER_DISPATCH g_fpOldDiskWrite;
PDRIVER_DISPATCH g_fpOldDiskControl;
PDRIVER_DISPATCH g_fpOldDiskInternalControl;

NTSTATUS SWNewDefaultHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	return OldMajorRouterTable[CallIndexTable[irpSp->MajorFunction]](DeviceObject, Irp);
}

NTSTATUS SWCallOldDiskWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION irpSp;
	IoSetNextIrpStackLocation(Irp);
	irpSp = IoGetCurrentIrpStackLocation(Irp);
	irpSp->DeviceObject = DeviceObject;
	return g_fpOldDiskWrite(DeviceObject, Irp);
}

VOID DisableWriteProtect(PULONG Dr0)
{
	ULONG uDr0;
	__asm
	{
		push eax
		mov eax, cr0
		mov uDr0, eax
		and eax, 0FFFEFFFFh
		mov cr0, eax
		pop eax
	}
	*Dr0 = uDr0;
}

VOID DisableIntermitAndSaveFlagRegister(PUSHORT FlagRegValue)
{
	USHORT uResult;
	__asm
	{
		pushf //pushfw
		cli
		pop ax
		mov uResult, ax
	}
	*FlagRegValue = uResult;
}

NTSTATUS SWNewDiskWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	if (
		!SWTestOffsetIsHit(DeviceObject, Irp, &ProtectObjectInfoC) && 
		!SWTestOffsetIsHit(DeviceObject, Irp, &ProtectObjectInfoE)
		)
	{
		return g_fpOldDiskWrite(DeviceObject, Irp);
	}
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = irpSp->Parameters.Write.Length;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS SWNewDiskControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	ULONG uControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
	switch(uControlCode)
	{
	case IOCTL_DISK_SET_DRIVE_LAYOUT:
	case IOCTL_DISK_SET_DRIVE_LAYOUT_EX:
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_MEDIA_WRITE_PROTECTED;

	case IOCTL_GET_SESSION_ID:
		if (
			irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(PARAM_GET_SESSION_ID) && 
			irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PARAM_GET_SESSION_ID)
			)
		{
			PPARAM_GET_SESSION_ID Param = (PPARAM_GET_SESSION_ID)Irp->AssociatedIrp.SystemBuffer;
			if (Param->Magic == PARAM_MAGIC_COOKIE)
			{
				Param->uSessionID = uSessionID;
				Irp->IoStatus.Information = sizeof(PARAM_GET_SESSION_ID);
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			else
			{
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}
		}
		else
		{
			Irp->IoStatus.Information = 0;
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		}
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return Irp->IoStatus.Status;

	case IOCTL_GET_PASSWORD:
		if (
			irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(PARAM_GET_PASSWORD) && 
			irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PARAM_GET_PASSWORD)
			)
		{
			PPARAM_GET_PASSWORD Param = (PPARAM_GET_PASSWORD)Irp->AssociatedIrp.SystemBuffer;
			if (Param->Magic == PARAM_MAGIC_COOKIE && Param->uSessionID == uSessionID)
			{
				memcpy(Param->Password, ProtectPassword, sizeof(Param->Password));
				Irp->IoStatus.Information = sizeof(PARAM_GET_PASSWORD);
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			else
			{
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}
		}
		else
		{
			Irp->IoStatus.Information = 0;
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		}
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return Irp->IoStatus.Status;

	case IOCTL_SET_PASSWORD:
		if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PARAM_SET_PASSWORD))
		{
			PPARAM_SET_PASSWORD Param = (PPARAM_SET_PASSWORD)Irp->AssociatedIrp.SystemBuffer;
			if (
				Param->Magic == PARAM_MAGIC_COOKIE && 
				Param->uSessionID == uSessionID    && 
				memcmp(Param->OrgPassword, ProtectPassword, sizeof(Param->OrgPassword)) == 0
				)
			{
				memcpy(ProtectPassword, Param->NewPassword, sizeof(ProtectPassword));
				SWWriteConfigData();
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			else
			{
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}
		}
		else
		{
			Irp->IoStatus.Information = 0;
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		}
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return Irp->IoStatus.Status;

	case IOCTL_GET_PROTECT_STATE:
		if (
			irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(PARAM_GET_PROTECT_STATE) && 
			irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PARAM_GET_PROTECT_STATE)
			)
		{
			PPARAM_GET_PROTECT_STATE Param = (PPARAM_GET_PROTECT_STATE)Irp->AssociatedIrp.SystemBuffer;
			if (
				Param->Magic == PARAM_MAGIC_COOKIE && 
				Param->uSessionID == uSessionID    && 
				memcmp(Param->Password, ProtectPassword, sizeof(Param->Password)) == 0
				)
			{
				Param->ProtectC = ProtectObjectInfoC.ProtectState;
				Param->ProtectE = ProtectObjectInfoE.ProtectState;
				Irp->IoStatus.Information = sizeof(PARAM_GET_PROTECT_STATE);
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			else
			{
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}
		}
		else
		{
			Irp->IoStatus.Information = 0;
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		}
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return Irp->IoStatus.Status;

	case IOCTL_SET_PROTECT_STATE:
		if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PARAM_SET_PROTECT_STATE))
		{
			PPARAM_SET_PROTECT_STATE Param = (PPARAM_SET_PROTECT_STATE)Irp->AssociatedIrp.SystemBuffer;
			if (
				Param->Magic == PARAM_MAGIC_COOKIE && 
				Param->uSessionID == uSessionID    && 
				memcmp(Param->Password, ProtectPassword, sizeof(Param->Password)) == 0
				)
			{
				ProtectObjectInfoC.ProtectState = Param->ProtectC;
				ProtectObjectInfoE.ProtectState = Param->ProtectE;
				SWWriteConfigData();
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			else
			{
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}
		}
		else
		{
			Irp->IoStatus.Information = 0;
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		}
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return Irp->IoStatus.Status;

	case IOCTL_ENABLE_THROUGH_WRITE:
		if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PARAM_ENABLE_TW))
		{
			PPARAM_ENABLE_TW Param = (PPARAM_ENABLE_TW)Irp->AssociatedIrp.SystemBuffer;
			if (
				Param->Magic == PARAM_MAGIC_COOKIE && 
				Param->uSessionID == uSessionID    && 
				memcmp(Param->Password, ProtectPassword, sizeof(Param->Password)) == 0
				)
			{
				bDisableAccess = FALSE;
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			else
			{
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}
		}
		else
		{
			Irp->IoStatus.Information = 0;
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		}
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return Irp->IoStatus.Status;

	case IOCTL_DISABLE_THROUGH_WRITE:
		if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PARAM_DISABLE_TW))
		{
			PPARAM_DISABLE_TW Param = (PPARAM_DISABLE_TW)Irp->AssociatedIrp.SystemBuffer;
			if (
				Param->Magic == PARAM_MAGIC_COOKIE && 
				Param->uSessionID == uSessionID    && 
				memcmp(Param->Password, ProtectPassword, sizeof(Param->Password)) == 0
				)
			{
				bDisableAccess = TRUE;
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			else
			{
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}
		}
		else
		{
			Irp->IoStatus.Information = 0;
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		}
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return Irp->IoStatus.Status;
	}
	return g_fpOldDiskControl(DeviceObject, Irp);
}

NTSTATUS SWNewDiskInternalControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	PSCSI_REQUEST_BLOCK Srb = irpSp->Parameters.Scsi.Srb;
	if (Srb==NULL || Srb->Function!=SRB_FUNCTION_EXECUTE_SCSI || (Srb->SrbFlags&SRB_FLAGS_DATA_OUT) == 0)
	{
		return g_fpOldDiskInternalControl(DeviceObject, Irp);
	}
	do
	{
		if (Srb->CdbLength == 6    && Srb->Cdb[0] == 0x0A) { break; }
		if (Srb->CdbLength == 0x0A && Srb->Cdb[0] == 0x2A) { break; }
		if (Srb->CdbLength == 0x0C && Srb->Cdb[0] == 0x2A) { break; }
		if (Srb->Cdb[0] == 0x2E || Srb->Cdb[0] == 0x3B)    { break; }
		return g_fpOldDiskInternalControl(DeviceObject, Irp);
	}
	while(FALSE);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS SWHookDiskMajorRouter(ULONG uRandom)
{
	ULONG uIndex;
	NTSTATUS status;
	ULONG uDr0;
	USHORT wFlagRegValue;
	HANDLE hDiskDevice;
	PFILE_OBJECT FileObject;
	IO_STATUS_BLOCK IoStatusBlock;
	UNICODE_STRING unDiskDeviceName;
	OBJECT_ATTRIBUTES ObjectAttributes;

	RtlInitUnicodeString(&unDiskDeviceName, L"\\Device\\Harddisk0\\DR0");
	InitializeObjectAttributes(&ObjectAttributes, &unDiskDeviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwCreateFile(
		&hDiskDevice, 
		GENERIC_READ|SYNCHRONIZE, 
		&ObjectAttributes, 
		&IoStatusBlock, 
		NULL, 
		FILE_ATTRIBUTE_NORMAL, 
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, 
		FILE_OPEN, 
		FILE_NO_INTERMEDIATE_BUFFERING|FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE|FILE_RANDOM_ACCESS, 
		NULL, 
		0);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = ObReferenceObjectByHandle(hDiskDevice, 0x80, NULL, KernelMode, &FileObject, NULL);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hDiskDevice);
		return status;
	}

	for (uIndex = 0; uIndex <= IRP_MJ_MAXIMUM_FUNCTION; uIndex++)
	{
		CallIndexTable[uIndex] = (uRandom+uIndex) % (IRP_MJ_MAXIMUM_FUNCTION+1);
	}

	DisableIntermitAndSaveFlagRegister(&wFlagRegValue);

	DisableWriteProtect(&uDr0);

	for (uIndex = 0; uIndex <= IRP_MJ_MAXIMUM_FUNCTION; uIndex++)
	{
		OldMajorRouterTable[CallIndexTable[uIndex]] = FileObject->DeviceObject->DriverObject->MajorFunction[uIndex];
		FileObject->DeviceObject->DriverObject->MajorFunction[uIndex] = SWNewDefaultHandler;
	}

	g_fpOldDiskWrite = FileObject->DeviceObject->DriverObject->MajorFunction[IRP_MJ_WRITE];
	FileObject->DeviceObject->DriverObject->MajorFunction[IRP_MJ_WRITE] = SWNewDiskWrite;
	g_fpOldDiskControl = FileObject->DeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	FileObject->DeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SWNewDiskControl;
	g_fpOldDiskInternalControl = FileObject->DeviceObject->DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL];
	FileObject->DeviceObject->DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = SWNewDiskInternalControl;

	__asm
	{
		push eax
		mov eax, uDr0
		mov cr0, eax
		pop eax
		mov ax, wFlagRegValue
		push ax
		popf //popfw
	}

	ZwClose(hDiskDevice);
	return status;
}
