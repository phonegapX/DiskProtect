#include "std.h"
#include "ProtectObjectInfo.h"
#include "HookDisk.h"

PROTECT_OBJECT_INFO ProtectObjectInfoC;
PROTECT_OBJECT_INFO ProtectObjectInfoE;
CHAR ProtectPassword[32];

BOOLEAN SWTestOffsetIsHit(PDEVICE_OBJECT DeviceObject, PIRP Irp, PPROTECT_OBJECT_INFO ProtectObjectInfo)
{
#define dwBufSize 0x218
	ULONG uIndex;
	NTSTATUS status;
	ULONG uReturnLength;
	PVOID SystemBuffer;
	BYTE Buffer[sizeof(OBJECT_NAME_INFORMATION) + dwBufSize*sizeof(WCHAR)];
	POBJECT_NAME_INFORMATION ObjectName = (POBJECT_NAME_INFORMATION)Buffer;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	LARGE_INTEGER uStartOffset = irpSp->Parameters.Write.ByteOffset;
	LARGE_INTEGER uEndOffset = (uEndOffset.QuadPart = uStartOffset.QuadPart + irpSp->Parameters.Write.Length, uEndOffset);

	status = ObQueryNameString(DeviceObject, ObjectName, dwBufSize, &uReturnLength);
	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}
	uReturnLength = wcslen(ProtectObjectInfo->DiskDeviceName) * sizeof(WCHAR);
	if (RtlCompareMemory(ObjectName->Name.Buffer, ProtectObjectInfo->DiskDeviceName, uReturnLength) != uReturnLength)
	{
		return FALSE;
	}
	if (
		ProtectObjectInfo->IsProtect &&
		uEndOffset.QuadPart > ProtectObjectInfo->StartingOffset.QuadPart &&
		uStartOffset.QuadPart < ProtectObjectInfo->StartingOffset.QuadPart + ProtectObjectInfo->PartitionLength.QuadPart
		)
	{
		return TRUE; //保护本分区
	}
	if (
		ProtectObjectInfo->DiskIndex == 0 && 
		uStartOffset.QuadPart == dwConfigDataSectorOffset && 
		irpSp->Parameters.Write.Length >= dwBytesPerSectore
		)
	{
		PROTECT_CONFIG_DATA ConfigData;
		SystemBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
		if (SystemBuffer == NULL)
		{
			return FALSE;
		}
		memcpy(&ConfigData, SystemBuffer, sizeof(ConfigData));
		ENCRYPT_DECODE_DATA(&ConfigData);
		if (
			memcmp(ConfigData.Magic, MagicFlag, sizeof(ConfigData.Magic)) != 0 ||
			bDisableAccess
			)
		{
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}
	for (uIndex = 0; uIndex < ProtectObjectInfo->PartitionCountInThisDisk; uIndex++)
	{
		PPARTITION_INFORMATION PartEntry = &ProtectObjectInfo->PartitionEntry[uIndex];
		if (
			uEndOffset.QuadPart > PartEntry->StartingOffset.QuadPart &&
			uStartOffset.QuadPart < PartEntry->StartingOffset.QuadPart + 8 * dwBytesPerSectore
			)
		{
			return TRUE; //保护每个分区的引导扇区
		}
	}
	if (uStartOffset.QuadPart == 0)
	{
		return TRUE; //保护主引导纪录
	}
	return FALSE;
#undef dwBufSize
}

NTSTATUS SWReadConfigSector(PPROTECT_CONFIG_DATA ConfigData)
{
	NTSTATUS status;
	HANDLE hDiskDevice;
	LARGE_INTEGER ByteOffset;
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
	status = ZwReadFile(
		hDiskDevice, 
		NULL, 
		NULL, 
		NULL, 
		&IoStatusBlock, 
		ConfigData, 
		dwBytesPerSectore, 
		(ByteOffset.QuadPart=dwConfigDataSectorOffset, &ByteOffset), 
		NULL);
	ZwClose(hDiskDevice);
	return status;
}

NTSTATUS SWReadConfigData()
{
	NTSTATUS status;
	PROTECT_CONFIG_DATA ConfigData;
	status = SWReadConfigSector(&ConfigData);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	ENCRYPT_DECODE_DATA(&ConfigData);
	if (memcmp(ConfigData.Magic, MagicFlag, sizeof(ConfigData.Magic)) != 0)
	{
		return STATUS_ACCESS_VIOLATION;
	}
	if (ConfigData.IsProtectC != 0)
	{
		ProtectObjectInfoC.ProtectState   = TRUE;
		ProtectObjectInfoC.IsProtect = TRUE;
	}
	else
	{
		ProtectObjectInfoC.ProtectState   = FALSE;
		ProtectObjectInfoC.IsProtect = FALSE;
	}
	if (ConfigData.IsProtectE != 0)
	{
		ProtectObjectInfoE.ProtectState   = TRUE;
		ProtectObjectInfoE.IsProtect = TRUE;
	}
	else
	{
		ProtectObjectInfoE.ProtectState   = FALSE;
		ProtectObjectInfoE.IsProtect = FALSE;
	}
	memcpy(ProtectPassword, ConfigData.Password, sizeof(ProtectPassword));
	return status;
}

NTSTATUS SWWriteConfigSector(PPROTECT_CONFIG_DATA ConfigData)
{
	PIRP Irp;
	NTSTATUS status;
	HANDLE hDiskDevice;
	KEVENT obWaitEvent;
	PFILE_OBJECT FileObject;
	LARGE_INTEGER ByteOffset;
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
	ZwClose(hDiskDevice);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	KeInitializeEvent(&obWaitEvent, SynchronizationEvent, FALSE);
	Irp = IoBuildSynchronousFsdRequest(IRP_MJ_WRITE, FileObject->DeviceObject, ConfigData, dwBytesPerSectore, (ByteOffset.QuadPart=dwConfigDataSectorOffset, &ByteOffset), &obWaitEvent, &IoStatusBlock);
	if (Irp == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	status = SWCallOldDiskWrite(ProtectObjectInfoC.FileObject->DeviceObject, Irp);
	if (status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&obWaitEvent, Executive, KernelMode, FALSE, NULL);
		status = STATUS_SUCCESS;
	}
	return status;
}

NTSTATUS SWWriteConfigData()
{
	NTSTATUS status;
	PROTECT_CONFIG_DATA ConfigData = {0};
	status = SWReadConfigSector(&ConfigData);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	ENCRYPT_DECODE_DATA(&ConfigData);
	if (memcmp(ConfigData.Magic, MagicFlag, sizeof(ConfigData.Magic)) != 0)
	{
		return STATUS_ACCESS_VIOLATION;
	}
	ConfigData.IsProtectC = ProtectObjectInfoC.ProtectState;
	ConfigData.IsProtectE = ProtectObjectInfoE.ProtectState;
	memcpy(ConfigData.Password, ProtectPassword, sizeof(ConfigData.Password));
	ENCRYPT_DECODE_DATA(&ConfigData);
	return SWWriteConfigSector(&ConfigData);
}

NTSTATUS SWQueryVolumeDeviceName(PPROTECT_OBJECT_INFO ProtectObjectInfo)
{
	WCHAR wBuffer[257];
	UNICODE_STRING unSymbolicLink;
	UNICODE_STRING unDeviceName;
	STRING AnsiString;
	OBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE hLinkHandle;
	NTSTATUS status;
	swprintf(wBuffer, L"\\DosDevices\\Global\\%C:", ProtectObjectInfo->DriveLetter);
	RtlInitUnicodeString(&unSymbolicLink, wBuffer);
	InitializeObjectAttributes(&ObjectAttributes, &unSymbolicLink, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenSymbolicLinkObject(&hLinkHandle, SYMBOLIC_LINK_QUERY, &ObjectAttributes);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	unDeviceName.Buffer = ProtectObjectInfo->VolumeDeviceName;
	unDeviceName.MaximumLength = sizeof(ProtectObjectInfo->VolumeDeviceName);
	status = ZwQuerySymbolicLinkObject(hLinkHandle, &unDeviceName, NULL);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hLinkHandle);
		return status;
	}
	RtlUnicodeStringToAnsiString(&AnsiString, &unDeviceName, TRUE);
	ProtectObjectInfo->PartitionIndex = AnsiString.Buffer[AnsiString.Length-1] - '0';
	RtlFreeAnsiString(&AnsiString);
	ZwClose(hLinkHandle);
	return status;
}

void SWInitThisProtectInfo(PPROTECT_OBJECT_INFO ProtectObjectInfo)
{
	ULONG Number;
	NTSTATUS status; 
	HANDLE hDiskDevice;
	PFILE_OBJECT FileObject;
	IO_STATUS_BLOCK IoStatusBlock;
	UNICODE_STRING unDiskDeviceName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	PDRIVE_LAYOUT_INFORMATION DriverLayoutInfo;
	WCHAR wBuffer[257];
	ULONG CurPartitionCount = 0;

	for (Number = 0; Number < 4; Number++)
	{
		swprintf(wBuffer, L"\\Device\\Harddisk%d\\DR%d", Number, Number);
		RtlInitUnicodeString(&unDiskDeviceName, wBuffer);
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
			continue;
		}
		status = ObReferenceObjectByHandle(hDiskDevice, 0x80, NULL, KernelMode, &FileObject, NULL);
		if (!NT_SUCCESS(status))
		{
			ZwClose(hDiskDevice);
			continue;
		}
		status = IoReadPartitionTable(IoGetAttachedDevice(FileObject->DeviceObject), dwBytesPerSectore, TRUE, &DriverLayoutInfo);
		ZwClose(hDiskDevice);
		if (!NT_SUCCESS(status))
		{
			continue;
		}
		if (
			ProtectObjectInfo->PartitionIndex >= CurPartitionCount &&
			ProtectObjectInfo->PartitionIndex <= CurPartitionCount+DriverLayoutInfo->PartitionCount
			)
		{
			ULONG uIndex = ProtectObjectInfo->PartitionIndex - CurPartitionCount - 1;
			PPARTITION_INFORMATION PartInfo = &DriverLayoutInfo->PartitionEntry[uIndex];
			ProtectObjectInfo->DiskIndex = Number;
			memcpy(ProtectObjectInfo->DiskDeviceName, wBuffer, sizeof(wBuffer));
			ProtectObjectInfo->StartingOffset = PartInfo->StartingOffset;
			ProtectObjectInfo->PartitionLength = PartInfo->PartitionLength;
			ProtectObjectInfo->FileObject = FileObject;
			ProtectObjectInfo->DriverLayoutInfo = DriverLayoutInfo;
			ProtectObjectInfo->PartitionCountInThisDisk = DriverLayoutInfo->PartitionCount <= 16 ? DriverLayoutInfo->PartitionCount : 16;
			for (Number = 0; Number < ProtectObjectInfo->PartitionCountInThisDisk; Number++)
			{
				ProtectObjectInfo->PartitionEntry[Number] = DriverLayoutInfo->PartitionEntry[Number];
			}
			break;
		}
		CurPartitionCount += DriverLayoutInfo->PartitionCount;
	}
}

NTSTATUS SWInitProtectInfo()
{
	NTSTATUS status;
	ProtectObjectInfoC.DiskIndex        = 0xFFFFFFFF;
	ProtectObjectInfoC.PartitionIndex   = 0xFFFFFFFF;
	ProtectObjectInfoC.DriverLayoutInfo = NULL;
	ProtectObjectInfoC.DriveLetter      = 'C';
	status = SWQueryVolumeDeviceName(&ProtectObjectInfoC);
	if (NT_SUCCESS(status))
	{
		SWInitThisProtectInfo(&ProtectObjectInfoC);
	}
	ProtectObjectInfoE.DiskIndex        = 0xFFFFFFFF;
	ProtectObjectInfoE.PartitionIndex   = 0xFFFFFFFF;
	ProtectObjectInfoE.DriverLayoutInfo = NULL;
	ProtectObjectInfoE.DriveLetter      = 'E';
	status = SWQueryVolumeDeviceName(&ProtectObjectInfoE);
	if (NT_SUCCESS(status))
	{
		SWInitThisProtectInfo(&ProtectObjectInfoE);
	}
	return status;
}
