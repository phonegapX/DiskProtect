#include "std.h"
#include "ProtectObjectInfo.h"
#include "VolumeShadowImage.h"
#include "HookDisk.h"
///////////////////////////////////////////////////////////////////

typedef struct _FILETE_DEVICE_EXTSION //(sizeof=0x258)
{
	CHAR DriveLetter;
	BYTE ThroughWrite;
	LIST_ENTRY ListEntry;
	KSPIN_LOCK SpinLock;
	KEVENT ThreadWaitEvent;
	KEVENT CompleteEvent;
	PVOID ThreadObject;
	BYTE bQuitThread;
	KEVENT UnwantedEvent;
	ULONG PageFileCount;
	WCHAR SymbolicLinkName[257];
	PVOLUME_SHADOW_IMAGE VolumeShadowImage;
	PDEVICE_OBJECT AttachedDevice;
} FILETE_DEVICE_EXTSION, *PFILETE_DEVICE_EXTSION;

/////////////////////////////////////////////////////////////////////
typedef struct _FILE_BOTH_DIR_INFORMATION
{
	ULONG  NextEntryOffset;
	ULONG  FileIndex;
	LARGE_INTEGER  CreationTime;
	LARGE_INTEGER  LastAccessTime;
	LARGE_INTEGER  LastWriteTime;
	LARGE_INTEGER  ChangeTime;
	LARGE_INTEGER  EndOfFile;
	LARGE_INTEGER  AllocationSize;
	ULONG  FileAttributes;
	ULONG  FileNameLength;
	ULONG  EaSize;
	CCHAR  ShortNameLength;
	WCHAR  ShortName[12];
	WCHAR  FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

NTSTATUS 
ZwQueryDirectoryFile(
					 IN  HANDLE                  FileHandle,
					 IN  HANDLE                  Event       OPTIONAL,
					 IN  PIO_APC_ROUTINE         ApcRoutine  OPTIONAL,
					 IN  PVOID                   ApcContext  OPTIONAL,
					 OUT PIO_STATUS_BLOCK        IoStatusBlock,
					 OUT PVOID                   FileInformation,
					 IN  ULONG                   Length,
					 IN  FILE_INFORMATION_CLASS  FileInformationClass,
					 IN  BOOLEAN                 ReturnSingleEntry,
					 IN  PUNICODE_STRING         FileName    OPTIONAL,
					 IN  BOOLEAN                 RestartScan
					 );

/////////////////////////////////////////////////////////////////////
NTSTATUS SWCreateFile(PWCHAR FileName)
{
	UNICODE_STRING unFileName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS status;
	HANDLE hFile;
	RtlInitUnicodeString(&unFileName, FileName);
	InitializeObjectAttributes(&ObjectAttributes, &unFileName, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwCreateFile(
		&hFile, 
		GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE, 
		&ObjectAttributes, 
		&IoStatusBlock, 
		NULL, 
		FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN, 
		0, 
		FILE_OVERWRITE_IF, 
		FILE_NO_INTERMEDIATE_BUFFERING|FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE|FILE_RANDOM_ACCESS|FILE_DELETE_ON_CLOSE,
		NULL, 
		0);
	if (NT_SUCCESS(status))
	{
		ZwClose(hFile);
	}
	return status;
}

void SWCreateAllFile()
{
	SWCreateFile(L"\\??\\D:\\kdVoluDumpC00.sys");
	SWCreateFile(L"\\??\\D:\\kdVoluDumpE00.sys");
}

NTSTATUS SWRCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
	PFILETE_DEVICE_EXTSION DevExtsion = (PFILETE_DEVICE_EXTSION)DeviceObject->DeviceExtension;
	if (Irp->PendingReturned)
	{
		IoMarkIrpPending(Irp);
	}
	KeSetEvent(&DevExtsion->CompleteEvent, IO_NO_INCREMENT, FALSE);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

VOID SWWorkThread(PVOID StartContext)
{
	PIRP Irp;
	PVOID SystemBuffer;
	PIO_STACK_LOCATION irpSp;
    	PLIST_ENTRY RequestEntry;
	IO_STATUS_BLOCK IoStatusBlock;
	PFILETE_DEVICE_EXTSION DevExtsion = ((PDEVICE_OBJECT)StartContext)->DeviceExtension;

	KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);
	for (;;)
	{
		KeWaitForSingleObject(&DevExtsion->ThreadWaitEvent, Executive, KernelMode, FALSE, NULL);
		if (DevExtsion->bQuitThread)
		{
			PsTerminateSystemThread(STATUS_SUCCESS);
		}
		while (RequestEntry = ExInterlockedRemoveHeadList(&DevExtsion->ListEntry, &DevExtsion->SpinLock))
		{
			Irp = CONTAINING_RECORD(RequestEntry, IRP, Tail.Overlay.ListEntry);
			irpSp = IoGetCurrentIrpStackLocation(Irp);

			switch (irpSp->MajorFunction)
			{
			case IRP_MJ_READ:
				SystemBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
				if (SystemBuffer == NULL)
				{
					Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					Irp->IoStatus.Information = 0;
					break;
				}
				if (
					SWFullDataInImage(DevExtsion->VolumeShadowImage, SystemBuffer, irpSp->Parameters.Read.ByteOffset, irpSp->Parameters.Read.Length)
					)
				{
					Irp->IoStatus.Status = SWReadVolumeShadowImage(DevExtsion->VolumeShadowImage, SystemBuffer, irpSp->Parameters.Read.ByteOffset, irpSp->Parameters.Read.Length);
				}
				else
				{
					IoCopyCurrentIrpStackLocationToNext(Irp);
					IoSetCompletionRoutine(Irp, SWRCompletionRoutine, NULL, TRUE, TRUE, TRUE);
					IoCallDriver(DevExtsion->AttachedDevice, Irp);
					KeWaitForSingleObject(&DevExtsion->CompleteEvent, Executive, KernelMode, FALSE, NULL);
					Irp->IoStatus.Status = SWReadVolumeShadowImage(DevExtsion->VolumeShadowImage, SystemBuffer, irpSp->Parameters.Read.ByteOffset, irpSp->Parameters.Read.Length);
				}
				Irp->IoStatus.Information = (NT_SUCCESS(Irp->IoStatus.Status) ? irpSp->Parameters.Read.Length : 0);
				break;

			case IRP_MJ_WRITE:
				SystemBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
				if (SystemBuffer == NULL)
				{
					Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					Irp->IoStatus.Information = 0;
					break;
				}
				if (DevExtsion->ThroughWrite == 'H')
				{
					Irp->IoStatus.Status = SWWriteVolumeShadowImage(DevExtsion->VolumeShadowImage, SystemBuffer, irpSp->Parameters.Write.ByteOffset, irpSp->Parameters.Write.Length);
				}
				else if (DevExtsion->ThroughWrite == 'L')
				{
					PIRP IrpAlloc;
					PFILE_OBJECT FileObject;
					LARGE_INTEGER uWriteOffset;
					if (DevExtsion->DriveLetter == 'C')
					{
						uWriteOffset.QuadPart = ProtectObjectInfoC.StartingOffset.QuadPart + irpSp->Parameters.Write.ByteOffset.QuadPart;
						FileObject = ProtectObjectInfoC.FileObject;
					}
					else if (DevExtsion->DriveLetter == 'E')
					{
						uWriteOffset.QuadPart = ProtectObjectInfoE.StartingOffset.QuadPart + irpSp->Parameters.Write.ByteOffset.QuadPart;
						FileObject = ProtectObjectInfoE.FileObject;
					}
					else
					{
						Irp->IoStatus.Status = STATUS_DRIVER_INTERNAL_ERROR;
						Irp->IoStatus.Information = 0;
						break;
					}
					IrpAlloc = IoBuildSynchronousFsdRequest
						(
						irpSp->MajorFunction, 
						FileObject->DeviceObject, 
						SystemBuffer, 
						irpSp->Parameters.Write.Length, 
						&uWriteOffset, 
						&DevExtsion->CompleteEvent, 
						&IoStatusBlock
						);
					Irp->IoStatus.Status = SWCallOldDiskWrite(FileObject->DeviceObject, IrpAlloc);
					if (Irp->IoStatus.Status == STATUS_PENDING)
					{
						Irp->IoStatus.Status = KeWaitForSingleObject(&DevExtsion->CompleteEvent, Executive, KernelMode, FALSE, NULL);
					}
				}
				else
				{
					Irp->IoStatus.Status = STATUS_DRIVER_INTERNAL_ERROR;
				}
				Irp->IoStatus.Information = (NT_SUCCESS(Irp->IoStatus.Status) ? irpSp->Parameters.Write.Length : 0);
				break;

			default:
				Irp->IoStatus.Status = STATUS_DRIVER_INTERNAL_ERROR;
			}
			IoCompleteRequest(Irp, (NT_SUCCESS(Irp->IoStatus.Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT));
		}
	}
}

NTSTATUS SWInitializeDevice(PDRIVER_OBJECT DriverObject, CHAR DriveLetter, CHAR ThroughWrite, ULONG uRandom)
{
	NTSTATUS status;
	HANDLE hThread;
	UNICODE_STRING unTargetVolumeDeviceName;
	UNICODE_STRING unfilterDeviceName;
	UNICODE_STRING unSymbolicLinkName;
	PDEVICE_OBJECT filterDeviceObject;
	PFILETE_DEVICE_EXTSION DevExtsion;
	WCHAR wBuffer[257];

	if (DriveLetter == 'C')
	{
		RtlInitUnicodeString(&unTargetVolumeDeviceName, ProtectObjectInfoC.VolumeDeviceName);
	}
	else if (DriveLetter == 'E')
	{
		RtlInitUnicodeString(&unTargetVolumeDeviceName, ProtectObjectInfoE.VolumeDeviceName);
	}
	else
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (ThroughWrite == 'L')
	{
		swprintf(
			wBuffer, 
			L"\\Device\\{%08X-%04X-%04X-%04X-%012X}", 
			uRandom^0x2468ACE, (USHORT)uRandom^0x5678, (USHORT)uRandom^0x4321, (USHORT)uRandom^0xBCDE, uRandom^0x13579BDF);
	}
	else
	{
		 swprintf(wBuffer, L"\\Device\\{%08X-%04X-%04X-%04X-%012X}", uRandom^0x13579BDF);
	}

	RtlInitUnicodeString(&unfilterDeviceName, wBuffer);
	status = IoCreateDevice(DriverObject, sizeof(FILETE_DEVICE_EXTSION), 
		&unfilterDeviceName, FILE_DEVICE_DISK, FILE_DEVICE_SECURE_OPEN, FALSE, &filterDeviceObject);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	DevExtsion = (PFILETE_DEVICE_EXTSION)filterDeviceObject->DeviceExtension;
	DevExtsion->DriveLetter = DriveLetter;
	DevExtsion->ThroughWrite = ThroughWrite;
	DevExtsion->ThreadObject = NULL;
	DevExtsion->VolumeShadowImage = NULL;
	KeInitializeEvent(&DevExtsion->UnwantedEvent, NotificationEvent, TRUE);
	DevExtsion->AttachedDevice = NULL;
	DevExtsion->PageFileCount = 0;
	DevExtsion->bQuitThread = TRUE;

	status = IoAttachDevice(filterDeviceObject, &unTargetVolumeDeviceName, &DevExtsion->AttachedDevice);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(filterDeviceObject);
		return status;
	}
	filterDeviceObject->Flags |= DevExtsion->AttachedDevice->Flags&(DO_BUFFERED_IO|DO_DIRECT_IO);
	filterDeviceObject->Flags |= DevExtsion->AttachedDevice->Flags&DO_POWER_PAGABLE;
	filterDeviceObject->Characteristics |= DevExtsion->AttachedDevice->Characteristics&FILE_CHARACTERISTICS_PROPAGATED;

	swprintf(DevExtsion->SymbolicLinkName, L"\\DosDevices\\Root#BOOST#0000#{%08X-%04X-%04X-%04X-%012X}", 
		uRandom^0x2468ACE, (USHORT)uRandom^0x5678, (USHORT)uRandom^0x4321, (USHORT)uRandom^0xBCDE, uRandom);

	if (ThroughWrite != 'L')
	{
		if (DriveLetter == 'C')
		{
			status = SWInitializeVolumeShadowImage(&DevExtsion->VolumeShadowImage, 0x8001, L"\\??\\D:\\kdVoluDumpC%02d.sys");
		}
		else if (DriveLetter == 'E')
		{
			status = SWInitializeVolumeShadowImage(&DevExtsion->VolumeShadowImage, 0x40001, L"\\??\\D:\\kdVoluDumpE%02d.sys");
		}
		else
		{
			status = STATUS_INVALID_PARAMETER;
		}
		if (!NT_SUCCESS(status))
		{
			IoDetachDevice(DevExtsion->AttachedDevice);DevExtsion->AttachedDevice = NULL;
			IoDeleteDevice(filterDeviceObject);
			return status;
		}
	}
	else
	{
		RtlInitUnicodeString(&unSymbolicLinkName, DevExtsion->SymbolicLinkName);
		status = IoCreateSymbolicLink(&unSymbolicLinkName, &unfilterDeviceName);
		IoDetachDevice(DevExtsion->AttachedDevice);
		if (!NT_SUCCESS(status))
		{
			IoDeleteDevice(filterDeviceObject);
			return status;
		}
		if (DriveLetter == 'C')
		{
			memcpy(ProtectObjectInfoC.filterDeviceSymbolicLinkName, DevExtsion->SymbolicLinkName, sizeof(DevExtsion->SymbolicLinkName));
		}
		else if (DriveLetter == 'E')
		{
			memcpy(ProtectObjectInfoE.filterDeviceSymbolicLinkName, DevExtsion->SymbolicLinkName, sizeof(DevExtsion->SymbolicLinkName));
		}
	}

	DevExtsion->ListEntry.Flink = DevExtsion->ListEntry.Blink = &DevExtsion->ListEntry;
	DevExtsion->bQuitThread = FALSE;
	KeInitializeSpinLock(&DevExtsion->SpinLock);
	KeInitializeEvent(&DevExtsion->ThreadWaitEvent, SynchronizationEvent, FALSE);
	KeInitializeEvent(&DevExtsion->CompleteEvent, SynchronizationEvent, FALSE);
	PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, SWWorkThread, filterDeviceObject);
	ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, &DevExtsion->ThreadObject, NULL);
	ZwClose(hThread);

	return STATUS_SUCCESS;
}

PDEVICE_OBJECT SWDeleteDevice(PDEVICE_OBJECT DeviceObject)
{
	NTSTATUS status;
	PDEVICE_OBJECT nextDeviceObject;
	PFILETE_DEVICE_EXTSION DevExtsion;
	DevExtsion = (PFILETE_DEVICE_EXTSION)DeviceObject->DeviceExtension;
	if (DevExtsion->ThreadObject != NULL)
	{
		DevExtsion->bQuitThread = TRUE;
		KeSetEvent(&DevExtsion->ThreadWaitEvent, IO_NO_INCREMENT, FALSE);
		KeWaitForSingleObject(DevExtsion->ThreadObject, Executive, KernelMode, FALSE, NULL);
		ObfDereferenceObject(DevExtsion->ThreadObject);
		KeClearEvent(&DevExtsion->ThreadWaitEvent);
		KeClearEvent(&DevExtsion->CompleteEvent);
	}
	if (DevExtsion->AttachedDevice != NULL && DevExtsion->ThroughWrite == 'H')
	{
		IoDetachDevice(DevExtsion->AttachedDevice);
	}
	nextDeviceObject = DeviceObject->NextDevice;
	IoDeleteDevice(DeviceObject);
	return nextDeviceObject;
}

VOID SWDriverClear(PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT DeviceObject;
	for (DeviceObject = DriverObject->DeviceObject; DeviceObject; DeviceObject = SWDeleteDevice(DeviceObject));
}

NTSTATUS SWMajorRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irpSp;
	PFILETE_DEVICE_EXTSION DevExtsion;
	DevExtsion = (PFILETE_DEVICE_EXTSION)DeviceObject->DeviceExtension;
	irpSp = IoGetCurrentIrpStackLocation(Irp);
	if (DevExtsion->ThroughWrite != 'L' && irpSp->Parameters.Read.Length != 0)
	{
		IoMarkIrpPending(Irp);
		ExInterlockedInsertTailList(&DevExtsion->ListEntry, &Irp->Tail.Overlay.ListEntry, &DevExtsion->SpinLock);
		KeSetEvent(&DevExtsion->ThreadWaitEvent, IO_NO_INCREMENT, FALSE);
		status = STATUS_PENDING;
	}
	else
	{
		IoSkipCurrentIrpStackLocation(Irp);
		status = IoCallDriver(DevExtsion->AttachedDevice, Irp);
	}
	return status;
}

NTSTATUS SWMajorWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PFILETE_DEVICE_EXTSION DevExtsion = (PFILETE_DEVICE_EXTSION)DeviceObject->DeviceExtension;
	IoMarkIrpPending(Irp);
	ExInterlockedInsertTailList(&DevExtsion->ListEntry, &Irp->Tail.Overlay.ListEntry, &DevExtsion->SpinLock);
	KeSetEvent(&DevExtsion->ThreadWaitEvent, IO_NO_INCREMENT, FALSE);
	return STATUS_PENDING;
}

NTSTATUS SWMajorDevControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILETE_DEVICE_EXTSION DevExtsion = (PFILETE_DEVICE_EXTSION)DeviceObject->DeviceExtension;
	if (irpSp->Parameters.DeviceIoControl.IoControlCode != IOCTL_QUERY_TW_DEVICE_NAME)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExtsion->AttachedDevice, Irp);
	}
	if (irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(DevExtsion->SymbolicLinkName) && !bDisableAccess)
	{
		memcpy(Irp->AssociatedIrp.SystemBuffer, DevExtsion->SymbolicLinkName, sizeof(DevExtsion->SymbolicLinkName));
		Irp->IoStatus.Information = sizeof(DevExtsion->SymbolicLinkName);
		Irp->IoStatus.Status = STATUS_SUCCESS;
	}
	else
	{
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
	}
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS SWMajorPower(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PFILETE_DEVICE_EXTSION DevExtsion = (PFILETE_DEVICE_EXTSION)DeviceObject->DeviceExtension;
	PoStartNextPowerIrp(Irp);
	IoSkipCurrentIrpStackLocation(Irp);
	return PoCallDriver(DevExtsion->AttachedDevice, Irp);
}

NTSTATUS SWCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
	PKEVENT waitEvent = (PKEVENT)Context;
	UNREFERENCED_PARAMETER(DeviceObject);
	if (Irp->PendingReturned)
	{
		KeSetEvent(waitEvent, IO_NO_INCREMENT, FALSE);
	}
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS SWPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PFILETE_DEVICE_EXTSION DevExtsion = (PFILETE_DEVICE_EXTSION)DeviceObject->DeviceExtension;
	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(DevExtsion->AttachedDevice, Irp);
}

NTSTATUS SWCallNextAndComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status;
	KEVENT waitEvent;
	PFILETE_DEVICE_EXTSION DevExtsion = (PFILETE_DEVICE_EXTSION)DeviceObject->DeviceExtension;
	KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);
	IoCopyCurrentIrpStackLocationToNext(Irp);
	IoSetCompletionRoutine(Irp, SWCompletionRoutine, &waitEvent, TRUE, TRUE, TRUE);
	status = IoCallDriver(DevExtsion->AttachedDevice, Irp);
	if (status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&waitEvent, Executive, KernelMode, FALSE, NULL);
		status = Irp->IoStatus.Status;
	}
	return status;
}

NTSTATUS SWMajorPnp(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILETE_DEVICE_EXTSION DevExtsion = (PFILETE_DEVICE_EXTSION)DeviceObject->DeviceExtension;

	switch(irpSp->MinorFunction)
	{
	case IRP_MN_START_DEVICE:
		{
			status = SWCallNextAndComplete(DeviceObject, Irp);
			DeviceObject->Characteristics &= ~FILE_CHARACTERISTICS_PROPAGATED;
			DeviceObject->Characteristics |= (DevExtsion->AttachedDevice->Characteristics & FILE_CHARACTERISTICS_PROPAGATED);
		}
		break;
	case IRP_MN_REMOVE_DEVICE:
		{
			status = SWCallNextAndComplete(DeviceObject, Irp);
			IoDetachDevice(DevExtsion->AttachedDevice);
			IoDeleteDevice(DeviceObject);
		}
		break;
	case IRP_MN_DEVICE_USAGE_NOTIFICATION:
		{
			BOOLEAN bCreateOrDelete; //创建还是删除分页文件
			BOOLEAN bIsSetDoPowerPagableFlag = FALSE;
			if(irpSp->Parameters.UsageNotification.Type != DeviceUsageTypePaging)
			{
				return SWPassThrough(DeviceObject, Irp);
			}
			bCreateOrDelete = irpSp->Parameters.UsageNotification.InPath;
			KeWaitForSingleObject(&DevExtsion->UnwantedEvent, Executive, KernelMode, FALSE, NULL);
			if (!bCreateOrDelete && DevExtsion->PageFileCount==1 && (DeviceObject->Flags & DO_DEVICE_HAS_NAME)==0)
			{
				DeviceObject->Flags |= DO_POWER_PAGABLE;
				bIsSetDoPowerPagableFlag = TRUE;
			}
			status = SWCallNextAndComplete(DeviceObject, Irp);
			if (NT_SUCCESS(status))
			{
				bCreateOrDelete ? InterlockedIncrement(&DevExtsion->PageFileCount) : InterlockedDecrement(&DevExtsion->PageFileCount);
				if (bCreateOrDelete && DevExtsion->PageFileCount == 1)
				{
					DeviceObject->Flags &= ~DO_POWER_PAGABLE;
				}
			}
			else
			{
				if (bIsSetDoPowerPagableFlag)
				{
					DeviceObject->Flags &= ~DO_POWER_PAGABLE;
				}
			}
			KeSetEvent(&DevExtsion->UnwantedEvent, IO_NO_INCREMENT, FALSE);	
		}
	    break;
	default:
		return SWPassThrough(DeviceObject, Irp);
	}
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS SetFileAttribute(PWCHAR wpFilePath, ULONG uNewAttributes, PULONG OldAttributes)
{
	FILE_BASIC_INFORMATION fbi;
	IO_STATUS_BLOCK        IoStatusBlock;
	UNICODE_STRING         unFIlePath;
	OBJECT_ATTRIBUTES      ObjectAttributes;
	NTSTATUS               status = STATUS_SUCCESS;
	HANDLE                 hFile  = NULL;
	RtlInitUnicodeString(&unFIlePath, wpFilePath);
	InitializeObjectAttributes(&ObjectAttributes, &unFIlePath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwCreateFile(&hFile, FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES|SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (NT_SUCCESS(status))
	{
		status = ZwQueryInformationFile(hFile, &IoStatusBlock, &fbi, sizeof(fbi), FileBasicInformation);
		if (NT_SUCCESS(status))
		{
			if (OldAttributes != NULL)
			{
				*OldAttributes = fbi.FileAttributes;
			}
			fbi.FileAttributes = uNewAttributes;
			status = ZwSetInformationFile(hFile, &IoStatusBlock, &fbi, sizeof(fbi), FileBasicInformation);
			if (NT_SUCCESS(status))
			{
				DbgPrint("ZwSetInformationFile  SUCCESS\r\n");
			}
		}
		ZwClose(hFile);
	}
	return status;
}

NTSTATUS SWDeleteFile(PWCHAR wpFileName, BOOLEAN bDelFolder)
{
	NTSTATUS          status;
	UNICODE_STRING    unFileName;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK   iosb;
	HANDLE            hFile;
	ULONG             uAttr;
	FILE_DISPOSITION_INFORMATION fdi;
	if (bDelFolder)
	{
		uAttr = FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_DIRECTORY;
	}
	else
	{
		uAttr = FILE_ATTRIBUTE_NORMAL;
	}
	status = SetFileAttribute(wpFileName, uAttr, NULL);	//设置属性			
	if (!NT_SUCCESS(status))
	{
		if (status == STATUS_OBJECT_NAME_NOT_FOUND)
		{
			return STATUS_SUCCESS;	//如果打开失败的原因是文件不存在,那么还是返回函数执行成功
		}
		return status;
	}
	RtlInitUnicodeString(&unFileName, wpFileName);
	InitializeObjectAttributes(&oa, &unFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwCreateFile(&hFile, DELETE|SYNCHRONIZE, &oa, &iosb, 0, 0, FILE_SHARE_DELETE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (status != STATUS_SUCCESS)
	{
		if (iosb.Information == FILE_DOES_NOT_EXIST)
		{
			return STATUS_SUCCESS;	//如果打开失败的原因是文件不存在,那么还是返回函数执行成功
		}
		else
		{
			return status;			//如果是由于其他原因所引起,那么返回错误
		}
	}
	fdi.DeleteFile = TRUE;
	status = ZwSetInformationFile(hFile, &iosb, &fdi, sizeof(fdi), FileDispositionInformation);
	ZwClose(hFile);
	return status;
}

NTSTATUS SWDeleteFolder(PWCHAR wpPath)
{
	NTSTATUS          status;
	OBJECT_ATTRIBUTES oa;
	HANDLE            hDirectory;
	UNICODE_STRING    us;
	UNICODE_STRING    unName;
	IO_STATUS_BLOCK   iosb;
	TIME_FIELDS       tf;
	ULONG             cb;
	PWCHAR            wpNewPath;
	PFILE_BOTH_DIR_INFORMATION pfdi;
	wpNewPath = ExAllocatePool(NonPagedPool, 1024);
	if (wpNewPath == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlInitUnicodeString(&us, wpPath);
	InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenFile(&hDirectory, FILE_LIST_DIRECTORY|SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT);
	if(status == STATUS_SUCCESS)
	{
		cb   = sizeof(FILE_BOTH_DIR_INFORMATION) + 512;
		pfdi = ExAllocatePool(NonPagedPool, cb);
		if (pfdi != NULL)
		{
			status = ZwQueryDirectoryFile(hDirectory, NULL, NULL, NULL, &iosb, pfdi, cb, FileBothDirectoryInformation, TRUE, NULL, TRUE);
			do
			{
				if(status == STATUS_SUCCESS)
				{
					pfdi->FileName[pfdi->FileNameLength/2] = L'\0';
					if ((pfdi->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)	//目录
					{
						if (_wcsicmp(pfdi->FileName, L".") == 0)
						{
							continue;
						}
						if (_wcsicmp(pfdi->FileName, L"..") == 0)
						{
							continue;
						}
						wcscpy(wpNewPath, wpPath);
						if (wpNewPath[wcslen(wpNewPath)-1] != L'\\') 
						{
							wcscat(wpNewPath, L"\\");
						}
						wcscat(wpNewPath, pfdi->FileName);
						status = SWDeleteFolder(wpNewPath);
						if (status != STATUS_SUCCESS)
						{
							break;
						}
					}
					else	//文件
					{
						wcscpy(wpNewPath, wpPath);
						if (wpNewPath[wcslen(wpNewPath)-1] != L'\\')
						{
							wcscat(wpNewPath, L"\\");
						}
						wcscat(wpNewPath, pfdi->FileName);
						RtlTimeToTimeFields(&pfdi->CreationTime, &tf);
						DbgPrint("%ws   size=%d   Delete on %d.%02d.%04d\n", wpNewPath, pfdi->EndOfFile.LowPart, tf.Day, tf.Month, tf.Year);						
						status = SWDeleteFile(wpNewPath, FALSE);
						if (status != STATUS_SUCCESS)
						{
							//break; //不能删除的文件不去理会它
						}
					}
				}
			}
			while((status = ZwQueryDirectoryFile(hDirectory, NULL, NULL, NULL, &iosb, pfdi, cb, FileBothDirectoryInformation, TRUE, NULL, FALSE)) != STATUS_NO_MORE_FILES);
			ExFreePool(pfdi);
		}
		else
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
		}
		ZwClose(hDirectory);
	}
	ExFreePool(wpNewPath);
	if (status == STATUS_NO_MORE_FILES) 
	{
		status = STATUS_SUCCESS;
	}
	if (status == STATUS_SUCCESS)
	{
		status = SWDeleteFile(wpPath, TRUE);
	}
	return status;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	ULONG uRandom;
	NTSTATUS status;
	LARGE_INTEGER uSeed;
 
//	SWDeleteFolder(L"\\??\\D:");	//清空D盘

	KeQuerySystemTime(&uSeed);
	uRandom = RtlRandom((PULONG)&uSeed);
	uSessionID     = uRandom;
	bDisableAccess = TRUE;		//初始化为不允许获取穿透写所用设备的符号连接和不允许写参数扇区
	SWCreateAllFile();			//实际是删除文件
	status = SWInitProtectInfo();
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = SWReadConfigData();//读取配置数据(是否保护,密码)
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	if (!ProtectObjectInfoC.IsProtect && !ProtectObjectInfoE.IsProtect)
	{
		return SWHookDiskMajorRouter(RtlRandom((PULONG)&uSeed));
	}

	uRandom = RtlRandom((PULONG)&uSeed);
	if (ProtectObjectInfoC.IsProtect)
	{
		if (
			NT_SUCCESS(SWInitializeDevice(DriverObject, 'C', 'L', uRandom)) &&
			NT_SUCCESS(SWInitializeDevice(DriverObject, 'C', 'H', uRandom))
			){}
		else
		{
			ProtectObjectInfoC.IsProtect = FALSE;
		}
	}

	uRandom = RtlRandom((PULONG)&uSeed);
	if (ProtectObjectInfoE.IsProtect)
	{
		if (
			NT_SUCCESS(SWInitializeDevice(DriverObject, 'E', 'L', uRandom)) &&
			NT_SUCCESS(SWInitializeDevice(DriverObject, 'E', 'H', uRandom))
			){}
		else
		{
			ProtectObjectInfoE.IsProtect = FALSE;
		}
	}

	if (!ProtectObjectInfoC.IsProtect && !ProtectObjectInfoE.IsProtect)
	{
		SWDriverClear(DriverObject);
		return STATUS_SUCCESS;
	}

	status = SWHookDiskMajorRouter(RtlRandom((PULONG)&uSeed));
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	DriverObject->DriverUnload = NULL;

	for (uRandom = 0; uRandom <= IRP_MJ_MAXIMUM_FUNCTION; uRandom++)
	{
		DriverObject->MajorFunction[uRandom] = SWPassThrough;
	}

	DriverObject->MajorFunction[IRP_MJ_READ] = SWMajorRead;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = SWMajorWrite;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SWMajorDevControl;
	DriverObject->MajorFunction[IRP_MJ_POWER] = SWMajorPower;
	DriverObject->MajorFunction[IRP_MJ_PNP] = SWMajorPnp;

	return STATUS_SUCCESS;
}
