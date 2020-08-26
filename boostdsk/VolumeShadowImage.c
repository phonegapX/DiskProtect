#include "std.h"
#include "VolumeShadowImage.h"

BYTE BITMAP_TABLE[8] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };

NTSTATUS SWInitializeVolumeShadowImage(PVOLUME_SHADOW_IMAGE * lpVolumeShadowImage, ULONG BlockCount, PWCHAR FileNameTemplate)
{
	ULONG Number;
	NTSTATUS status;
	UNICODE_STRING unFileName;
	IO_STATUS_BLOCK IoStatusBlock;
	OBJECT_ATTRIBUTES ObjectAttributes;
	PVOLUME_SHADOW_IMAGE VolumeShadowImage;
	FILE_END_OF_FILE_INFORMATION EndOfFileInfo;
	WCHAR wBuffer[258];

	VolumeShadowImage = (PVOLUME_SHADOW_IMAGE)ExAllocatePool(PagedPool, sizeof(VOLUME_SHADOW_IMAGE));
	if (VolumeShadowImage == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	memset(VolumeShadowImage, 0, sizeof(*VolumeShadowImage));
	VolumeShadowImage->BlockCount = BlockCount;
	VolumeShadowImage->BlockNodeList = ExAllocatePool(PagedPool, BlockCount*sizeof(BLOCK_NODE));
	if (VolumeShadowImage->BlockNodeList == NULL)
	{
		ExFreePool(VolumeShadowImage);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	memset(VolumeShadowImage->BlockNodeList, 0, BlockCount*sizeof(BLOCK_NODE));

	for (Number = 0; Number < 99; Number++)
	{
		swprintf(wBuffer, FileNameTemplate, Number);
		RtlInitUnicodeString(&unFileName, wBuffer);
		InitializeObjectAttributes(&ObjectAttributes, &unFileName, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);
		status = ZwCreateFile(
			&VolumeShadowImage->FileHandle, 
			GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE, 
			&ObjectAttributes, 
			&IoStatusBlock, 
			NULL, 
			FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN, 
			0, 
			FILE_OVERWRITE_IF, 
			FILE_NO_INTERMEDIATE_BUFFERING|FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE|FILE_RANDOM_ACCESS, 
			NULL, 
			0);
		if (NT_SUCCESS(status))
		{
			status = ZwSetInformationFile(
				VolumeShadowImage->FileHandle, 
				&IoStatusBlock, 
				(EndOfFileInfo.EndOfFile.QuadPart = dwImageFileIncrementBlockSize, &EndOfFileInfo), 
				sizeof(EndOfFileInfo), 
				FileEndOfFileInformation);
			if (!NT_SUCCESS(status))
			{
				ZwClose(VolumeShadowImage->FileHandle);
				ExFreePool(VolumeShadowImage->BlockNodeList);
				ExFreePool(VolumeShadowImage);
				return status;
			}
			VolumeShadowImage->EndOfImageFile.QuadPart = dwImageFileIncrementBlockSize;
			VolumeShadowImage->OffsetOfImageFile.QuadPart = 0;
			*lpVolumeShadowImage = VolumeShadowImage;
			return STATUS_SUCCESS;
		}
	}

	ExFreePool(VolumeShadowImage->BlockNodeList);
	ExFreePool(VolumeShadowImage);
	return status;
}

PBLOCK_NODE SWFindBlockNode(PVOLUME_SHADOW_IMAGE VolumeShadowImage, ULONG BlockNum)
{
	ULONG i, uBlockIndex;
	PBLOCK_NODE BlockNode;
	for (i = 0; i < VolumeShadowImage->BlockCount; i++)
	{
		if (i == 0)
		{
			uBlockIndex = BlockNum % VolumeShadowImage->BlockCount;
		}
		else
		{
			uBlockIndex = (((BlockNum % (VolumeShadowImage->BlockCount - 2)) + 1) * i + (BlockNum % VolumeShadowImage->BlockCount)) % VolumeShadowImage->BlockCount;
		}
		BlockNode = &VolumeShadowImage->BlockNodeList[uBlockIndex];
		if ((BlockNode->BlockNum.QuadPart & 0x7FFFFFF) == BlockNum)
		{
			return BlockNode;	//找到了
		}
		if (!BlockNode->IsUsed)	//没使用
		{
			return BlockNode;
		}
	}
	return NULL;
}

BOOLEAN SWBitmapRangeIsSet(ULONG InnerOffset, ULONG InnerLength, PBYTE Bitmap)
{
	ULONG uStartSector = InnerOffset / dwBytesPerSectore;
	ULONG uEndSector   = (InnerOffset + InnerLength) / dwBytesPerSectore;
	for (;uStartSector < uEndSector; uStartSector++)
	{
		if ((Bitmap[uStartSector/8] & BITMAP_TABLE[uStartSector%8]) == 0)
		{
			return FALSE;
		}
	}
	return TRUE;
}

VOID SWUpdateBitmap(ULONG InnerOffset, ULONG InnerLength, PBYTE Bitmap)
{
	ULONG uStartSector = InnerOffset / dwBytesPerSectore;
	ULONG uEndSector   = (InnerOffset + InnerLength) / dwBytesPerSectore;
	for (;uStartSector < uEndSector; uStartSector++)
	{
		Bitmap[uStartSector/8] |= BITMAP_TABLE[uStartSector%8];
	}
}

BOOLEAN SWFullDataInImage(PVOLUME_SHADOW_IMAGE VolumeShadowImage, PVOID SystemBuffer, LARGE_INTEGER Offset, ULONG Length)
{
	PBYTE CurBufAddress;
	ULONG BlockNum, InnerOffset, InnerLength;
	PBLOCK_NODE BlockNode;

	if (Length == 0) return TRUE;
	CurBufAddress = (PBYTE)SystemBuffer;
	BlockNum = (ULONG)(Offset.QuadPart / dwNodeBlockSize);
	InnerOffset = (ULONG)(Offset.QuadPart % dwNodeBlockSize);
	InnerLength = (dwNodeBlockSize - InnerOffset) > Length ? Length : (dwNodeBlockSize - InnerOffset);
	do
	{
		if ((BlockNode = SWFindBlockNode(VolumeShadowImage, BlockNum)) == NULL)
		{
			return FALSE;
		}
		if (!BlockNode->IsUsed)
		{
			return FALSE;
		}
		if (!SWBitmapRangeIsSet(InnerOffset, InnerLength, BlockNode->Bitmap))
		{
			return FALSE;
		}
		CurBufAddress += InnerLength;
		BlockNum++;
		InnerLength = Length - ((ULONG)CurBufAddress-(ULONG)SystemBuffer);
		InnerLength = InnerLength <= dwNodeBlockSize ? InnerLength : dwNodeBlockSize;
		InnerOffset = 0;
	}
	while ((ULONG)CurBufAddress-(ULONG)SystemBuffer < Length);
	return TRUE;
}

NTSTATUS SWReadImageFile(HANDLE FileHandle, LARGE_INTEGER BasicOffset, PBYTE Bitmap, ULONG InnerOffset, PVOID SystemBuffer, ULONG InnerLength)
{
	LARGE_INTEGER Offset;
	IO_STATUS_BLOCK IoStatusBlock;
	ULONG uStartSector = InnerOffset / dwBytesPerSectore;
	ULONG uEndSector   = (InnerOffset + InnerLength) / dwBytesPerSectore;
	PBYTE CurBufAddress = (PBYTE)SystemBuffer;
	ULONG ReadLength = 0;
	PBYTE ReadBuffer = NULL;

	if (InnerOffset + InnerLength > dwNodeBlockSize || InnerOffset & 0x1FF || InnerLength & 0x1FF)
	{
		return STATUS_INVALID_PARAMETER;
	}

	for (;uStartSector < uEndSector; uStartSector++)
	{
		if ((Bitmap[uStartSector/8] & BITMAP_TABLE[uStartSector%8]) != 0)
		{
			if (ReadLength == 0)
			{
				Offset.QuadPart = BasicOffset.QuadPart + InnerOffset;
				ReadBuffer = CurBufAddress;
			}
			ReadLength += 512;
		}
		else
		{
			if (ReadLength != 0)
			{
				ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, ReadBuffer, ReadLength, &Offset, NULL);
				ReadLength = 0;
			}
		}
		InnerOffset += dwBytesPerSectore;
		CurBufAddress += dwBytesPerSectore;
	}
	if (ReadLength != 0)
	{
		ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, ReadBuffer, ReadLength, &Offset, NULL);
	}
	return STATUS_SUCCESS;
}

NTSTATUS SWReadVolumeShadowImage(PVOLUME_SHADOW_IMAGE VolumeShadowImage, PVOID SystemBuffer, LARGE_INTEGER Offset, ULONG Length)
{
	PBYTE CurBufAddress;
	ULONG BlockNum, InnerOffset, InnerLength;
	PBLOCK_NODE BlockNode;
	LARGE_INTEGER BasicOffset;

	if (Length == 0) return STATUS_SUCCESS;
	CurBufAddress = (PBYTE)SystemBuffer;
	BlockNum = (ULONG)(Offset.QuadPart / dwNodeBlockSize);
	InnerOffset = (ULONG)(Offset.QuadPart % dwNodeBlockSize);
	InnerLength = (dwNodeBlockSize - InnerOffset) > Length ? Length : (dwNodeBlockSize - InnerOffset);
	do
	{
		BlockNode = SWFindBlockNode(VolumeShadowImage, BlockNum);
		if (BlockNode != NULL && BlockNode->IsUsed)
		{
			BasicOffset.QuadPart = (BlockNode->BlockNum.QuadPart >> 27);
			SWReadImageFile(VolumeShadowImage->FileHandle, BasicOffset, BlockNode->Bitmap, InnerOffset, CurBufAddress, InnerLength);
		}
		CurBufAddress += InnerLength;
		BlockNum++;
		InnerLength = Length - ((ULONG)CurBufAddress-(ULONG)SystemBuffer);
		InnerLength = InnerLength <= dwNodeBlockSize ? InnerLength : dwNodeBlockSize;
		InnerOffset = 0;
	}
	while ((ULONG)CurBufAddress-(ULONG)SystemBuffer < Length);
	return STATUS_SUCCESS;
}

NTSTATUS SWWriteImageFile(HANDLE FileHandle, LARGE_INTEGER BasicOffset, ULONG InnerOffset, PVOID SystemBuffer, ULONG InnerLength)
{
	IO_STATUS_BLOCK IoStatusBlock;
	BasicOffset.QuadPart += InnerOffset;
	return ZwWriteFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, SystemBuffer, InnerLength, &BasicOffset, NULL);
}

NTSTATUS SWWriteVolumeShadowImage(PVOLUME_SHADOW_IMAGE VolumeShadowImage, PVOID SystemBuffer, LARGE_INTEGER Offset, ULONG Length)
{
	NTSTATUS status;
	PBYTE CurBufAddress;
	ULONG BlockNum, InnerOffset, InnerLength;
	PBLOCK_NODE BlockNode;
	LARGE_INTEGER BasicOffset;
	IO_STATUS_BLOCK IoStatusBlock;
	FILE_END_OF_FILE_INFORMATION FileEndOfInfo;

	if (Length == 0) return STATUS_SUCCESS;
	CurBufAddress = (PBYTE)SystemBuffer;
	BlockNum = (ULONG)(Offset.QuadPart / dwNodeBlockSize);
	InnerOffset = (ULONG)(Offset.QuadPart % dwNodeBlockSize);
	InnerLength = (dwNodeBlockSize - InnerOffset) > Length ? Length : (dwNodeBlockSize - InnerOffset);
	do
	{
		BlockNode = SWFindBlockNode(VolumeShadowImage, BlockNum);
		if (BlockNode == NULL)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		if (!BlockNode->IsUsed)
		{
			BlockNode->IsUsed = TRUE;
			BlockNode->BlockNum.QuadPart &= 0xFFFFFFFFF8000000;
			BlockNode->BlockNum.QuadPart |= (BlockNum & 0x7FFFFFF);
			BlockNode->BlockNum.QuadPart &= 0x7FFFFFF;
			BlockNode->BlockNum.QuadPart |= (VolumeShadowImage->OffsetOfImageFile.QuadPart << 27);

			VolumeShadowImage->OffsetOfImageFile.QuadPart += dwNodeBlockSize;
			if (VolumeShadowImage->OffsetOfImageFile.QuadPart > VolumeShadowImage->EndOfImageFile.QuadPart)
			{
				VolumeShadowImage->EndOfImageFile.QuadPart += dwImageFileIncrementBlockSize;
				FileEndOfInfo.EndOfFile = VolumeShadowImage->EndOfImageFile;
				ZwSetInformationFile(VolumeShadowImage->FileHandle, &IoStatusBlock, &FileEndOfInfo, sizeof(FileEndOfInfo), FileEndOfFileInformation);
			}
		}
		BasicOffset.QuadPart = (BlockNode->BlockNum.QuadPart >> 27);
		status = SWWriteImageFile(VolumeShadowImage->FileHandle, BasicOffset, InnerOffset, CurBufAddress, InnerLength);
		if (!NT_SUCCESS(status))
		{
			return status;
		}
		SWUpdateBitmap(InnerOffset, InnerLength, BlockNode->Bitmap);
		CurBufAddress += InnerLength;
		BlockNum++;
		InnerLength = Length - ((ULONG)CurBufAddress-(ULONG)SystemBuffer);
		InnerLength = InnerLength <= dwNodeBlockSize ? InnerLength : dwNodeBlockSize;
		InnerOffset = 0;
	}
	while ((ULONG)CurBufAddress-(ULONG)SystemBuffer < Length);
	return STATUS_SUCCESS;
}
