#ifndef _VOLUMESHADOWIMAGE_H_
#define _VOLUMESHADOWIMAGE_H_

#pragma pack(push, 1)
typedef struct _BLOCK_NODE //(sizeof=0x29)
{
	BYTE IsUsed;				//是否被使用
	LARGE_INTEGER BlockNum;		//当前块号, 一块为128KB
	BYTE Bitmap[32];			//每个位代表一个扇区,一共可以表示32*8=256个扇区,也就是128KB,正好一块
} BLOCK_NODE, *PBLOCK_NODE;
#pragma pack(pop)

typedef struct _VOLUME_SHADOW_IMAGE //(sizeof=0x20)
{
	HANDLE FileHandle;
	ULONG BlockCount;		//C盘:0x8001 or E盘:0x40001
	PBLOCK_NODE BlockNodeList;
	LARGE_INTEGER OffsetOfImageFile;
	LARGE_INTEGER EndOfImageFile;
} VOLUME_SHADOW_IMAGE, *PVOLUME_SHADOW_IMAGE;

NTSTATUS SWInitializeVolumeShadowImage(PVOLUME_SHADOW_IMAGE * lpVolumeShadowImage, ULONG BlockCount, PWCHAR FileNameTemplate);
NTSTATUS SWReadVolumeShadowImage(PVOLUME_SHADOW_IMAGE VolumeShadowImage, PVOID SystemBuffer, LARGE_INTEGER Offset, ULONG Length);
BOOLEAN SWFullDataInImage(PVOLUME_SHADOW_IMAGE VolumeShadowImage, PVOID SystemBuffer, LARGE_INTEGER Offset, ULONG Length);
NTSTATUS SWWriteVolumeShadowImage(PVOLUME_SHADOW_IMAGE VolumeShadowImage, PVOID SystemBuffer, LARGE_INTEGER Offset, ULONG Length);

#endif
