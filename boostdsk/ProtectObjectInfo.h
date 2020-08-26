#ifndef _PROTECTOBJECTINFO_H_
#define _PROTECTOBJECTINFO_H_

typedef struct _PROTECT_OBJECT_INFO //(sizeof=0x838)
{
	BOOLEAN IsProtect;						//是否被保护的实际状态
	BOOLEAN ProtectState;					//是否被保护(主要用于与应用层通信,可以与上面不同)
	CHAR DriveLetter;
	ULONG PartitionIndex;					//相对于整个系统的分区索引
	ULONG DiskIndex;
	WCHAR VolumeDeviceName[257];			//比如: \Device\HarddiskVolume1
	WCHAR DiskDeviceName[257];				//比如: \Device\Harddisk0\DR0
	WCHAR filterDeviceSymbolicLinkName[257];
	LARGE_INTEGER StartingOffset;			//分区开始偏移
	LARGE_INTEGER PartitionLength;			//分区长度
	PFILE_OBJECT FileObject;				//代表这个磁盘设备的文件对象
	PDRIVE_LAYOUT_INFORMATION DriverLayoutInfo;
	ULONG PartitionCountInThisDisk;
	PARTITION_INFORMATION PartitionEntry[16];
} PROTECT_OBJECT_INFO, *PPROTECT_OBJECT_INFO;

extern PROTECT_OBJECT_INFO ProtectObjectInfoC;
extern PROTECT_OBJECT_INFO ProtectObjectInfoE;
extern CHAR ProtectPassword[32];

NTSTATUS SWReadConfigData();
NTSTATUS SWWriteConfigData();
NTSTATUS SWInitProtectInfo();
BOOLEAN SWTestOffsetIsHit(PDEVICE_OBJECT DeviceObject, PIRP Irp, PPROTECT_OBJECT_INFO ProtectObjectInfo);

#endif
