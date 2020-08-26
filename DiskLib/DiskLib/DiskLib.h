#pragma once

#define dwBytesOfKilo			1024
#define dwPieceSize				(256*dwBytesOfKilo)

//用于效验索引文件后 输出统计信息
typedef struct _PACKET_CHECK_INFO
{
	CHAR FileName[512];			//检查文件的文件名
	ULONG uPieceCount;			//这个文件检查出有多少个块不对
	BOOL FileExist;				//要操作的文件是不是存在
	LARGE_INTEGER FileSize;		//这个文件应该的大小
	LARGE_INTEGER RealFileSize;	//这个文件实际是多大
	struct _PACKET_CHECK_INFO * Next;	//下一个节点
} PACKET_CHECK_INFO, *PPACKET_CHECK_INFO;

#define PROGRESS_REPORT_START		0
#define PROGRESS_REPORT_DISP		1
#define PROGRESS_REPORT_END			2
#define CHECKPROGRESS_REPORT_START	3
#define CHECKPROGRESS_REPORT_DISP	4

typedef VOID (*PCREATE_PROGRESS_REPORT) (PVOID ReportContext, ULONG uFlag, PCHAR FileName, LARGE_INTEGER & UParam);

//写还原驱动配置参数扇区,在没装驱动之前调用才有效
EXTERN_C BOOL WINAPI DiskLibWriteParamSector();

//本库初始化
EXTERN_C BOOL WINAPI DiskLibInitialize();

//检查还原保护密码是否正确
EXTERN_C BOOL WINAPI DiskLibCheckPassword(PCHAR Password);

//设置新的还原保护密码
EXTERN_C BOOL WINAPI DiskLibSetPassword(PCHAR Password);

//设置保护状态
EXTERN_C BOOL WINAPI DiskLibSetProtectState(BOOL ProtectStateC, BOOL ProtectStateE);

//获取保护状态
EXTERN_C BOOL WINAPI DiskLibGetProtectState(PBOOL ProtectStateC, PBOOL ProtectStateE);

//允许还原穿透写和允许重新设置配置参数扇区
EXTERN_C BOOL WINAPI DiskLibEnableThroughWrite();

//禁止还原穿透写和禁止设置配置参数扇区
EXTERN_C BOOL WINAPI DiskLibDisableThroughWrite();

//创建索引文件
EXTERN_C BOOL WINAPI DiskLibCreateIndexFile(PCHAR PathFileName, PCREATE_PROGRESS_REPORT ReportRoutine, PVOID ReportContext);

//修复更新
EXTERN_C BOOL WINAPI DiskLibRepairUpdate(PCHAR strSourcePath, PCHAR strDestPath, PCREATE_PROGRESS_REPORT ReportRoutine, PVOID ReportContext);

//快照更新(索引对比更新)
EXTERN_C BOOL WINAPI DiskLibSnapshotUpdate(PCHAR strSourcePath, PCHAR strDestPath, PCREATE_PROGRESS_REPORT ReportRoutine, PVOID ReportContext);

//完全更新(重新拷贝)
EXTERN_C BOOL WINAPI DiskLibCompleteUpdate(PCHAR strSourcePath, PCHAR strDestPath, PCREATE_PROGRESS_REPORT ReportRoutine, PVOID ReportContext);

//开始检查索引文件
EXTERN_C BOOL WINAPI DiskLibPacketCheckStart(PCHAR strPath, PPACKET_CHECK_INFO * PacketCheckInfo, PCREATE_PROGRESS_REPORT ReportRoutine, PVOID ReportContext);

//检查索引文件结束
EXTERN_C void WINAPI DiskLibPacketCheckEnd(PPACKET_CHECK_INFO PacketCheckInfo);

//剩余空间大小判断
