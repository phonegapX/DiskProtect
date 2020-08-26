#pragma once
#include "afxcoll.h"
#include "..\..\boostdsk\common.h"

#undef MAX_PATH
#define MAX_PATH 460
//==============================================================================
// 下面是索引文件相关定义
//

#define dwBytesOfKilo			1024
#define dwBytesOfMega			(dwBytesOfKilo*dwBytesOfKilo)
#define dwBytesOfGiga			(dwBytesOfMega*dwBytesOfKilo)
#define dwPieceSize				(256*dwBytesOfKilo)
#define dwSizeOfReserve			512
#define PacketMagicFlag			'  DQ'
#define CurrentVersion			1
#define SHA_HASH_LENGTH			20
#define INDEX_FILE_NAME			"KeydoneIndex.dat"

#pragma pack(push, 1)

typedef union _PACKET_RESERVE
{
	UCHAR ByteOf[dwSizeOfReserve];
	struct
	{
		ULONG         PacketMagic;				// 魔法标志 == 'QD  '
		ULONG         PacketVersion;			// 索引文件的版本号
		ULONG         PacketFileCount;			// 索引文件中包含多少个文件
		LARGE_INTEGER PacketFileMaxSize;		// 索引文件所包含文件的总大小
		CHAR          RootDirName[MAX_PATH];	// 索引文件所包含文件的根目录名(如果是单文件形式的话这里全部为0)
	};
} PACKET_RESERVE, *PPACKET_RESERVE;

#pragma pack(pop)

// 接下来: 1字节文件相对路径长度(以0结尾) + 8字节文件大小 + 8字节文件最后修改时间 + 文件SHA
// 索引文件最后20个字节是整个索引文件的SHA
//==============================================================================

typedef struct _FILE_INDEX_INFO
{
	PCHAR FilePathName;
	PLARGE_INTEGER FileSize;
	PFILETIME FileTime;
	PBYTE Sha1;
	//////////////////////////////////
	// 下面的字段每次对比拷贝临时使用
	_FILE_INDEX_INFO * Next;	//用这个将要拷贝的文件链起来
	ULONG PieceCount;			//这个文件一共要拷贝多少个PIECE
	PULONG PieceList;			//PIECE编号列表
	BOOL FileExist;				//要操作的文件是不是存在
	LARGE_INTEGER RealFileSize;	//文件如果存在,那么要操作的文件当前的实际大小是多少,用于统计剩余空间大小
} FILE_INDEX_INFO, *PFILE_INDEX_INFO;

ULONG CreateIndexFile(PCHAR PathFileName, PCHAR TargetIndexFile, PCREATE_PROGRESS_REPORT ReportRoutine, PVOID ReportContext);

enum UPDATE_TYPE
{
	SNAPSHOT_UPDATE,	//比较源目录和目标目录中索引文件
	REPAIR_UPDATE,		//用源目录中的索引文件去校验目标目录中的实际文件
	DIRECT_UPDATE		//不做任何比较,直接根据源目录中索引文件进行文件拷贝
};

class CFolder
{
public:
	CFolder() : m_hFile(INVALID_HANDLE_VALUE), m_hMap(NULL), m_IndexFileMap(NULL), m_IndexFileSize(0), m_FileIndexInfo(NULL), m_FileCount(0), m_PieceList(NULL), m_LastError(ERROR_SUCCESS)
	{}
	~CFolder();
	BOOL Load(PCHAR Path);
	BOOL CopyTo(CFolder & DestFolder, UPDATE_TYPE UpdateType);
	BOOL PacketCheck(CFolder & DestFolder, PPACKET_CHECK_INFO * PacketCheckInfo);
	void PacketCheckEnd(PPACKET_CHECK_INFO PacketCheckInfo);
	ULONG GetLastErrorCode(void);
	void AttachCallBack(PCREATE_PROGRESS_REPORT ReportRoutine, PVOID ReportContext);

private:
	CMapStringToPtr m_FileListMap;
	PFILE_INDEX_INFO m_FileIndexInfo;
	CHAR m_Path[MAX_PATH];	//目录路径
	CHAR m_Name[MAX_PATH];	//目录名称
	HANDLE m_hFile;
	HANDLE m_hMap;
	PBYTE m_IndexFileMap;
	ULONG m_IndexFileSize;	//索引文件大小
	ULONG m_FileCount;		//目录下所有文件总数
	PULONG m_PieceList;		//块索引列表
	ULONG m_LastError;
	PCREATE_PROGRESS_REPORT m_ReportRoutine;
	PVOID m_ReportContext;

private:
	PFILE_INDEX_INFO CompareWith(CFolder & DestFolder);
	PFILE_INDEX_INFO RepairWith (CFolder & DestFolder);
	PFILE_INDEX_INFO ParseWith();
	void CloseFolder();
};
