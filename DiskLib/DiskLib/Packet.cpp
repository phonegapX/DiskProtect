#include "stdafx.h"
#include "DiskLib.h"
#include "Packet.h"
#include "openssl\sha.h"
#include <string>
#include <vector>

//此函数用于计算ptr中的SHA1 Hash值，并将计算结果（20字节）放在dm中。
void Sha1(PCHAR ptr, size_t len, PBYTE dm)
{
	SHA_CTX context;
	SHA1_Init(&context);
	SHA1_Update(&context, (PBYTE)ptr, len);
	SHA1_Final(dm, &context);
}

BOOL IsDirectory(PCHAR szPath)
{
	WIN32_FIND_DATA stData;
	CHAR szNewPath[MAX_PATH];
	strcpy(szNewPath, szPath);
	if (szNewPath[strlen(szNewPath) - 1] == '\\')
	{
		szNewPath[strlen(szNewPath) - 1] = '\0';
	}
	HANDLE hSearch = ::FindFirstFile(szNewPath, &stData);
	if (hSearch == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR(0, "IsDirectory:查找文件失败(FindFirstFile)(%s)", szNewPath)
		return TRUE;
	}
	FindClose(hSearch);
	if (stData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{	//是目录
		return TRUE;
	}
	return FALSE;
}

ULONG GetDirectorySizeAndFileCount(PCHAR lpPath, LARGE_INTEGER & DirSize, ULONG & FileCount)
{
	ULONG uError = ERROR_SUCCESS;
	WIN32_FIND_DATA stData;
	CHAR szNewPath[MAX_PATH];
	CHAR szPath[MAX_PATH];
	strcpy(szNewPath, lpPath);
	if (szNewPath[strlen(szNewPath) - 1] != '\\')
	{
		strcat(szNewPath, "\\");
	}
	strcpy(szPath, szNewPath);
	strcat(szNewPath, "*.*");
	HANDLE hSearch = ::FindFirstFile(szNewPath, &stData);
	if (hSearch == INVALID_HANDLE_VALUE) 
	{
		uError = GetLastError();
		LOG_ERROR(uError, "GetDirectorySizeAndFileCount:查找文件失败(FindFirstFile)(%s)", szNewPath)
		return uError;
	}
	do
	{
		if (!strcmp(stData.cFileName, "..") || !strcmp(stData.cFileName, ".")) { continue; }
		if (stData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) 
		{	//是目录
			strcpy(szNewPath, szPath);
			if (szNewPath[strlen(szNewPath) - 1] != '\\') { strcat(szNewPath, "\\"); }
			strcat(szNewPath, stData.cFileName);
			strcat(szNewPath, "\\");
			uError = GetDirectorySizeAndFileCount(szNewPath, DirSize, FileCount);
			if (uError != ERROR_SUCCESS)
			{
				break;
			}
		}
		else
		{	//是文件
			if (stricmp(stData.cFileName, INDEX_FILE_NAME) == 0)
			{
				continue;
			}
			strcpy(szNewPath, szPath);
			strcat(szNewPath, stData.cFileName);
			HANDLE hFile = CreateFile(szNewPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile == INVALID_HANDLE_VALUE) 
			{ 
				uError = GetLastError();
				LOG_ERROR(uError, "GetDirectorySizeAndFileCount:打开文件失败(CreateFile)(%s)", szNewPath)
				break;
			}
			LARGE_INTEGER FileSize;
			if (!GetFileSizeEx(hFile, &FileSize))
			{
				CloseHandle(hFile);
				uError = GetLastError();
				LOG_ERROR(uError, "GetDirectorySizeAndFileCount:获取文件大小失败(GetFileSizeEx)(%s)", szNewPath)
				break;
			}
			DirSize.QuadPart += FileSize.QuadPart;
			FileCount++;
			CloseHandle(hFile);
		}
	}
	while (::FindNextFile(hSearch, &stData));
	FindClose(hSearch);
	return uError;
}

ULONG AddSingleFile(PCHAR szPath, PBYTE & Offset, ULONG uBaseLength, ULONG & IndexFileSize, PCREATE_PROGRESS_REPORT ReportRoutine, PVOID ReportContext, LARGE_INTEGER & uProgress)
{
	ULONG uError = ERROR_SUCCESS;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	__try
	{
		LARGE_INTEGER FileSize;
		hFile = CreateFile(szPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			uError = GetLastError();
			LOG_ERROR(uError, "AddSingleFile:打开文件失败(CreateFile)(%s)", szPath)
			__leave;
		}
		*((PBYTE)Offset) = strlen(&szPath[uBaseLength]);
		Offset += sizeof(BYTE);
		IndexFileSize += sizeof(BYTE);
		strcpy((PCHAR)Offset, &szPath[uBaseLength]);
		Offset += (strlen(&szPath[uBaseLength]) + sizeof('\0'));
		IndexFileSize += (strlen(&szPath[uBaseLength]) + sizeof('\0'));
		if (!GetFileSizeEx(hFile, &FileSize))
		{
			uError = GetLastError();
			LOG_ERROR(uError, "AddSingleFile:获取文件大小失败(GetFileSizeEx)(%s)", szPath)
			__leave;
		}
		*((PLARGE_INTEGER)Offset) = FileSize;
		Offset += sizeof(LARGE_INTEGER);
		IndexFileSize += sizeof(LARGE_INTEGER);
		if (!GetFileTime(hFile, NULL, NULL, (PFILETIME)Offset))
		{
			uError = GetLastError();
			LOG_ERROR(uError, "AddSingleFile:获取文件时间失败(GetFileTime)(%s)", szPath)
			__leave;
		}
		Offset += sizeof(FILETIME);
		IndexFileSize += sizeof(FILETIME);
		for (; FileSize.QuadPart != 0; )
		{ 
			static CHAR Buffer[dwPieceSize];
			ULONG Readed;
			if (!ReadFile(hFile, Buffer, dwPieceSize, &Readed, NULL))
			{
				uError = GetLastError();
				LOG_ERROR(uError, "AddSingleFile:文件读取失败(ReadFile)(%s)", szPath)
				__leave;
			}
			Sha1(Buffer, Readed, Offset);
			Offset += SHA_HASH_LENGTH;
			IndexFileSize += SHA_HASH_LENGTH;
			FileSize.QuadPart -= Readed;
			uProgress.QuadPart += Readed;
			ReportRoutine(ReportContext, PROGRESS_REPORT_DISP, szPath, uProgress); //报告进度
		}
	}
	__finally
	{
		if (hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hFile);
		}
	}
	return uError;
}

ULONG AddMultiFile(PCHAR lpPath, PBYTE & Offset, ULONG uBaseLength, ULONG & IndexFileSize, PCREATE_PROGRESS_REPORT ReportRoutine, PVOID ReportContext, LARGE_INTEGER & uProgress)
{
	ULONG uError = ERROR_SUCCESS;
	WIN32_FIND_DATA stData;
	CHAR szNewPath[MAX_PATH];
	CHAR szPath[MAX_PATH];
	strcpy(szNewPath, lpPath);
	if (szNewPath[strlen(szNewPath) - 1] != '\\') 
	{ 
		strcat(szNewPath, "\\");
	}
	strcpy(szPath, szNewPath);
	strcat(szNewPath, "*.*");
	HANDLE hSearch = ::FindFirstFile(szNewPath, &stData);
	if (hSearch == INVALID_HANDLE_VALUE) 
	{ 
		uError = GetLastError();
		LOG_ERROR(uError, "AddMultiFile:查找文件失败(FindFirstFile)(%s)", szNewPath)
		return uError;
	}
	do
	{
		if (!strcmp(stData.cFileName, "..") || !strcmp(stData.cFileName, ".")) { continue; }
		if (stData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) 
		{	//是目录
			strcpy(szNewPath, szPath);
			if (szNewPath[strlen(szNewPath) - 1] != '\\') { strcat(szNewPath, "\\"); }
			strcat(szNewPath, stData.cFileName);
			strcat(szNewPath, "\\");
			uError = AddMultiFile(szNewPath, Offset, uBaseLength, IndexFileSize, ReportRoutine, ReportContext, uProgress);
			if (uError != ERROR_SUCCESS)
			{
				break;
			}
		}
		else
		{	//是文件
			if (stricmp(stData.cFileName, INDEX_FILE_NAME) == 0)
			{
				continue;
			}
			strcpy(szNewPath, szPath);
			strcat(szNewPath, stData.cFileName);
			uError = AddSingleFile(szNewPath, Offset, uBaseLength, IndexFileSize, ReportRoutine, ReportContext, uProgress);
			if (uError != ERROR_SUCCESS)
			{
				LOG_ERROR(uError, "AddMultiFile:添加文件索引信息失败(AddSingleFile)(%s)", szNewPath)
				break;
			}
		}
	}
	while (::FindNextFile(hSearch, &stData));
	FindClose(hSearch);
	return uError;
}

/***********************************************************/
/* 参数一: 要制作索引文件的目录或文件的路径                */
/* 参数二: 生成的索引文件存放路径                          */
/***********************************************************/
ULONG CreateIndexFile(PCHAR PathFileName, PCHAR TargetIndexFile, PCREATE_PROGRESS_REPORT ReportRoutine, PVOID ReportContext)
{
	LARGE_INTEGER DirSize = {0};
	ULONG FileCount = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hMap = NULL;
	PBYTE BeginOffset = NULL;
	ULONG uBaseLength = 0;
	ULONG IndexFileSize  = 0;
	ULONG uError = ERROR_SUCCESS;
	PBYTE Offset = NULL;
	LARGE_INTEGER uProgress = {0};
	CHAR SourcePathName[MAX_PATH];
	strcpy(SourcePathName, PathFileName);
	if (SourcePathName[strlen(SourcePathName) - 1] == '\\')
	{
		SourcePathName[strlen(SourcePathName) - 1] = '\0';
	}
	if (SourcePathName[1] != ':' || SourcePathName[2] != '\\') // 验证路径正确性
	{
		LOG_ERROR(ERROR_INVALID_PARAMETER, "CreateIndexFile:输入路径不符合规范", NULL)
		return ERROR_INVALID_PARAMETER;
	}
	__try
	{
		hFile = CreateFile(TargetIndexFile, GENERIC_WRITE|GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) 
		{ 
			uError = GetLastError();
			LOG_ERROR(uError, "CreateIndexFile:创建索引文件失败(CreateFile)", NULL)
			__leave;
		}
		hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, dwBytesOfMega * 10, NULL);
		if (hMap == NULL)
		{ 
			uError = GetLastError();
			LOG_ERROR(uError, "CreateIndexFile:创建索引文件失败(CreateFileMapping)", NULL)
			__leave;
		}
		BeginOffset = (PBYTE)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		if (BeginOffset == NULL)
		{ 
			uError = GetLastError();
			LOG_ERROR(uError, "CreateIndexFile:创建索引文件失败(MapViewOfFile)", NULL)
			__leave;
		}
		Offset = BeginOffset + sizeof(PACKET_RESERVE);
		IndexFileSize += sizeof(PACKET_RESERVE);
		((PPACKET_RESERVE)BeginOffset)->PacketMagic = PacketMagicFlag;
		((PPACKET_RESERVE)BeginOffset)->PacketVersion = CurrentVersion;
		if (IsDirectory(SourcePathName))
		{
			uError = GetDirectorySizeAndFileCount(SourcePathName, DirSize, FileCount);
			if (uError != ERROR_SUCCESS)
			{
				LOG_ERROR(uError, "CreateIndexFile:获取目录大小失败(GetDirectorySizeAndFileCount)", NULL)
				__leave;
			}
			((PPACKET_RESERVE)BeginOffset)->PacketFileCount = FileCount;
			((PPACKET_RESERVE)BeginOffset)->PacketFileMaxSize = DirSize;
			strcpy(((PPACKET_RESERVE)BeginOffset)->RootDirName, strrchr(SourcePathName, '\\') + 1);
			uBaseLength = strlen(SourcePathName) + 1;
			ReportRoutine(ReportContext, PROGRESS_REPORT_START, SourcePathName, DirSize); //开始报告进度
			uError = AddMultiFile(SourcePathName, Offset, uBaseLength, IndexFileSize, ReportRoutine, ReportContext, uProgress);
			ReportRoutine(ReportContext, PROGRESS_REPORT_END, NULL, LARGE_INTEGER()); //结束报告进度
			if (uError != ERROR_SUCCESS)
			{
				LOG_ERROR(uError, "CreateIndexFile:添加文件索引信息失败(AddMultiFile)", NULL)
				__leave;
			}
		}
		else
		{
			HANDLE hFile = CreateFile(SourcePathName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile == INVALID_HANDLE_VALUE) 
			{
				uError = GetLastError();
				__leave;
			}
			LARGE_INTEGER FileSize;
			if (!GetFileSizeEx(hFile, &FileSize))
			{
				CloseHandle(hFile);
				uError = GetLastError();
				__leave;
			}
			CloseHandle(hFile);
			((PPACKET_RESERVE)BeginOffset)->PacketFileCount = 1;
			((PPACKET_RESERVE)BeginOffset)->PacketFileMaxSize = FileSize;
			memset(((PPACKET_RESERVE)BeginOffset)->RootDirName, 0, sizeof(((PPACKET_RESERVE)BeginOffset)->RootDirName));
			uBaseLength = 0;
			ReportRoutine(ReportContext, PROGRESS_REPORT_START, SourcePathName, FileSize); //开始报告进度
			uError = AddSingleFile(SourcePathName, Offset, uBaseLength, IndexFileSize, ReportRoutine, ReportContext, uProgress);
			ReportRoutine(ReportContext, PROGRESS_REPORT_END, NULL, LARGE_INTEGER()); //结束报告进度
			if (uError != ERROR_SUCCESS)
			{
				__leave;
			}
		}
		Sha1((PCHAR)BeginOffset, IndexFileSize, Offset);
		Offset += SHA_HASH_LENGTH;
		IndexFileSize += SHA_HASH_LENGTH;
		FlushViewOfFile(BeginOffset, IndexFileSize);
		UnmapViewOfFile(BeginOffset); BeginOffset = NULL;
		CloseHandle(hMap); hMap = NULL;
		uError = SetFilePointer(hFile, IndexFileSize, NULL, FILE_BEGIN);
		if (uError != IndexFileSize)
		{
			uError = GetLastError();
			LOG_ERROR(uError, "CreateIndexFile:设置文件指针失败(SetFilePointer)", NULL)
			__leave;
		}
		if (!SetEndOfFile(hFile))
		{
			uError = GetLastError();
			LOG_ERROR(uError, "CreateIndexFile:截断文件失败(SetEndOfFile)", NULL)
			__leave;
		}
		CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;
		uError = ERROR_SUCCESS;
	}
	__finally
	{
		if (BeginOffset != NULL)
		{
			UnmapViewOfFile(BeginOffset);
		}
		if (hMap != NULL)
		{
			CloseHandle(hMap);
		}
		if (hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hFile);
		}
		if (uError != ERROR_SUCCESS)
		{
			DeleteFile(TargetIndexFile);
		}
	}
	return uError;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 设置文件大小
ULONG SetFileSize(HANDLE hFile, PLARGE_INTEGER lpFileSize)
{
	LARGE_INTEGER FileSize = *lpFileSize;
	if(
		(SetFilePointer(hFile, FileSize.LowPart, &FileSize.HighPart, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
		&& 
		(SetEndOfFile(hFile))
		)
	{
		return ERROR_SUCCESS;
	}
	return GetLastError();
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 重叠IO写
ULONG FileOverlapWrite(HANDLE hFile, LPVOID lpBuffer, PLARGE_INTEGER lpOffset, ULONG nNumberOfBytes, HANDLE hEvent)
{
	OVERLAPPED Overlapped;
	ULONG NumberOfBytesWritten = 0;
	ULONG dwError = ERROR_SUCCESS;
	Overlapped.hEvent       = hEvent;
	Overlapped.Offset       = lpOffset->LowPart;
	Overlapped.OffsetHigh   = lpOffset->HighPart;
	Overlapped.Internal     = 0;
	Overlapped.InternalHigh = 0;
	if(!WriteFile(hFile, lpBuffer, nNumberOfBytes, &NumberOfBytesWritten, &Overlapped))
	{
		if((dwError = GetLastError()) == ERROR_IO_PENDING)
		{
			WaitForSingleObject(hEvent, INFINITE);
			if(!GetOverlappedResult(hFile, &Overlapped, &NumberOfBytesWritten, FALSE))
			{
				dwError = GetLastError();
			}
			else
			{
				dwError = ERROR_SUCCESS;
			}
		}
	}
	ResetEvent(hEvent);
	return dwError;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 重叠IO读
ULONG FileOverlapRead (HANDLE hFile, LPVOID lpBuffer, PLARGE_INTEGER lpOffset, ULONG nNumberOfBytes, PULONG NumberOfBytesRead, HANDLE hEvent)
{
	OVERLAPPED Overlapped;
	ULONG dwError = ERROR_SUCCESS;
	Overlapped.hEvent       = hEvent;
	Overlapped.Offset       = lpOffset->LowPart;
	Overlapped.OffsetHigh   = lpOffset->HighPart;
	Overlapped.Internal     = 0;
	Overlapped.InternalHigh = 0;
	if(!ReadFile(hFile, lpBuffer, nNumberOfBytes, NumberOfBytesRead, &Overlapped))
	{
		if((dwError = GetLastError()) == ERROR_IO_PENDING)
		{
			WaitForSingleObject(hEvent, INFINITE);
			if(!GetOverlappedResult(hFile, &Overlapped, NumberOfBytesRead, FALSE))
			{
				dwError = GetLastError();
			}
			else
			{
				dwError = ERROR_SUCCESS;
			}
		}
	}
	ResetEvent(hEvent);
	return dwError;
}

//-------------------------------------------------------------------------------------
//Description:
// This function maps a wide-character string to a new character string
//
//Parameters:
// lpcwszStr: [in] Pointer to the character string to be converted 
// lpszStr: [out] Pointer to a buffer that receives the translated string. 
// dwSize: [in] Size of the buffer
//
//Return Values:
// TRUE: Succeed
// FALSE: Failed
// 
//Example:
// MByteToWChar(szW,szA,sizeof(szA)/sizeof(szA[0]));
//---------------------------------------------------------------------------------------
BOOL WCharToMByte(LPCWSTR lpcwszStr, LPSTR lpszStr, DWORD dwSize)
{
	DWORD dwMinSize;
	dwMinSize = WideCharToMultiByte(CP_OEMCP,NULL,lpcwszStr,-1,NULL,0,NULL,FALSE);
	if(dwSize < dwMinSize)
	{
		return FALSE;
	}
	WideCharToMultiByte(CP_OEMCP,NULL,lpcwszStr,-1,lpszStr,dwSize,NULL,FALSE);
	return TRUE;
}

BOOL QueryDeviceName(CHAR cDriverLetter, PCHAR lpDeviceName)
{
	DWORD  bResult = FALSE;
	HANDLE hDevice = INVALID_HANDLE_VALUE;
	DWORD BytesReturned = 0;
	CHAR VolumeName[] = "\\\\.\\ :";
	VolumeName[4] = cDriverLetter;
	__try
	{
		WCHAR wDeviceName[MAX_PATH];
		CHAR  szDeviceName[MAX_PATH];
		hDevice = CreateFile(VolumeName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDevice == INVALID_HANDLE_VALUE)
		{
			__leave;
		}
		if (!DeviceIoControl(hDevice, IOCTL_QUERY_TW_DEVICE_NAME, NULL, 0, wDeviceName, sizeof(wDeviceName), &BytesReturned, NULL))
		{
			__leave;
		}
		if(!WCharToMByte(wDeviceName, szDeviceName, sizeof(szDeviceName)/sizeof(szDeviceName[0])))
		{
			__leave;	
		}
		lstrcpy(lpDeviceName, szDeviceName);
		bResult = TRUE;
	}
	__finally
	{
		if (hDevice != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hDevice);
		}
	}
	return bResult;
}

BOOL TransformDevicePath(PCHAR GeneralPath, PCHAR DevicePath)
{
	CHAR szDeviceName[MAX_PATH];
	if (!QueryDeviceName(GeneralPath[0], szDeviceName))
	{
		return FALSE;
	}
	strcat(szDeviceName, strchr(GeneralPath, '\\'));
	strcpy(DevicePath, "\\\\.\\");
	strcat(DevicePath, &szDeviceName[strlen("\\DosDevices\\")]);
	return TRUE;
}
/*-------------------------------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------------------------------*/

CFolder::~CFolder()
{
	CloseFolder();
}

void CFolder::CloseFolder()
{
	if (m_IndexFileMap != NULL)
	{
		UnmapViewOfFile(m_IndexFileMap);
		m_IndexFileMap = NULL;
	}
	if (m_hMap != NULL)
	{
		CloseHandle(m_hMap);
		m_hMap = NULL;
	}
	if (m_hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hFile);
		m_hFile = INVALID_HANDLE_VALUE;
	}
	if (m_FileIndexInfo != NULL)
	{
		delete [] m_FileIndexInfo;
		m_FileIndexInfo = NULL;
	}
	if (m_PieceList != NULL)
	{
		delete [] m_PieceList;
		m_PieceList = NULL;
	}
	m_FileListMap.RemoveAll();
}

static int getcount(char* str, char ch)
{
	int n = 0;
	while(*str++ != NULL)
	{
		if((char)*str == ch) {++n;}
	}
	return n;
}

BOOL CFolder::Load(PCHAR Path)
{
	BOOL bResult = TRUE;
	strcpy(m_Path, Path);
	if (m_Path[strlen(m_Path) - 1] != '\\')
	{ 
		strcat(m_Path, "\\");
	}
	if (m_Path[1] != ':' || m_Path[2] != '\\') // 验证路径正确性
	{
		m_LastError = ERROR_INVALID_PARAMETER;
		LOG_ERROR(m_LastError, "CFolder::Load: 输入路径不符合规范", NULL)
		return FALSE;
	}
	if (getcount(m_Path, '\\') < 2) // 验证路径正确性,至少要有2个分割符
	{
		m_LastError = ERROR_INVALID_PARAMETER;
		LOG_ERROR(m_LastError, "CFolder::Load: 输入路径不符合规范", NULL)
		return FALSE;
	}
	m_LastError = ERROR_SUCCESS;
	__try
	{
		ULONG i;
		PBYTE CurOffset;
		ULONG uPieceCount;
		ULONG uPieceTotal;
		LARGE_INTEGER uFileSize;
		BYTE SHABuf[SHA_HASH_LENGTH];
		CHAR szIndexFileName[MAX_PATH];
		strcpy(szIndexFileName, m_Path);
		strcat(szIndexFileName, INDEX_FILE_NAME);
		m_hFile = CreateFile(szIndexFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (m_hFile == INVALID_HANDLE_VALUE)
		{ 
			m_LastError = GetLastError();
			LOG_ERROR(m_LastError, "CFolder::Load: 索引文件打开失败(CreateFile)(%s)", szIndexFileName)
			__leave;
		}
		if (!GetFileSizeEx(m_hFile, &uFileSize) && uFileSize.QuadPart <= sizeof(PACKET_RESERVE)+SHA_HASH_LENGTH)
		{
			m_LastError = GetLastError();
			LOG_ERROR(m_LastError, "CFolder::Load: 获取索引文件大小失败(GetFileSizeEx)(%s)", szIndexFileName)
			__leave;
		}
		m_hMap = CreateFileMapping(m_hFile, NULL, PAGE_READONLY, 0, uFileSize.LowPart, NULL);
		if (m_hMap == NULL)
		{ 
			m_LastError = GetLastError();
			LOG_ERROR(m_LastError, "CFolder::Load: 索引文件映射失败(CreateFileMapping)(%s)", szIndexFileName)
			__leave;
		}
		m_IndexFileMap = (PBYTE)MapViewOfFile(m_hMap, FILE_MAP_READ, 0, 0, 0);
		if (m_IndexFileMap == NULL)
		{ 
			m_LastError = GetLastError();
			LOG_ERROR(m_LastError, "CFolder::Load: 索引文件映射失败(MapViewOfFile)(%s)", szIndexFileName)
			__leave;
		}
		m_IndexFileSize = uFileSize.LowPart;
		Sha1((PCHAR)m_IndexFileMap, (size_t)(uFileSize.LowPart - SHA_HASH_LENGTH), SHABuf);
		if (memcmp(m_IndexFileMap + uFileSize.LowPart - SHA_HASH_LENGTH, SHABuf, SHA_HASH_LENGTH) != 0)
		{
			m_LastError = ERROR_ACCESS_DENIED;
			LOG_ERROR(m_LastError, "CFolder::Load: 索引文件校验失败(%s)", szIndexFileName)
			__leave;
		}
		//比较根目录名称，魔法标志，版本号,目录总大小可以用于进度

		if (
			((PPACKET_RESERVE)m_IndexFileMap)->PacketMagic != PacketMagicFlag  ||
			((PPACKET_RESERVE)m_IndexFileMap)->PacketVersion != CurrentVersion ||
			strstr(m_Path, ((PPACKET_RESERVE)m_IndexFileMap)->RootDirName) == NULL
			)
		{
			m_LastError = ERROR_ACCESS_DENIED;
			LOG_ERROR(m_LastError, "CFolder::Load: 索引文件不匹配(%s)", szIndexFileName)
			__leave;
		}
		strcpy(m_Name, ((PPACKET_RESERVE)m_IndexFileMap)->RootDirName);
		m_FileCount = ((PPACKET_RESERVE)m_IndexFileMap)->PacketFileCount;
		m_FileIndexInfo = new FILE_INDEX_INFO[m_FileCount];
		if (m_FileIndexInfo == NULL)
		{
			m_LastError = ERROR_NOT_ENOUGH_MEMORY;
			LOG_ERROR(m_LastError, "CFolder::Load: 分配内存失败(%s)", m_Path)
			__leave;
		}
		uPieceCount = 0;
		uPieceTotal = 0;
		CurOffset = m_IndexFileMap + sizeof(PACKET_RESERVE);
		for(i = 0; i < m_FileCount; i++)
		{
			m_FileIndexInfo[i].FilePathName = (PCHAR)CurOffset + sizeof(BYTE);
			CurOffset += (sizeof(BYTE) + CurOffset[0] + sizeof('\0')); //要验证文件名长度
			m_FileIndexInfo[i].FileSize = (PLARGE_INTEGER)CurOffset;
			CurOffset += sizeof(LARGE_INTEGER);
			m_FileIndexInfo[i].FileTime = (PFILETIME)CurOffset;
			CurOffset += sizeof(FILETIME);
			m_FileIndexInfo[i].Sha1 = (m_FileIndexInfo[i].FileSize->QuadPart != 0 ? CurOffset : NULL);
			uPieceCount = 	
				(m_FileIndexInfo[i].FileSize->QuadPart/dwPieceSize + (m_FileIndexInfo[i].FileSize->QuadPart%dwPieceSize == 0 ? 0 : 1));
			uPieceTotal += uPieceCount;
			CurOffset += uPieceCount * SHA_HASH_LENGTH;
		}
		m_PieceList = new ULONG[uPieceTotal];
		if (m_PieceList == NULL)
		{
			m_LastError = ERROR_NOT_ENOUGH_MEMORY;
			LOG_ERROR(m_LastError, "CFolder::Load: 分配内存失败(2)(%s)", m_Path)
			__leave;
		}
		m_FileListMap.InitHashTable(m_FileCount, TRUE);
		for(i = 0; i < m_FileCount; i++)
		{
			m_FileListMap[m_FileIndexInfo[i].FilePathName] = &m_FileIndexInfo[i];
		}
	}
	__finally
	{
		if (m_LastError != ERROR_SUCCESS)
		{
			if (m_IndexFileMap != NULL)
			{
				UnmapViewOfFile(m_IndexFileMap);
				m_IndexFileMap = NULL;
			}
			if (m_hMap != NULL)
			{
				CloseHandle(m_hMap);
				m_hMap = NULL;
			}
			if (m_hFile != INVALID_HANDLE_VALUE)
			{
				CloseHandle(m_hFile);
				m_hFile = INVALID_HANDLE_VALUE;
			}
			if (m_FileIndexInfo != NULL)
			{
				delete [] m_FileIndexInfo;
				m_FileIndexInfo = NULL;
			}
			if (m_PieceList != NULL)
			{
				delete [] m_PieceList;
				m_PieceList = NULL;
			}
			bResult = FALSE;
		}
	}
	return bResult;
}

ULONG CFolder::GetLastErrorCode(void)
{
	return m_LastError;
}

void  CFolder::AttachCallBack(PCREATE_PROGRESS_REPORT ReportRoutine, PVOID ReportContext)
{
	m_ReportRoutine = ReportRoutine;
	m_ReportContext = ReportContext;
}

//只比较2个目录中的索引文件,比较其中纪录的文件的时间,大小,和SHA1
PFILE_INDEX_INFO CFolder::CompareWith(CFolder & DestFolder)
{
	PVOID Object;
	PFILE_INDEX_INFO DestFileIndexInfo;
	PFILE_INDEX_INFO SourceFileIndexInfo;
	PFILE_INDEX_INFO lpResult = NULL;
	PULONG PieceList = m_PieceList;
	for(ULONG i = 0; i < m_FileCount; i++)
	{
		SourceFileIndexInfo = &m_FileIndexInfo[i];
		SourceFileIndexInfo->PieceList  = NULL;
		SourceFileIndexInfo->PieceCount = 0;

		if (DestFolder.m_FileListMap.Lookup(SourceFileIndexInfo->FilePathName, Object))
		{
			DestFileIndexInfo = (PFILE_INDEX_INFO)Object;
			//是不是还要先比较时间和大小
			ULONG SourcePieceCount = 
				(SourceFileIndexInfo->FileSize->QuadPart/dwPieceSize + (SourceFileIndexInfo->FileSize->QuadPart%dwPieceSize == 0 ? 0 : 1));
			ULONG DestPieceCount = 
				(DestFileIndexInfo->FileSize->QuadPart/dwPieceSize + (DestFileIndexInfo->FileSize->QuadPart%dwPieceSize == 0 ? 0 : 1));
			for (ULONG j = 0; j < SourcePieceCount; j++) //遍历所有块
			{
				if (j < DestPieceCount) //目标文件中也有这个块,比较它
				{
					if (
						memcmp(SourceFileIndexInfo->Sha1+j*SHA_HASH_LENGTH, DestFileIndexInfo->Sha1+j*SHA_HASH_LENGTH, SHA_HASH_LENGTH) != 0
						)
					{
						PieceList[SourceFileIndexInfo->PieceCount] = j;
						SourceFileIndexInfo->PieceCount++;
					}
				}
				else //目标文件中没这个块
				{
					PieceList[SourceFileIndexInfo->PieceCount] = j;
					SourceFileIndexInfo->PieceCount++;
				}
			}
			if (SourceFileIndexInfo->PieceCount != 0) //这个文件需要拷贝数据
			{
				SourceFileIndexInfo->PieceList = PieceList;
				PieceList += SourceFileIndexInfo->PieceCount;
				SourceFileIndexInfo->FileExist = TRUE; //标志这个文件存在
				SourceFileIndexInfo->RealFileSize = *DestFileIndexInfo->FileSize;//文件实际大小
			}
		}
		else //文件不存在
		{
			ULONG SourcePieceCount = 
				(SourceFileIndexInfo->FileSize->QuadPart/dwPieceSize + (SourceFileIndexInfo->FileSize->QuadPart%dwPieceSize == 0 ? 0 : 1));
			for (ULONG j = 0; j < SourcePieceCount; j++) //遍历所有块
			{
				PieceList[SourceFileIndexInfo->PieceCount] = j;
				SourceFileIndexInfo->PieceCount++;
			}
			SourceFileIndexInfo->PieceList = PieceList;
			PieceList += SourceFileIndexInfo->PieceCount;
			SourceFileIndexInfo->FileExist = FALSE; //标志这个文件不存在
			SourceFileIndexInfo->RealFileSize.QuadPart = 0;//实际大小为0
		}
		if (SourceFileIndexInfo->PieceCount != 0) //这个文件需要拷贝数据
		{
			SourceFileIndexInfo->Next = NULL;
			if (lpResult == NULL)
			{
				lpResult = SourceFileIndexInfo;
			}
			else
			{
				SourceFileIndexInfo->Next = lpResult;
				lpResult = SourceFileIndexInfo;
			}
		}
	}
	return lpResult;
}

//用源目录中的索引文件去校验目标目录中的实际文件(忽略目标目录中的索引文件),比较大小,时间,SHA1
PFILE_INDEX_INFO CFolder::RepairWith(CFolder & DestFolder)
{
	LARGE_INTEGER uProgressCount;
	LARGE_INTEGER uMaxPieceCount;
	PFILE_INDEX_INFO lpResult = NULL;
	PFILE_INDEX_INFO SourceFileIndexInfo = NULL;
	HANDLE hEvent = NULL;
	PVOID DataBuffer = NULL;
	PULONG PieceList = m_PieceList;

	uMaxPieceCount.QuadPart = 0;
	for(ULONG i = 0; i < m_FileCount; i++) //遍历所有文件
	{
		SourceFileIndexInfo = &m_FileIndexInfo[i];
		uMaxPieceCount.QuadPart += (SourceFileIndexInfo->FileSize->QuadPart/dwPieceSize + (SourceFileIndexInfo->FileSize->QuadPart%dwPieceSize == 0 ? 0 : 1));
	}
	__try
	{
		DataBuffer = malloc(dwPieceSize);
		if (DataBuffer == NULL)
		{
			m_LastError = ERROR_NOT_ENOUGH_MEMORY;
			LOG_ERROR(m_LastError, "CFolder::RepairWith: malloc Fail", NULL)
			__leave;
		}
		// 创建文件IO操作的Event
		if((hEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL)
		{
			m_LastError = GetLastError();
			LOG_ERROR(m_LastError, "CFolder::RepairWith: CreateEvent Fail", NULL)
			__leave;
		}
		//开始报告文件校验进度
		m_ReportRoutine(m_ReportContext, CHECKPROGRESS_REPORT_START, m_Name, uMaxPieceCount);
		uProgressCount.QuadPart = 0; //计数清0
		for(ULONG i = 0; i < m_FileCount; i++) //遍历所有文件
		{
			HANDLE hFile = INVALID_HANDLE_VALUE;
			ULONG SourcePieceCount = 0;
			CHAR szFilePath[MAX_PATH];
			__try
			{
				SourceFileIndexInfo = &m_FileIndexInfo[i];
				SourceFileIndexInfo->PieceList  = NULL;
				SourceFileIndexInfo->PieceCount = 0;

				//计算这个文件有多少个块
				SourcePieceCount = (SourceFileIndexInfo->FileSize->QuadPart/dwPieceSize + (SourceFileIndexInfo->FileSize->QuadPart%dwPieceSize == 0 ? 0 : 1));

				strcpy(szFilePath, DestFolder.m_Path);
				strcat(szFilePath, SourceFileIndexInfo->FilePathName);

				if((hFile = CreateFile(szFilePath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED, NULL)) == INVALID_HANDLE_VALUE)
				{	//文件打开失败,或者不存在
					for (ULONG j = 0; j < SourcePieceCount; j++) //遍历所有块
					{
						PieceList[SourceFileIndexInfo->PieceCount] = j;
						SourceFileIndexInfo->PieceCount++;
						//报告文件校验进度
						uProgressCount.QuadPart++;
						m_ReportRoutine(m_ReportContext, CHECKPROGRESS_REPORT_DISP, SourceFileIndexInfo->FilePathName, uProgressCount);
					}
					SourceFileIndexInfo->FileExist = FALSE; //标志这个文件不存在
					SourceFileIndexInfo->RealFileSize.QuadPart = 0;//实际大小为0
				}
				else	//文件打开成功
				{
					FILETIME FileTime;
					LARGE_INTEGER FileSize;
					if (
						GetFileSizeEx(hFile, &FileSize) && GetFileTime(hFile, NULL, NULL, &FileTime) &&
						SourceFileIndexInfo->FileSize->QuadPart == FileSize.QuadPart &&
						SourceFileIndexInfo->FileTime->dwLowDateTime == FileTime.dwLowDateTime &&
						SourceFileIndexInfo->FileTime->dwHighDateTime == FileTime.dwHighDateTime
						)
					{
						//报告文件校验进度
						uProgressCount.QuadPart += SourcePieceCount;
						m_ReportRoutine(m_ReportContext, CHECKPROGRESS_REPORT_DISP, SourceFileIndexInfo->FilePathName, uProgressCount);

						continue; //这个文件的文件时间和文件大小都和纪录的一样,就认为这个文件不需要更新
					}
					//比较这个文件哪些块需要更新
					for (ULONG j = 0; j < SourcePieceCount; j++) //遍历所有块,判断哪些块要更新
					{
						BYTE Sha1Buf[128]; 
						ULONG NumberOfBytesRead;
						LARGE_INTEGER ByteOffset;
						ByteOffset.QuadPart = j * dwPieceSize;
						m_LastError = FileOverlapRead (hFile, DataBuffer, &ByteOffset, dwPieceSize, &NumberOfBytesRead, hEvent);
						if (m_LastError == ERROR_SUCCESS)
						{
							Sha1((PCHAR)DataBuffer, NumberOfBytesRead, Sha1Buf);
							if (memcmp(Sha1Buf, SourceFileIndexInfo->Sha1+j*SHA_HASH_LENGTH, SHA_HASH_LENGTH) != 0)
							{
								PieceList[SourceFileIndexInfo->PieceCount] = j;
								SourceFileIndexInfo->PieceCount++;
							}
						}
						else
						{
							PieceList[SourceFileIndexInfo->PieceCount] = j;
							SourceFileIndexInfo->PieceCount++;
						}
						//报告文件校验进度
						uProgressCount.QuadPart ++;
						m_ReportRoutine(m_ReportContext, CHECKPROGRESS_REPORT_DISP, SourceFileIndexInfo->FilePathName, uProgressCount);
					}
					if (SourceFileIndexInfo->PieceCount != 0) //这个文件需要拷贝数据
					{
						SourceFileIndexInfo->FileExist = TRUE;			//标志这个文件存在
						SourceFileIndexInfo->RealFileSize = FileSize;	//文件实际大小
					}
				}
				if (SourceFileIndexInfo->PieceCount != 0) //这个文件需要拷贝数据
				{
					SourceFileIndexInfo->PieceList = PieceList;
					PieceList += SourceFileIndexInfo->PieceCount;

					SourceFileIndexInfo->Next = NULL;
					if (lpResult == NULL)
					{
						lpResult = SourceFileIndexInfo;
					}
					else
					{
						SourceFileIndexInfo->Next = lpResult;
						lpResult = SourceFileIndexInfo;
					}
				}
			}
			__finally
			{
				if (hFile != INVALID_HANDLE_VALUE)
				{
					CloseHandle(hFile);
				}
			}
		}
		m_ReportRoutine(m_ReportContext, PROGRESS_REPORT_END, NULL, LARGE_INTEGER());
	}
	__finally
	{
		if (hEvent != NULL)
		{
			CloseHandle(hEvent);
		}
		if (DataBuffer != NULL)
		{
			free(DataBuffer);
		}
	}
	return lpResult;
}

//直接将所有文件链起来,用于完全拷贝文件,不做任何比较工作
PFILE_INDEX_INFO CFolder::ParseWith()
{
	PFILE_INDEX_INFO SourceFileIndexInfo;
	PFILE_INDEX_INFO lpResult = NULL;
	PULONG PieceList = m_PieceList;
	for(ULONG i = 0; i < m_FileCount; i++)
	{
		SourceFileIndexInfo = &m_FileIndexInfo[i];
		SourceFileIndexInfo->PieceList  = NULL;
		SourceFileIndexInfo->PieceCount = 0;
		{
			ULONG SourcePieceCount = 
				(SourceFileIndexInfo->FileSize->QuadPart/dwPieceSize + (SourceFileIndexInfo->FileSize->QuadPart%dwPieceSize == 0 ? 0 : 1));
			for (ULONG j = 0; j < SourcePieceCount; j++) //遍历所有块
			{
				PieceList[SourceFileIndexInfo->PieceCount] = j;
				SourceFileIndexInfo->PieceCount++;
			}
			SourceFileIndexInfo->PieceList = PieceList;
			PieceList += SourceFileIndexInfo->PieceCount;
		}
		if (SourceFileIndexInfo->PieceCount != 0) //这个文件需要拷贝数据
		{
			SourceFileIndexInfo->Next = NULL;
			if (lpResult == NULL)
			{
				lpResult = SourceFileIndexInfo;
			}
			else
			{
				SourceFileIndexInfo->Next = lpResult;
				lpResult = SourceFileIndexInfo;
			}
			SourceFileIndexInfo->FileExist = TRUE; //标志这个文件存在
			SourceFileIndexInfo->RealFileSize = *SourceFileIndexInfo->FileSize;//文件实际大小
		}
	}
	return lpResult;
}

bool createMultipleDirectory(const char* pszDir)
{
	std::string strDir(pszDir);//存放要创建的目录字符串
	std::vector<std::string> vPath;//存放每一层目录字符串
	std::string strTemp;//一个临时变量,存放目录字符串
	bool bSuccess = false;//成功标志

	std::string::const_iterator sIter;//定义字符串迭代器
	//遍历要创建的字符串
	for (sIter = strDir.begin(); sIter != strDir.end(); sIter++) {
		if (*sIter != '\\') {//如果当前字符不是'\\'
			strTemp += (*sIter);
		} else {//如果当前字符是'\\'
			vPath.push_back(strTemp);//将当前层的字符串添加到数组中
			strTemp += '\\';
		}
	}

	//遍历存放目录的数组,创建每层目录
	std::vector<std::string>::const_iterator vIter;
	for (vIter = vPath.begin(); vIter != vPath.end(); vIter++) {
		//如果CreateDirectory执行成功,返回true,否则返回false
		bSuccess = CreateDirectory(vIter->c_str(), NULL) ? true : false;    
	}

	return bSuccess;
}

BOOL CFolder::CopyTo(CFolder & DestFolder, UPDATE_TYPE UpdateType)
{
	int i;
	LARGE_INTEGER uProgressSize;
	LARGE_INTEGER uFileSize;
	PFILE_INDEX_INFO FileIndexInfo = NULL;
	HANDLE hEvent = NULL;
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestFile   = INVALID_HANDLE_VALUE;
	HANDLE hDestTWFile = INVALID_HANDLE_VALUE;
	PVOID DataBuffer   = NULL;
	BOOL bThroughWrite = FALSE;
	ULONG FileCount   = 0; // 有多少个文件需要操作
	ULONG uPieceTotal = 0; // 所有文件中要操作的块的总和
	PFILE_INDEX_INFO InfoHead = NULL;
	CHAR DevicePath[MAX_PATH];
	CHAR SourceFilePath[MAX_PATH];
	CHAR DestFilePath[MAX_PATH];
	CHAR DestFileTWPath[MAX_PATH];
	if (
		strstr(m_Path, DestFolder.m_Path) != NULL ||
		strstr(DestFolder.m_Path, m_Path) != NULL
		)
	{
		m_LastError = ERROR_ACCESS_DENIED;
		CHAR szErrorMsg[512];
		wsprintf(szErrorMsg, "(%s)(%s)", m_Path, DestFolder.m_Path);
		LOG_ERROR(m_LastError, "CFolder::CopyTo: 路径重叠 %s", szErrorMsg)
		return FALSE;
	}
	switch(UpdateType)
	{
	case SNAPSHOT_UPDATE:
		if (stricmp(m_Name, DestFolder.m_Name) != 0)
		{
			m_LastError = ERROR_ACCESS_DENIED;
			CHAR szErrorMsg[512];
			wsprintf(szErrorMsg, "(%s)(%s)", m_Name, DestFolder.m_Name);
			LOG_ERROR(m_LastError, "CFolder::CopyTo: 快照目录不符 %s", szErrorMsg)
			return FALSE;
		}
		InfoHead = CompareWith(DestFolder);	//对比索引文件更新
		break;
	case REPAIR_UPDATE:
		InfoHead = RepairWith(DestFolder);	//修复更新(拿源目录中的索引文件去验证目标目录中的文件)
	    break;
	case DIRECT_UPDATE:
		InfoHead = ParseWith();				//直接更新(完全拷贝)
		break;
	}
	__try
	{
		// 创建文件IO操作的Event
		if((hEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL)
		{
			m_LastError = GetLastError();
			LOG_ERROR(m_LastError, "CFolder::CopyTo: CreateEvent Fail", NULL)
			__leave;
		}
		if (InfoHead == NULL) //2个目录里面文件什么都一样,不需要拷贝
		{
			m_LastError = ERROR_SUCCESS;
			LOG_ERROR(m_LastError, "CFolder::CopyTo:目录完全相同,不需要拷贝", NULL)
			goto __CopyIndexFile;
		}
		for (FileIndexInfo = InfoHead; FileIndexInfo != NULL; FileIndexInfo = FileIndexInfo->Next) //统计有多少文件需要更新,一共有多少个块需要更新
		{
			FileCount++;
			uPieceTotal += FileIndexInfo->PieceCount;
		}
		DataBuffer = malloc(dwPieceSize);
		if (DataBuffer == NULL)
		{
			m_LastError = ERROR_NOT_ENOUGH_MEMORY;
			LOG_ERROR(m_LastError, "CFolder::CopyTo: malloc Fail", NULL)
			__leave;
		}
		bThroughWrite = TransformDevicePath(DestFolder.m_Path, DevicePath); //转换为穿透写路径
		{	//准备报告进度
			LARGE_INTEGER uMaxSize;
			uMaxSize.QuadPart = uPieceTotal;
			m_ReportRoutine(m_ReportContext, PROGRESS_REPORT_START, m_Name, uMaxSize);
		}
		uProgressSize.QuadPart = 0; //进度大小清0
		for (FileIndexInfo = InfoHead; FileIndexInfo != NULL; FileIndexInfo = FileIndexInfo->Next) //遍历要写的所有文件
		{
			strcpy(SourceFilePath, m_Path);
			strcat(SourceFilePath, FileIndexInfo->FilePathName);
			strcpy(DestFilePath, DestFolder.m_Path);
			strcat(DestFilePath, FileIndexInfo->FilePathName);
			if (bThroughWrite) //如果穿透写
			{
				strcpy(DestFileTWPath, DevicePath);
				strcat(DestFileTWPath, FileIndexInfo->FilePathName);
			}
			__try
			{
				if((hSourceFile = CreateFile(SourceFilePath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED, NULL)) == INVALID_HANDLE_VALUE)
				{
					m_LastError = GetLastError();
					LOG_ERROR(m_LastError, "CFolder::CopyTo: CreateFile[S](%s)", SourceFilePath)
					__leave;
				}
				createMultipleDirectory(DestFilePath);
				if((hDestFile = CreateFile(DestFilePath, GENERIC_WRITE|GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED, NULL)) == INVALID_HANDLE_VALUE)
				{
					m_LastError = GetLastError();
					LOG_ERROR(m_LastError, "CFolder::CopyTo: CreateFile[D](%s)", DestFilePath)
					__leave;
				}
				if (bThroughWrite) //如果穿透写
				{
					createMultipleDirectory(DestFileTWPath);
					if((hDestTWFile = CreateFile(DestFileTWPath, GENERIC_WRITE|GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED, NULL)) == INVALID_HANDLE_VALUE)
					{
						m_LastError = GetLastError();
						LOG_ERROR(m_LastError, "CFolder::CopyTo: CreateFile[TW](%s)", DestFileTWPath)
						__leave;
					}
				}
				if (!GetFileSizeEx(hDestFile, &uFileSize))
				{
					m_LastError = GetLastError();
					LOG_ERROR(m_LastError, "CFolder::CopyTo: GetFileSizeEx(%s)", DestFilePath)
					__leave;
				}
				if (uFileSize.QuadPart > FileIndexInfo->FileSize->QuadPart)
				{
					SetFileSize(hDestFile, FileIndexInfo->FileSize); //文件长的就要截断
				}
				if (bThroughWrite) //如果穿透写
				{
					if (!GetFileSizeEx(hDestTWFile, &uFileSize))
					{
						m_LastError = GetLastError();
						LOG_ERROR(m_LastError, "CFolder::CopyTo: GetFileSizeEx(%s)", DestFileTWPath)
						__leave;
					}
					if (uFileSize.QuadPart > FileIndexInfo->FileSize->QuadPart)
					{
						SetFileSize(hDestTWFile, FileIndexInfo->FileSize); //文件长的就要截断
					}
				}
				for (i = 0; i < FileIndexInfo->PieceCount; i++) //遍历单个文件中要操作的所有块
				{
					ULONG NumberOfBytesRead;
					LARGE_INTEGER ByteOffset;
					ByteOffset.QuadPart = FileIndexInfo->PieceList[i] * dwPieceSize;
					m_LastError = FileOverlapRead (hSourceFile, DataBuffer, &ByteOffset, dwPieceSize, &NumberOfBytesRead, hEvent);
					if (m_LastError != ERROR_SUCCESS)
					{
						LOG_ERROR(m_LastError, "CFolder::CopyTo: FileOverlapRead(%s)", SourceFilePath)
						__leave;
					}
					m_LastError = FileOverlapWrite (hDestFile, DataBuffer, &ByteOffset, NumberOfBytesRead, hEvent);
					if (m_LastError != ERROR_SUCCESS)
					{
						LOG_ERROR(m_LastError, "CFolder::CopyTo: FileOverlapWrite(%s)", DestFilePath)
						__leave;
					}
					if (bThroughWrite) //如果穿透写
					{
						m_LastError = FileOverlapWrite (hDestTWFile, DataBuffer, &ByteOffset, NumberOfBytesRead, hEvent);
						if (m_LastError != ERROR_SUCCESS)
						{
							LOG_ERROR(m_LastError, "CFolder::CopyTo: FileOverlapWrite(%s)", DestFileTWPath)
							__leave;
						}
					}
					//报告进度
					uProgressSize.QuadPart ++;
					m_ReportRoutine(m_ReportContext, PROGRESS_REPORT_DISP, FileIndexInfo->FilePathName, uProgressSize);
				}
				SetFileTime(hDestFile, NULL, NULL, FileIndexInfo->FileTime);
				if (bThroughWrite) //如果穿透写
				{
					SetFileTime(hDestTWFile, NULL, NULL, FileIndexInfo->FileTime);
				}
			}
			__finally
			{
				if (hSourceFile != INVALID_HANDLE_VALUE)
				{
					CloseHandle(hSourceFile);
					hSourceFile = INVALID_HANDLE_VALUE;
				}
				if (hDestFile != INVALID_HANDLE_VALUE)
				{
					CloseHandle(hDestFile);
					hDestFile = INVALID_HANDLE_VALUE;
				}
				if (bThroughWrite) //如果穿透写
				{
					if (hDestTWFile != INVALID_HANDLE_VALUE)
					{
						CloseHandle(hDestTWFile);
						hDestTWFile = INVALID_HANDLE_VALUE;
					}
				}
				if (m_LastError != ERROR_SUCCESS)
				{
					__leave;
				}
			}
		}
		//结束报告进度
		m_ReportRoutine(m_ReportContext, PROGRESS_REPORT_END, NULL, LARGE_INTEGER());
__CopyIndexFile:
		////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// 最后还要拷贝索引文件
		DestFolder.CloseFolder();
		strcpy(DestFilePath, DestFolder.m_Path);
		strcat(DestFilePath, INDEX_FILE_NAME);
		if (bThroughWrite) //如果穿透写
		{
			strcpy(DestFileTWPath, DevicePath);
			strcat(DestFileTWPath, INDEX_FILE_NAME);
		}
		if((hDestFile = CreateFile(DestFilePath, GENERIC_WRITE|GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED, NULL)) == INVALID_HANDLE_VALUE)
		{
			m_LastError = GetLastError();
			LOG_ERROR(m_LastError, "CFolder::CopyTo: CreateFile[D](%s)", DestFilePath)
			__leave;
		}
		if (bThroughWrite) //如果穿透写
		{
			if((hDestTWFile = CreateFile(DestFileTWPath, GENERIC_WRITE|GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED, NULL)) == INVALID_HANDLE_VALUE)
			{
				m_LastError = GetLastError();
				LOG_ERROR(m_LastError, "CFolder::CopyTo: CreateFile[TW](%s)", DestFileTWPath)
				__leave;
			}
		}
		uFileSize.QuadPart = m_IndexFileSize;
		for (i = 0; uFileSize.QuadPart != 0; i++)
		{
			ULONG NumberOfBytesWrite;
			LARGE_INTEGER ByteOffset;
			ByteOffset.QuadPart = i * dwPieceSize;
			NumberOfBytesWrite = (uFileSize.QuadPart >= dwPieceSize ? dwPieceSize : uFileSize.QuadPart);
			m_LastError = FileOverlapWrite (hDestFile, m_IndexFileMap+i*dwPieceSize, &ByteOffset, NumberOfBytesWrite, hEvent);
			if (m_LastError != ERROR_SUCCESS)
			{
				LOG_ERROR(m_LastError, "CFolder::CopyTo: FileOverlapWrite(%s)", DestFilePath)
				__leave;
			}
			if (bThroughWrite) //如果穿透写
			{
				m_LastError = FileOverlapWrite (hDestTWFile, m_IndexFileMap+i*dwPieceSize, &ByteOffset, NumberOfBytesWrite, hEvent);
				if (m_LastError != ERROR_SUCCESS)
				{
					LOG_ERROR(m_LastError, "CFolder::CopyTo: FileOverlapWrite(%s)", DestFileTWPath)
					__leave;
				}
			}
			uFileSize.QuadPart -= NumberOfBytesWrite;
		}
	}
	__finally
	{
		if (hSourceFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hSourceFile);
		}
		if (hDestFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hDestFile);
		}
		if (bThroughWrite) //如果穿透写
		{
			if (hDestTWFile != INVALID_HANDLE_VALUE)
			{
				CloseHandle(hDestTWFile);
			}
		}
		if (hEvent != NULL)
		{
			CloseHandle(hEvent);
		}
		if (DataBuffer != NULL)
		{
			free(DataBuffer);
		}
	}
	if (m_LastError == ERROR_SUCCESS)
	{
		return TRUE;
	}
	return FALSE;
}

BOOL CFolder::PacketCheck(CFolder & DestFolder, PPACKET_CHECK_INFO * PacketCheckInfo)
{
	PFILE_INDEX_INFO InfoHead = RepairWith(DestFolder);	//拿源目录中的索引文件去验证目标目录中的文件
	if (InfoHead == NULL)
	{
		*PacketCheckInfo = NULL;
		return TRUE;
	}
	ULONG FileCount = 0;
	PFILE_INDEX_INFO FileIndexInfo = NULL;
	for (FileIndexInfo = InfoHead; FileIndexInfo != NULL; FileIndexInfo = FileIndexInfo->Next) //统计有多少文件
	{
		FileCount++;
	}
	PPACKET_CHECK_INFO PacketCheckInfoPreHead = NULL;
	PPACKET_CHECK_INFO PacketCheckInfoHead = (PPACKET_CHECK_INFO)malloc(sizeof(PACKET_CHECK_INFO) * FileCount);
	*PacketCheckInfo = PacketCheckInfoHead;
	for (FileIndexInfo = InfoHead; FileIndexInfo != NULL; FileIndexInfo = FileIndexInfo->Next, PacketCheckInfoHead++)
	{
		if (PacketCheckInfoPreHead != NULL)
		{
			PacketCheckInfoPreHead->Next = PacketCheckInfoHead;
		}
		strcpy(PacketCheckInfoHead->FileName, FileIndexInfo->FilePathName);
		PacketCheckInfoHead->FileSize = *FileIndexInfo->FileSize;
		PacketCheckInfoHead->RealFileSize = FileIndexInfo->RealFileSize;
		PacketCheckInfoHead->FileExist = FileIndexInfo->FileExist;
		PacketCheckInfoHead->uPieceCount = FileIndexInfo->PieceCount;
		PacketCheckInfoHead->Next = NULL;
		PacketCheckInfoPreHead = PacketCheckInfoHead;
	}
	return TRUE;
}

void CFolder::PacketCheckEnd(PPACKET_CHECK_INFO PacketCheckInfo)
{
	if (PacketCheckInfo != NULL)
	{
		free(PacketCheckInfo);
	}
}
