// stdafx.cpp : 只包括标准包含文件的源文件
// DiskLib.pch 将作为预编译头
// stdafx.obj 将包含预编译类型信息

#include "stdafx.h"

// TODO: 在 STDAFX.H 中
// 引用任何所需的附加头文件，而不是在此文件中引用

BOOL g_bIsWriteErrlog = TRUE;

void WriteErrorLogFile(ULONG uError, PCHAR ErrorText, PCHAR ErrorSubText)
{
	CHAR       szErrorMessage[1024];
	CHAR       szErrorText[128];
	CHAR       szTime[64];
	CHAR       szFilePath[MAX_PATH];
	DWORD      dwByteOfWritten;
	SYSTEMTIME stSystemTime;
	PCHAR      x;
	HANDLE     hFile;
	if (!g_bIsWriteErrlog)
	{
		return;
	}
	GetModuleFileName(NULL, szFilePath, sizeof(szFilePath));
	x = strrchr(szFilePath, '\\') + 1;
	*x = 0;
	lstrcat(szFilePath, "__DiskLib__.txt");
	hFile = CreateFile(szFilePath, GENERIC_WRITE|GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return;
	}
	GetLocalTime(&stSystemTime);
	wsprintf(szTime, "%u-%02u-%02u %02u:%02u:%02u", stSystemTime.wYear, stSystemTime.wMonth, stSystemTime.wDay, stSystemTime.wHour, stSystemTime.wMinute, stSystemTime.wSecond);
	SetFilePointer(hFile, 0, NULL, FILE_END);
	wsprintf(szErrorText, ErrorText, ErrorSubText);
	wsprintf(szErrorMessage, "%s  ErrorCode: %5u  %s\r\n", szTime, uError, szErrorText);
	WriteFile(hFile, szErrorMessage, lstrlen(szErrorMessage), &dwByteOfWritten, NULL);
	CloseHandle(hFile);
}
