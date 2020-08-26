#ifndef _STD_H_
#define _STD_H_

#include <ntddk.h>
#include <ntdddisk.h>
#include <srb.h>
#include <stdio.h>

typedef unsigned char BYTE;
typedef BYTE *PBYTE;
typedef unsigned short WORD;

#include "common.h"

#define dwBytesOfKilo					1024
#define dwBytesOfMega					(dwBytesOfKilo*dwBytesOfKilo)
#define dwBytesOfGiga					(dwBytesOfMega*dwBytesOfKilo)
#define dwImageFileIncrementBlockSize	(256*dwBytesOfMega)
#define dwNodeBlockSize					(128*dwBytesOfKilo)

NTSYSAPI ULONG NTAPI RtlRandom(PULONG Seed);
NTKERNELAPI PDEVICE_OBJECT IoGetAttachedDevice(IN PDEVICE_OBJECT DeviceObject);
NTKERNELAPI NTSTATUS ObQueryNameString(IN PVOID Object, OUT POBJECT_NAME_INFORMATION ObjectNameInfo, IN ULONG Length, OUT PULONG ReturnLength);

#endif
