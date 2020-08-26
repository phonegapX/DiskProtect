#ifndef _HOOKDISK_H_
#define _HOOKDISK_H_

NTSTATUS SWHookDiskMajorRouter(ULONG uRandom);
NTSTATUS SWCallOldDiskWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp);

extern BOOLEAN bDisableAccess;
extern ULONG uSessionID;

#endif
