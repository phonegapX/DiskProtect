#ifndef _COMMON_H_
#define _COMMON_H_

#define dwBytesPerSectore				512
#define dwConfigDataSectorOffset		0x6000
#define MagicFlag						"BOOST"

#pragma pack(push, 1)

typedef union _PROTECT_CONFIG_DATA //(sizeof=0x200)
{
	struct
	{
		CHAR Magic[5];	//BOOST
		BYTE IsProtectC;
		BYTE IsProtectE;
		CHAR Password[32];
		CHAR Reserve[469];
		ULONG uKey;
	};
	CHAR ByteOf[dwBytesPerSectore];
} PROTECT_CONFIG_DATA, *PPROTECT_CONFIG_DATA;

#pragma pack(pop)

#define ENCRYPT_DECODE_DATA(ConfData)													\
{																						\
	PPROTECT_CONFIG_DATA __InnerProtect_Config_Data_ = ConfData;						\
	ULONG __Inner_uKey_ = __InnerProtect_Config_Data_->uKey;							\
	ULONG __Inner_Count_ = sizeof(__InnerProtect_Config_Data_->ByteOf) / sizeof(ULONG);	\
	PULONG __Inner_Data_Addr = (PULONG)__InnerProtect_Config_Data_->ByteOf;				\
	ULONG __Inner_i_;																	\
	__Inner_Count_--;																	\
	for (__Inner_i_ = 0;__Inner_i_ < __Inner_Count_; __Inner_i_++)						\
	{																					\
		__Inner_Data_Addr[__Inner_i_] = __Inner_Data_Addr[__Inner_i_] ^ __Inner_uKey_;	\
	}																					\
}

#define IOCTL_GET_SESSION_ID			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x310, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PASSWORD				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x311, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_PASSWORD				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x312, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROTECT_STATE			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x313, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_PROTECT_STATE			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x314, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENABLE_THROUGH_WRITE		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x315, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISABLE_THROUGH_WRITE		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x316, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_TW_DEVICE_NAME		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x317, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PARAM_MAGIC_COOKIE				'  DK'

#pragma pack(push, 1)

typedef struct _PARAM_GET_SESSION_ID
{
	ULONG Magic;
	ULONG uSessionID;
} PARAM_GET_SESSION_ID, *PPARAM_GET_SESSION_ID;

typedef struct _PARAM_GET_PASSWORD
{
	ULONG Magic;
	ULONG uSessionID;
	CHAR  Password[32];
} PARAM_GET_PASSWORD, *PPARAM_GET_PASSWORD;

typedef struct _PARAM_SET_PASSWORD
{
	ULONG Magic;
	ULONG uSessionID;
	CHAR  OrgPassword[32];
	CHAR  NewPassword[32];
} PARAM_SET_PASSWORD, *PPARAM_SET_PASSWORD;

typedef struct _PARAM_GET_PROTECT_STATE
{
	ULONG Magic;
	ULONG uSessionID;
	CHAR  Password[32];
	BYTE  ProtectC;
	BYTE  ProtectE;
} PARAM_GET_PROTECT_STATE, *PPARAM_GET_PROTECT_STATE;

typedef struct _PARAM_SET_PROTECT_STATE
{
	ULONG Magic;
	ULONG uSessionID;
	CHAR  Password[32];
	BYTE  ProtectC;
	BYTE  ProtectE;
} PARAM_SET_PROTECT_STATE, *PPARAM_SET_PROTECT_STATE;

typedef struct _PARAM_ENABLE_TW
{
	ULONG Magic;
	ULONG uSessionID;
	CHAR  Password[32];
} PARAM_ENABLE_TW, *PPARAM_ENABLE_TW;

typedef struct _PARAM_DISABLE_TW
{
	ULONG Magic;
	ULONG uSessionID;
	CHAR  Password[32];
} PARAM_DISABLE_TW, *PPARAM_DISABLE_TW;

#pragma pack(pop)

#endif
