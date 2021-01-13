/*++

Module Name:

	FsFilter_final.c

Abstract:

	This is the main module of the FsFilter1 miniFilter driver.

Environment:

	Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <wdm.h>
#include <stdlib.h>

#include <string.h>
#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;
#define MAX_LEN 40000
#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))


#define PROCESS_POOL_TAG 'XmeM'

typedef struct access_model
{
	wchar_t proc[100];
	wchar_t number[100];
	wchar_t File_name[100];
} ACCESS;

ACCESS access_array[1024];
int id = 0;

/*************************************************************************
	Prototypes
*************************************************************************/

EXTERN_C_START
typedef NTSTATUS(*QUERY_INFO_PROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

QUERY_INFO_PROCESS ZwQueryInformationProcess;

NTSTATUS InitZwQueryInformationProcess()
{
	if (!ZwQueryInformationProcess) {
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");

		// ignore pointer to function pointer conversion warning
#pragma warning(push)
#pragma warning(disable: 4055)
		ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
#pragma warning(pop)
	}
	return !ZwQueryInformationProcess ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath

);

NTSTATUS
FsFilter1InstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
FsFilter1InstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
FsFilter1InstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
FsFilter1Unload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
FsFilter1InstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
FsFilter1PreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

VOID
FsFilter1OperationStatusCallback(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
	_In_ NTSTATUS OperationStatus,
	_In_ PVOID RequesterContext
);

FLT_POSTOP_CALLBACK_STATUS
FsFilter1PostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
FsFilter1PreOperationNoPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
ReadOnlyPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
WriteOnlyPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
ReadOnlyPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_POSTOP_CALLBACK_STATUS
WriteOnlyPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

BOOLEAN
FsFilter1DoRequestOperationStatus(
	_In_ PFLT_CALLBACK_DATA Data
);

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FsFilter1Unload)
#pragma alloc_text(PAGE, FsFilter1InstanceQueryTeardown)
#pragma alloc_text(PAGE, FsFilter1InstanceSetup)
#pragma alloc_text(PAGE, FsFilter1InstanceTeardownStart)
#pragma alloc_text(PAGE, FsFilter1InstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

	{ IRP_MJ_READ,
      0,
      ReadOnlyPreOperation,
      ReadOnlyPostOperation },

	{ IRP_MJ_WRITE,
	  0,
	  WriteOnlyPreOperation,
	  WriteOnlyPostOperation },

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	NULL,                               //  Context
	Callbacks,                          //  Operation callbacks

	FsFilter1Unload,                           //  MiniFilterUnload

	FsFilter1InstanceSetup,                    //  InstanceSetup
	FsFilter1InstanceQueryTeardown,            //  InstanceQueryTeardown
	FsFilter1InstanceTeardownStart,            //  InstanceTeardownStart
	FsFilter1InstanceTeardownComplete,         //  InstanceTeardownComplete

	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};

NTSTATUS
FsFilter1InstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
/*++

Routine Description:

	This routine is called whenever a new instance is created on a volume. This
	gives us a chance to decide if we need to attach to this volume or not.

	If this routine is not defined in the registration structure, automatic
	instances are always created.

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance and its associated volume.

	Flags - Flags describing the reason for this attach request.

Return Value:

	STATUS_SUCCESS - attach
	STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FsFilter1!FsFilter1InstanceSetup: Entered\n"));

	return STATUS_SUCCESS;
}

NTSTATUS
FsFilter1InstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

	This is called when an instance is being manually deleted by a
	call to FltDetachVolume or FilterDetach thereby giving us a
	chance to fail that detach request.

	If this routine is not defined in the registration structure, explicit
	detach requests via FltDetachVolume or FilterDetach will always be
	failed.

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance and its associated volume.

	Flags - Indicating where this detach request came from.

Return Value:

	Returns the status of this operation.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FsFilter1!FsFilter1InstanceQueryTeardown: Entered\n"));

	return STATUS_SUCCESS;
}


VOID
FsFilter1InstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

	This routine is called at the start of instance teardown.

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance and its associated volume.

	Flags - Reason why this instance is being deleted.

Return Value:

	None.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FsFilter1!FsFilter1InstanceTeardownStart: Entered\n"));
}


VOID
FsFilter1InstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

	This routine is called at the end of instance teardown.

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance and its associated volume.

	Flags - Reason why this instance is being deleted.

Return Value:

	None.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FsFilter1!FsFilter1InstanceTeardownComplete: Entered\n"));
}


/*************************************************************************
	MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
Readconfigfromfile()
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES Attributes;
	HANDLE File_1;
	UNICODE_STRING FileName;
	IO_STATUS_BLOCK IOStatusBlock;
	LARGE_INTEGER ByteOffset;

	char Buffer[1024];
	char AmountOfProcessesTempBuffer[20];
	memset(Buffer, 0, 1024);
	memset(AmountOfProcessesTempBuffer, 0, 20);
	ByteOffset.LowPart = ByteOffset.HighPart = 0;

	DbgPrint("======== READING FILE CONFIGURATION ========\n");

	RtlInitUnicodeString(&FileName, L"\\SystemRoot\\conf.txt");
	InitializeObjectAttributes(&Attributes, &FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;
	status = ZwCreateFile(&File_1, GENERIC_READ, &Attributes, &IOStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (status == STATUS_SUCCESS)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "before ZwReadFile");
		status = ZwReadFile(File_1, NULL, NULL, NULL, &IOStatusBlock, Buffer, 1024, &ByteOffset, NULL);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "after ZwReadFile");

		if (NT_SUCCESS(status))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ZwReadFile success");
			int i1 = 0;
			unsigned int n = 0;
			while (Buffer[i1] != '\0')
			{
				if (Buffer[i1] == '\n')
				{
					n++;
				}
				i1++;
			}
			n++;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "AmountOfProcesses: %u\n", n);

			int i = 0;
			for (int j = 0; j < n; j++)
			{
				int k = 0;

				/* считываем имя процесса */
				while (Buffer[i] != ' ')
				{
					access_array[j].File_name[k] = Buffer[i];
					i = i + 1;
					k = k + 1;
				}

				/* пропускаем пробел */
				i = i + 1;
				k = 0;

				/* переходим к считыванию роли процесса */
				while (Buffer[i] != ' ')
				{
					access_array[j].proc[k] = Buffer[i];
					i = i + 1;
					k = k + 1;
				}

				/* считываем права доступа */
				i = i + 1;
				k = 0;
				while (!(Buffer[i] == '\n' || Buffer[i] == '\0'))
				{
					access_array[j].number[k] = Buffer[i];
					i = i + 1;
					k = k + 1;
				}
				/* если данная строка - не последняя для считывания, переходим на следующую строку */
				if (j != n - 1)
				{
					i = i + 1;
				}

				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Readconfigfromfile Results: \nFile_name: %ws,\nProc: %ws,\nNumber: %ws\n", access_array[j].File_name, access_array[j].proc, access_array[j].number);
			}
			id = n;
			ZwClose(File_1);
		}
		else
		{
			DbgPrint("ZwReadFile failed");
			ZwClose(File_1);
			return STATUS_UNSUCCESSFUL;
		}
	}
	else
	{
		DbgPrint("ZwCreateFile failed");
		ZwClose(File_1);
		return STATUS_UNSUCCESSFUL;
	}

	return status;
}

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

	This is the initialization routine for this miniFilter driver.  This
	registers with FltMgr and initializes all global data structures.

Arguments:

	DriverObject - Pointer to driver object created by the system to
		represent this driver.

	RegistryPath - Unicode string identifying where the parameters for this
		driver are located in the registry.

Return Value:

	Routine can return non success error codes.

--*/
{
	NTSTATUS status;
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "=======START OF ENTRY========");
	status = Readconfigfromfile();
	if (status == STATUS_UNSUCCESSFUL)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("DriverEntry: Error with the GetProcessesRolesInformation\n"));
		return status;
	}

	UNREFERENCED_PARAMETER(RegistryPath);
	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FsFilter1!DriverEntry: Entered\n"));

	//
	//  Register with FltMgr to tell it our callback routines
	//

	status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&gFilterHandle);
	DbgPrint("After FltRegisterFilter");
	FLT_ASSERT(NT_SUCCESS(status));

	if (NT_SUCCESS(status)) {
		//
		//  Start filtering i/o
		//
		DbgPrint("Start filtering i/o");
		status = FltStartFiltering(gFilterHandle);
		if (!NT_SUCCESS(status)) {
			DbgPrint("!NT_SUCCESS(status) after FltStartFiltering");
			FltUnregisterFilter(gFilterHandle);
		}
	}
	DbgPrint("==============END OF ENTRY============");
	return status;
}

NTSTATUS
FsFilter1Unload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
/*++

Routine Description:

	This is the unload routine for this miniFilter driver. This is called
	when the minifilter is about to be unloaded. We can fail this unload
	request if this is not a mandatory unload indicated by the Flags
	parameter.

Arguments:

	Flags - Indicating if this is a mandatory unload.

Return Value:

	Returns STATUS_SUCCESS.

--*/
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FsFilter1Unload: Entered\n"));

	FltUnregisterFilter(gFilterHandle);

	return STATUS_SUCCESS;
}


/*************************************************************************
	MiniFilter callback routines.
*************************************************************************/

FLT_PREOP_CALLBACK_STATUS
FsFilter1PreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

	This routine is a pre-operation dispatch routine for this miniFilter.

	This is non-pageable because it could be called on the paging path

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	CompletionContext - The context for the completion routine for this
		operation.

Return Value:

	The return value is the status of the operation.

--*/
{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FsFilter1PreOperation: Entered\n"));

	//
	//  See if this is an operation we would like the operation status
	//  for.  If so request it.
	//
	//  NOTE: most filters do NOT need to do this.  You only need to make
	//        this call if, for example, you need to know if the oplock was
	//        actually granted.
	//

	if (FsFilter1DoRequestOperationStatus(Data)) {

		status = FltRequestOperationStatusCallback(Data,
			FsFilter1OperationStatusCallback,
			(PVOID)(++OperationStatusCtx));
		if (!NT_SUCCESS(status)) {

			PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
				("FsFilter1PreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
					status));
		}
	}

	// This template code does not do anything with the callbackData, but
	// rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
	// This passes the request down to the next miniFilter in the chain.

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

VOID
FsFilter1OperationStatusCallback(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
	_In_ NTSTATUS OperationStatus,
	_In_ PVOID RequesterContext
)
/*++

Routine Description:

	This routine is called when the given operation returns from the call
	to IoCallDriver.  This is useful for operations where STATUS_PENDING
	means the operation was successfully queued.  This is useful for OpLocks
	and directory change notification operations.

	This callback is called in the context of the originating thread and will
	never be called at DPC level.  The file object has been correctly
	referenced so that you can access it.  It will be automatically
	dereferenced upon return.

	This is non-pageable because it could be called on the paging path

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	RequesterContext - The context for the completion routine for this
		operation.

	OperationStatus -

Return Value:

	The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FsFilter1OperationStatusCallback: Entered\n"));

	PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
		("FsFilter1OperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
			OperationStatus,
			RequesterContext,
			ParameterSnapshot->MajorFunction,
			ParameterSnapshot->MinorFunction,
			FltGetIrpName(ParameterSnapshot->MajorFunction)));
}


FLT_POSTOP_CALLBACK_STATUS
FsFilter1PostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

	This routine is the post-operation completion routine for this
	miniFilter.

	This is non-pageable because it may be called at DPC level.

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	CompletionContext - The completion context set in the pre-operation routine.

	Flags - Denotes whether the completion is successful or is being drained.

Return Value:

	The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FsFilter1PostOperation: Entered\n"));

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
FsFilter1PreOperationNoPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

	This routine is a pre-operation dispatch routine for this miniFilter.

	This is non-pageable because it could be called on the paging path

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	CompletionContext - The context for the completion routine for this
		operation.

Return Value:

	The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FsFilter1PreOperationNoPostOperation: Entered\n"));

	// This template code does not do anything with the callbackData, but
	// rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
	// This passes the request down to the next miniFilter in the chain.

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
FsFilter1DoRequestOperationStatus(
	_In_ PFLT_CALLBACK_DATA Data
)
/*++

Routine Description:

	This identifies those operations we want the operation status for.  These
	are typically operations that return STATUS_PENDING as a normal completion
	status.

Arguments:

Return Value:

	TRUE - If we want the operation status
	FALSE - If we don't

--*/
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

	//
	//  return boolean state based on which operations we are interested in
	//

	return (BOOLEAN)

		//
		//  Check for oplock operations
		//

		(((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
		((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
			(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
			(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
			(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

			||

			//
			//    Check for directy change notification
			//

			((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
			(iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
			);
}

PUNICODE_STRING
DuplicateUnicodeString(PUNICODE_STRING sourceString) {
	PUNICODE_STRING resultString;

	resultString = ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING) + sourceString->MaximumLength, PROCESS_POOL_TAG);
	if (!resultString) {
		DbgPrint("DuplicateUnicodeString: memory allocation error");
		return NULL;
	}

	resultString->Length = sourceString->Length;
	resultString->MaximumLength = sourceString->MaximumLength;
	resultString->Buffer = (PWCH) & ((PUCHAR)resultString)[sizeof(UNICODE_STRING)];

	RtlCopyMemory(resultString->Buffer, sourceString->Buffer, sourceString->MaximumLength);

	return resultString;
}

PUNICODE_STRING
GetVolumeNameFromPath(PUNICODE_STRING kernelPath) {
	PUNICODE_STRING volumeName;

	volumeName = DuplicateUnicodeString(kernelPath);
	if (!volumeName) {
		DbgPrint("GetVolumeNameFromPath: memory allocation error");
		return NULL;
	}

	// search for 3rd slash in path \Device\HarddiskVolume4\... and cut the rest to get only volume name
	USHORT index = 0;
	int len = volumeName->Length / sizeof(WCHAR);
	int slashCount = 3;
	while (index < len) {
		if (volumeName->Buffer[index] == '\\') {
			if (--slashCount == 0) {
				volumeName->Buffer[index] = 0;
				volumeName->Length = index * sizeof(WCHAR);
				return volumeName;
			}
		}
		index++;
	}

	ExFreePoolWithTag(volumeName, PROCESS_POOL_TAG);
	return NULL;
}

PUNICODE_STRING
GetDosPathFromKernelPath(PUNICODE_STRING kernelPath) {
	PDEVICE_OBJECT diskDeviceObject;
	UNICODE_STRING volumeDosDrive;
	WCHAR volumeDosDriveBuffer[128];
	PFLT_VOLUME volumeObject;
	NTSTATUS status;
	PUNICODE_STRING volumeName, dosPath;
	RtlInitUnicodeString(&volumeDosDrive, NULL);
	volumeDosDrive.Length = 0;
	volumeDosDrive.MaximumLength = sizeof(volumeDosDriveBuffer);
	volumeDosDrive.Buffer = &volumeDosDriveBuffer[0];

	dosPath = DuplicateUnicodeString(kernelPath);
	if (!dosPath) return NULL;

	volumeName = GetVolumeNameFromPath(kernelPath);
	if (volumeName) {
		status = FltGetVolumeFromName(gFilterHandle, volumeName, &volumeObject);
		if (NT_SUCCESS(status)) {

			status = FltGetDiskDeviceObject(volumeObject, &diskDeviceObject);
			if (NT_SUCCESS(status)) {

				status = IoVolumeDeviceToDosName(diskDeviceObject, &volumeDosDrive);
				if (NT_SUCCESS(status)) {

					int srcOffset = volumeName->Length / sizeof(WCHAR);
					int dstOffset = volumeDosDrive.Length / sizeof(WCHAR);

					int sizeToMove = (dosPath->Length - volumeName->Length);

					RtlMoveMemory(&dosPath->Buffer[dstOffset], &dosPath->Buffer[srcOffset], sizeToMove);
					RtlCopyMemory(dosPath->Buffer, volumeDosDrive.Buffer, volumeDosDrive.Length);

					dosPath->Length -= (USHORT)((srcOffset - dstOffset) * sizeof(WCHAR));

					ObDereferenceObject(diskDeviceObject);
					FltObjectDereference(volumeObject);
					ExFreePoolWithTag(volumeName, PROCESS_POOL_TAG);
					RtlFreeUnicodeString(&volumeDosDrive);
					return dosPath;
				}
				else {
					DbgPrint("IoVolumeDeviceToDosName error %08X\n", status);
				}
				ObDereferenceObject(diskDeviceObject);
			}
			else {
				DbgPrint("FltGetDiskDeviceObject error %08X\n", status);
			}
			FltObjectDereference(volumeObject);
		}
		else {
			DbgPrint("FltGetVolumeFromName error %08X\n", status);
		}
		ExFreePoolWithTag(volumeName, PROCESS_POOL_TAG);
	}
	ExFreePoolWithTag(dosPath, PROCESS_POOL_TAG);
	return NULL;
}

NTSTATUS GetProcessImageName(PEPROCESS eProcess, PUNICODE_STRING* ProcessImageName)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG returnedLength;
	HANDLE hProcess = NULL;

	PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

	if (eProcess == NULL)
	{
		return STATUS_INVALID_PARAMETER_1;
	}

	status = ObOpenObjectByPointer(eProcess,
		0, NULL, 0, 0, KernelMode, &hProcess);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ObOpenObjectByPointer Failed: %08x\n", status);
		return status;
	}

	if (ZwQueryInformationProcess == NULL)
	{
		UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");

		ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

		if (ZwQueryInformationProcess == NULL)
		{
			DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
			status = STATUS_UNSUCCESSFUL;
			ZwClose(hProcess);
			return status;
		}
	}

	/* Query the actual size of the process path */
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		NULL, // buffer
		0,    // buffer size
		&returnedLength);

	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		DbgPrint("ZwQueryInformationProcess status = %x\n", status);
		ZwClose(hProcess);
		return status;
	}

	*ProcessImageName = ExAllocatePoolWithTag(NonPagedPoolNx, returnedLength, '2gat');

	if (ProcessImageName == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		ZwClose(hProcess);
		return status;
	}

	/* Retrieve the process path from the handle to the process */
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		*ProcessImageName,
		returnedLength,
		&returnedLength);

	if (!NT_SUCCESS(status))
		ExFreePoolWithTag(*ProcessImageName, '2gat');

	ZwClose(hProcess);
	return status;
}

PUNICODE_STRING
GetProcessFileName()
{
	NTSTATUS status;

	if (NT_SUCCESS(InitZwQueryInformationProcess())) {
		try {

			PEPROCESS peProcess = IoGetCurrentProcess();
			HANDLE hObjectProcess;
			OBJECT_ATTRIBUTES   objectAttributes;
			CLIENT_ID           ClientID;
			ULONG returnedLength;
			PUNICODE_STRING processFileName;
			PUNICODE_STRING processDosFileName;

			InitializeObjectAttributes(&objectAttributes, 0, OBJ_KERNEL_HANDLE, 0, 0);
			ClientID.UniqueProcess = PsGetProcessId(peProcess);
			ClientID.UniqueThread = 0;
			status = ZwOpenProcess(&hObjectProcess,
				0x0400,
				&objectAttributes,
				&ClientID);

			if (!NT_SUCCESS(status)) {
				DbgPrint("GetProcessFileName: ZwOpenProcess failed: %08X\n", status);
				return NULL;
			}

			status = ZwQueryInformationProcess(hObjectProcess, ProcessImageFileName, NULL, 0, &returnedLength);
			if (status == STATUS_INFO_LENGTH_MISMATCH) {

				processFileName = ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING) + returnedLength, PROCESS_POOL_TAG);
				if (processFileName) {
					status = ZwQueryInformationProcess(hObjectProcess, ProcessImageFileName, processFileName, returnedLength, &returnedLength);
					if (NT_SUCCESS(status)) {
						ZwClose(hObjectProcess);

						processDosFileName = GetDosPathFromKernelPath(processFileName);
						if (processDosFileName) {
							ExFreePoolWithTag(processFileName, PROCESS_POOL_TAG);
							return processDosFileName;
						}
						return processFileName;
					}
					ExFreePoolWithTag(processFileName, PROCESS_POOL_TAG);
				}
			}
			ZwClose(hObjectProcess);
		}
		except(EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("GetProcessFileName: EXCEPTION - %08x\n", GetExceptionCode());
		}
	}
	return NULL;
}

FLT_PREOP_CALLBACK_STATUS
ReadOnlyPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	DbgPrint("===========ReadOnlyPreOpearation");
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	try {

		status = FltGetFileNameInformation(Data,
			FLT_FILE_NAME_NORMALIZED |
			FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
			&nameInfo);
		if (NT_SUCCESS(status))

		{

			status = FltParseFileNameInformation(nameInfo);

			for (int i = 0; i < id; i++)
			{
				if (wcsncmp(nameInfo->Name.Buffer, access_array[i].File_name, wcslen(access_array[i].File_name)) == 0)
				{
					DbgPrint("======Successfull File_name wcsncmp");
					PUNICODE_STRING FullPath = NULL; // будет содержать путь процесса, который совершает действие

					/* получаем имя процесса, инициировавшего операцию (IoThreadToProcess позволяет получить по callback data->thread процесс) */
					GetProcessImageName(IoThreadToProcess(Data->Thread), &FullPath);

					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Buffer: %ws\n", FullPath->Buffer);
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "access_array[].proc: %ws\n", access_array[i].proc);

					if (wcscmp(FullPath->Buffer, access_array[i].proc) == 0)
					{
						DbgPrint("======Successfull proc wcsncmp");
						DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "access_array[].number[1]: %wc\n", access_array[i].number[1]);

						if (access_array[i].number[1] == '1')
						{
							DbgPrint("===========number[1] is equal 1============");
							Data->IoStatus.Status = STATUS_ACCESS_DENIED;

							/* завершаем работу */
							return FLT_PREOP_COMPLETE;
						}
					}
				}

			}
		}
	}
	except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("PtPreOperationPassThrough: EXCEPTION - %08x\n", GetExceptionCode());
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
WriteOnlyPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	DbgPrint("============WriteOnlyPreOp");
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	try {

		status = FltGetFileNameInformation(Data,
			FLT_FILE_NAME_NORMALIZED |
			FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
			&nameInfo);
		
		if (NT_SUCCESS(status))

		{

			status = FltParseFileNameInformation(nameInfo);

			for (int i = 0; i < id; i++)
			{
				if (wcsncmp(nameInfo->Name.Buffer, access_array[i].File_name, wcslen(access_array[i].File_name)) == 0)
				{
					DbgPrint("===========Successfull File_name wcsncmp");
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "FileNameInfo->Name.Buffer: %ws\n", nameInfo->Name.Buffer);

					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
						("FileNameInfo->Name.Buffer: %ws\n", nameInfo->Name.Buffer));
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
						("FileNameInfo->Volume.Buffer: %ws\n", nameInfo->Volume.Buffer));
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
						("FileNameInfo->FinalComponent.Buffer: %ws\n", nameInfo->FinalComponent.Buffer));
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
						("FileNameInfo->ParentDir.Buffer: %ws\n", nameInfo->ParentDir.Buffer));


					PUNICODE_STRING FullPath = NULL; // будет содержать путь процесса, который совершает действие

					/* получаем имя процесса, инициировавшего операцию (IoThreadToProcess позволяет получить по callback data->thread процесс) */
					GetProcessImageName(IoThreadToProcess(Data->Thread), &FullPath);

					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Buffer: %ws\n", FullPath->Buffer);
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "access_array[].proc: %ws\n", access_array[i].proc);

					if (wcscmp(FullPath->Buffer, access_array[i].proc) == 0)
					{
						DbgPrint("===========Successfull proc wcsncmp");
						DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "access_array[].number: %wc\n", access_array[i].number[0]);


						if (access_array[i].number[0] == '1')
						{
							DbgPrint("======number[0] is equal 1=======");
							Data->IoStatus.Status = STATUS_ACCESS_DENIED;

							/* завершаем работу */
							return FLT_PREOP_COMPLETE;
						}
					}
				}

			}
		}
	}
	except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("PtPreOperationPassThrough: EXCEPTION - %08x\n", GetExceptionCode());
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
ReadOnlyPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
WriteOnlyPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}
