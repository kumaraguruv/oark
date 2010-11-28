/*
Copyright (c) <2010> <Dreg aka David Reguera Garcia, dreg@fr33project.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/


///////////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2010 - <company name here>
///
/// Original filename: oark_driver.cpp
/// Project          : oark_driver
/// Date of creation : 2010-11-12
/// Author(s)        : <author name(s)>
///
/// Purpose          : <description>
///
/// Revisions:
///  0000 [2010-11-12] Initial revision.
///
///////////////////////////////////////////////////////////////////////////////

// $Id$

#ifdef __cplusplus
extern "C" {
#endif
#include <ntddk.h>
#include <string.h>
#ifdef __cplusplus
}; // extern "C"
#endif

#include "oark_driver.h"
#include "common.h"

#ifdef __cplusplus
namespace { // anonymous namespace to limit the scope of this global variable!
#endif
PDRIVER_OBJECT pdoGlobalDrvObj = 0;
#ifdef __cplusplus
}; // anonymous namespace
#endif

int WriteUserMode( void * address, DWORD size, void * data )
{
	NTSTATUS Status;
	PMDL mdl;

	mdl = IoAllocateMdl( address, size,  FALSE, FALSE, NULL );
	if( mdl )
	{         
			MmProbeAndLockPages( mdl, UserMode, IoWriteAccess );

		address = MmGetSystemAddressForMdlSafe( mdl, NormalPagePriority );

		if(!address) {
			MmUnlockPages( mdl );
			IoFreeMdl( mdl );
			goto out;          
		}

		memcpy( address, data, size );

		MmUnlockPages( mdl );
		IoFreeMdl( mdl );  
	}

	return 0;

	out:
		return -1;
}

NTSTATUS OARKDRIVER_DispatchCreateClose(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PIRP					Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS OARKDRIVER_DispatchDeviceControl(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PIRP					Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	READ_KERN_MEM_t      read_kern_mem;
	void               * ptrdat;
	IDTR                 idtr;
	PEPROCESS eprocess;
	NTSTATUS retf;
	
    switch(irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case OARK_IOCTL_CHANGE_MODE:
		DbgPrint( " IOCTL!\n" );
        if( irpSp->Parameters.DeviceIoControl.InputBufferLength != sizeof( READ_KERN_MEM_t ) ) 
				break;

		read_kern_mem =  * ( (READ_KERN_MEM_t *) Irp->AssociatedIrp.SystemBuffer );

		switch ( read_kern_mem.type )
		{
				case SYM_TYP_KPCR:
					/* 
						Comment by Dreg:

						FS points to KPCR:

						1: kd> dt nt!_KPCR
						   +0x000 NtTib            : _NT_TIB
						   +0x01c SelfPcr          : Ptr32 _KPCR
						   ..

						Then FS:[0x1C] points to KPCR, then GDT[FS] (0x30) == FS:[0x1C]
					*/
					__asm 
					{ 
						MOV EAX, FS:[0x1C] 
						MOV ptrdat, EAX 
					}

					DbgPrint( " FS0: 0x%08X\n", ptrdat );
				break;

				case SYM_TYP_IDT:
					__asm { sidt idtr }

					ptrdat = & idtr;

					
					DbgPrint( " IDT 0x%08X\n", MAKEDWORD( idtr.baseAddressLow, idtr.baseAddressHi ) );
				break;

				case SYM_TYP_NULL:
					ptrdat = read_kern_mem.src_address;
					DbgPrint( " Reading... 0x%08X\n", ptrdat );
				break;

				case SYM_TYP_PSLOUPRBYID:
					 retf = PsLookupProcessByProcessId( (HANDLE) read_kern_mem.src_address, & eprocess );
					 ptrdat = & eprocess;
					 if( retf != STATUS_SUCCESS )
						eprocess = NULL;
				break;

				case SYM_TYP_OBDEREFOBJ:
					ObDereferenceObject( read_kern_mem.src_address );

					ptrdat = NULL;
				break;

				default:
					ptrdat = NULL;
				break;
			}

			if ( ptrdat != NULL )
				WriteUserMode( read_kern_mem.dst_address, read_kern_mem.size, ptrdat );
			
			Irp->IoStatus.Status = STATUS_SUCCESS;

        break;
    default:
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        break;
    }

    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID OARKDRIVER_DriverUnload(
    IN PDRIVER_OBJECT		DriverObject
    )
{
    PDEVICE_OBJECT pdoNextDeviceObj = pdoGlobalDrvObj->DeviceObject;
    IoDeleteSymbolicLink(&usSymlinkName);

    // Delete all the device objects
    while(pdoNextDeviceObj)
    {
        PDEVICE_OBJECT pdoThisDeviceObj = pdoNextDeviceObj;
        pdoNextDeviceObj = pdoThisDeviceObj->NextDevice;
        IoDeleteDevice(pdoThisDeviceObj);
    }

	DbgPrint( " drv unloaded!\n" );
}

#ifdef __cplusplus
extern "C" {
#endif
NTSTATUS DriverEntry(
    IN OUT PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING      RegistryPath
    )
{
    PDEVICE_OBJECT pdoDeviceObj = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    pdoGlobalDrvObj = DriverObject;

	DbgPrint( " drv entry!\n" );

    // Create the device object.
    if(!NT_SUCCESS(status = IoCreateDevice(
        DriverObject,
        0,
        &usDeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        TRUE,
        &pdoDeviceObj
        )))
    {
        // Bail out (implicitly forces the driver to unload).
        return status;
    };

    // Now create the respective symbolic link object
    if(!NT_SUCCESS(status = IoCreateSymbolicLink(
        &usSymlinkName,
        &usDeviceName
        )))
    {
        IoDeleteDevice(pdoDeviceObj);
        return status;
    }

    // NOTE: You need not provide your own implementation for any major function that
    //       you do not want to handle. I have seen code using DDKWizard that left the
    //       *empty* dispatch routines intact. This is not necessary at all!
    DriverObject->MajorFunction[IRP_MJ_CREATE] =
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = OARKDRIVER_DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OARKDRIVER_DispatchDeviceControl;
    DriverObject->DriverUnload = OARKDRIVER_DriverUnload;

	DbgPrint( " drv loaded!\n" );

    return STATUS_SUCCESS;
}
#ifdef __cplusplus
}; // extern "C"
#endif
