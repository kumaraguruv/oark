///////////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2010 - <company name here>
///
/// Original filename: oark_driver.h
/// Project          : oark_driver
/// Date of creation : <see oark_driver.cpp>
/// Author(s)        : <see oark_driver.cpp>
///
/// Purpose          : <see oark_driver.cpp>
///
/// Revisions:         <see oark_driver.cpp>
///
///////////////////////////////////////////////////////////////////////////////

// $Id$

#ifndef __OARKDRIVER_H_VERSION__
#define __OARKDRIVER_H_VERSION__ 100

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif


#include "drvcommon.h"
#include "drvversion.h"

#define DEVICE_NAME			"\\Device\\OARKDRIVER_DeviceName"
#define SYMLINK_NAME		"\\DosDevices\\OARKDRIVER_DeviceName"
PRESET_UNICODE_STRING(usDeviceName, DEVICE_NAME);
PRESET_UNICODE_STRING(usSymlinkName, SYMLINK_NAME);

#ifndef FILE_DEVICE_OARKDRIVER
#define FILE_DEVICE_OARKDRIVER 0x8000
#endif

// Values defined for "Method"
// METHOD_BUFFERED
// METHOD_IN_DIRECT
// METHOD_OUT_DIRECT
// METHOD_NEITHER
// 
// Values defined for "Access"
// FILE_ANY_ACCESS
// FILE_READ_ACCESS
// FILE_WRITE_ACCESS

const ULONG IOCTL_OARKDRIVER_OPERATION = CTL_CODE(FILE_DEVICE_OARKDRIVER, 0x01, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA);

#endif // __OARKDRIVER_H_VERSION__
