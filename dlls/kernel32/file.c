/*
 * File handling functions
 *
 * Copyright 1993 John Burton
 * Copyright 1996, 2004 Alexandre Julliard
 * Copyright 2008 Jeff Zaroyko
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>

#define NONAMELESSUNION
#define NONAMELESSSTRUCT
#include "winerror.h"
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "winioctl.h"
#include "wincon.h"
#include "ddk/ntddk.h"
#include "kernel_private.h"
#include "fileapi.h"
#include "shlwapi.h"

#include "wine/exception.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(file);

/***********************************************************************
 *              create_file_OF
 *
 * Wrapper for CreateFile that takes OF_* mode flags.
 */
static HANDLE create_file_OF( LPCSTR path, INT mode )
{
    DWORD access, sharing, creation;

    if (mode & OF_CREATE)
    {
        creation = CREATE_ALWAYS;
        access = GENERIC_READ | GENERIC_WRITE;
    }
    else
    {
        creation = OPEN_EXISTING;
        switch(mode & 0x03)
        {
        case OF_READ:      access = GENERIC_READ; break;
        case OF_WRITE:     access = GENERIC_WRITE; break;
        case OF_READWRITE: access = GENERIC_READ | GENERIC_WRITE; break;
        default:           access = 0; break;
        }
    }

    switch(mode & 0x70)
    {
    case OF_SHARE_EXCLUSIVE:  sharing = 0; break;
    case OF_SHARE_DENY_WRITE: sharing = FILE_SHARE_READ; break;
    case OF_SHARE_DENY_READ:  sharing = FILE_SHARE_WRITE; break;
    case OF_SHARE_DENY_NONE:
    case OF_SHARE_COMPAT:
    default:                  sharing = FILE_SHARE_READ | FILE_SHARE_WRITE; break;
    }
    return CreateFileA( path, access, sharing, NULL, creation, FILE_ATTRIBUTE_NORMAL, 0 );
}


/***********************************************************************
 *           FILE_name_AtoW
 *
 * Convert a file name to Unicode, taking into account the OEM/Ansi API mode.
 *
 * If alloc is FALSE uses the TEB static buffer, so it can only be used when
 * there is no possibility for the function to do that twice, taking into
 * account any called function.
 */
WCHAR *FILE_name_AtoW( LPCSTR name, BOOL alloc )
{
    ANSI_STRING str;
    UNICODE_STRING strW, *pstrW;
    NTSTATUS status;

    RtlInitAnsiString( &str, name );
    pstrW = alloc ? &strW : &NtCurrentTeb()->StaticUnicodeString;
    if (!AreFileApisANSI())
        status = RtlOemStringToUnicodeString( pstrW, &str, alloc );
    else
        status = RtlAnsiStringToUnicodeString( pstrW, &str, alloc );
    if (status == STATUS_SUCCESS) return pstrW->Buffer;

    if (status == STATUS_BUFFER_OVERFLOW)
        SetLastError( ERROR_FILENAME_EXCED_RANGE );
    else
        SetLastError( RtlNtStatusToDosError(status) );
    return NULL;
}


/***********************************************************************
 *           FILE_name_WtoA
 *
 * Convert a file name back to OEM/Ansi. Returns number of bytes copied.
 */
DWORD FILE_name_WtoA( LPCWSTR src, INT srclen, LPSTR dest, INT destlen )
{
    DWORD ret;

    if (srclen < 0) srclen = lstrlenW( src ) + 1;
    if (!destlen)
    {
        if (!AreFileApisANSI())
        {
            UNICODE_STRING strW;
            strW.Buffer = (WCHAR *)src;
            strW.Length = srclen * sizeof(WCHAR);
            ret = RtlUnicodeStringToOemSize( &strW ) - 1;
        }
        else
            RtlUnicodeToMultiByteSize( &ret, src, srclen * sizeof(WCHAR) );
    }
    else
    {
        if (!AreFileApisANSI())
            RtlUnicodeToOemN( dest, destlen, &ret, src, srclen * sizeof(WCHAR) );
        else
            RtlUnicodeToMultiByteN( dest, destlen, &ret, src, srclen * sizeof(WCHAR) );
    }
    return ret;
}


/***********************************************************************
 *           _hread   (KERNEL32.@)
 */
LONG WINAPI _hread( HFILE hFile, LPVOID buffer, LONG count)
{
    return _lread( hFile, buffer, count );
}


/***********************************************************************
 *           _hwrite   (KERNEL32.@)
 *
 *	experimentation yields that _lwrite:
 *		o truncates the file at the current position with
 *		  a 0 len write
 *		o returns 0 on a 0 length write
 *		o works with console handles
 *
 */
LONG WINAPI _hwrite( HFILE handle, LPCSTR buffer, LONG count )
{
    DWORD result;

    TRACE("%d %p %d\n", handle, buffer, count );

    if (!count)
    {
        /* Expand or truncate at current position */
        if (!SetEndOfFile( LongToHandle(handle) )) return HFILE_ERROR;
        return 0;
    }
    if (!WriteFile( LongToHandle(handle), buffer, count, &result, NULL ))
        return HFILE_ERROR;
    return result;
}


/***********************************************************************
 *           _lclose   (KERNEL32.@)
 */
HFILE WINAPI _lclose( HFILE hFile )
{
    TRACE("handle %d\n", hFile );
    return CloseHandle( LongToHandle(hFile) ) ? 0 : HFILE_ERROR;
}


/***********************************************************************
 *           _lcreat   (KERNEL32.@)
 */
HFILE WINAPI _lcreat( LPCSTR path, INT attr )
{
    HANDLE hfile;

    /* Mask off all flags not explicitly allowed by the doc */
    attr &= FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
    TRACE("%s %02x\n", path, attr );
    hfile = CreateFileA( path, GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               CREATE_ALWAYS, attr, 0 );
    return HandleToLong(hfile);
}


/***********************************************************************
 *           _lopen   (KERNEL32.@)
 */
HFILE WINAPI _lopen( LPCSTR path, INT mode )
{
    HANDLE hfile;

    TRACE("(%s,%04x)\n", debugstr_a(path), mode );
    hfile = create_file_OF( path, mode & ~OF_CREATE );
    return HandleToLong(hfile);
}

/***********************************************************************
 *           _lread   (KERNEL32.@)
 */
UINT WINAPI _lread( HFILE handle, LPVOID buffer, UINT count )
{
    DWORD result;
    if (!ReadFile( LongToHandle(handle), buffer, count, &result, NULL ))
        return HFILE_ERROR;
    return result;
}


/***********************************************************************
 *           _llseek   (KERNEL32.@)
 */
LONG WINAPI _llseek( HFILE hFile, LONG lOffset, INT nOrigin )
{
    return SetFilePointer( LongToHandle(hFile), lOffset, NULL, nOrigin );
}


/***********************************************************************
 *           _lwrite   (KERNEL32.@)
 */
UINT WINAPI _lwrite( HFILE hFile, LPCSTR buffer, UINT count )
{
    return (UINT)_hwrite( hFile, buffer, (LONG)count );
}


/**************************************************************************
 *           SetFileCompletionNotificationModes   (KERNEL32.@)
 */
BOOL WINAPI SetFileCompletionNotificationModes( HANDLE file, UCHAR flags )
{
    FILE_IO_COMPLETION_NOTIFICATION_INFORMATION info;
    IO_STATUS_BLOCK io;

    info.Flags = flags;
    return set_ntstatus( NtSetInformationFile( file, &io, &info, sizeof(info),
                                               FileIoCompletionNotificationInformation ));
}


/*************************************************************************
 *           SetHandleCount   (KERNEL32.@)
 */
UINT WINAPI SetHandleCount( UINT count )
{
    return count;
}


/***********************************************************************
 *           DosDateTimeToFileTime   (KERNEL32.@)
 */
BOOL WINAPI DosDateTimeToFileTime( WORD fatdate, WORD fattime, FILETIME *ft )
{
    TIME_FIELDS fields;
    LARGE_INTEGER time;

    fields.Year         = (fatdate >> 9) + 1980;
    fields.Month        = ((fatdate >> 5) & 0x0f);
    fields.Day          = (fatdate & 0x1f);
    fields.Hour         = (fattime >> 11);
    fields.Minute       = (fattime >> 5) & 0x3f;
    fields.Second       = (fattime & 0x1f) * 2;
    fields.Milliseconds = 0;
    if (!RtlTimeFieldsToTime( &fields, &time )) return FALSE;
    ft->dwLowDateTime  = time.u.LowPart;
    ft->dwHighDateTime = time.u.HighPart;
    return TRUE;
}


/***********************************************************************
 *           FileTimeToDosDateTime   (KERNEL32.@)
 */
BOOL WINAPI FileTimeToDosDateTime( const FILETIME *ft, WORD *fatdate, WORD *fattime )
{
    TIME_FIELDS fields;
    LARGE_INTEGER time;

    if (!fatdate || !fattime)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    time.u.LowPart  = ft->dwLowDateTime;
    time.u.HighPart = ft->dwHighDateTime;
    RtlTimeToTimeFields( &time, &fields );
    if (fields.Year < 1980)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    *fattime = (fields.Hour << 11) + (fields.Minute << 5) + (fields.Second / 2);
    *fatdate = ((fields.Year - 1980) << 9) + (fields.Month << 5) + fields.Day;
    return TRUE;
}


/**************************************************************************
 *                      Operations on file names                          *
 **************************************************************************/


/**************************************************************************
 *           ReplaceFileA (KERNEL32.@)
 */
BOOL WINAPI ReplaceFileA(LPCSTR lpReplacedFileName,LPCSTR lpReplacementFileName,
                         LPCSTR lpBackupFileName, DWORD dwReplaceFlags,
                         LPVOID lpExclude, LPVOID lpReserved)
{
    WCHAR *replacedW, *replacementW, *backupW = NULL;
    BOOL ret;

    /* This function only makes sense when the first two parameters are defined */
    if (!lpReplacedFileName || !(replacedW = FILE_name_AtoW( lpReplacedFileName, TRUE )))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!lpReplacementFileName || !(replacementW = FILE_name_AtoW( lpReplacementFileName, TRUE )))
    {
        HeapFree( GetProcessHeap(), 0, replacedW );
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    /* The backup parameter, however, is optional */
    if (lpBackupFileName)
    {
        if (!(backupW = FILE_name_AtoW( lpBackupFileName, TRUE )))
        {
            HeapFree( GetProcessHeap(), 0, replacedW );
            HeapFree( GetProcessHeap(), 0, replacementW );
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    }
    ret = ReplaceFileW( replacedW, replacementW, backupW, dwReplaceFlags, lpExclude, lpReserved );
    HeapFree( GetProcessHeap(), 0, replacedW );
    HeapFree( GetProcessHeap(), 0, replacementW );
    HeapFree( GetProcessHeap(), 0, backupW );
    return ret;
}


/***********************************************************************
 *		OpenVxDHandle (KERNEL32.@)
 *
 *	This function is supposed to return the corresponding Ring 0
 *	("kernel") handle for a Ring 3 handle in Win9x.
 *	Evidently, Wine will have problems with this. But we try anyway,
 *	maybe it helps...
 */
HANDLE WINAPI OpenVxDHandle(HANDLE hHandleRing3)
{
    FIXME( "(%p), stub! (returning Ring 3 handle instead of Ring 0)\n", hHandleRing3);
    return hHandleRing3;
}


/****************************************************************************
 *		DeviceIoControl (KERNEL32.@)
 */
BOOL WINAPI DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode,
                            LPVOID lpvInBuffer, DWORD cbInBuffer,
                            LPVOID lpvOutBuffer, DWORD cbOutBuffer,
                            LPDWORD lpcbBytesReturned,
                            LPOVERLAPPED lpOverlapped)
{
    NTSTATUS status;

    TRACE( "(%p,%x,%p,%d,%p,%d,%p,%p)\n",
           hDevice,dwIoControlCode,lpvInBuffer,cbInBuffer,
           lpvOutBuffer,cbOutBuffer,lpcbBytesReturned,lpOverlapped );

    /* Check if this is a user defined control code for a VxD */

    if (HIWORD( dwIoControlCode ) == 0 && (GetVersion() & 0x80000000))
    {
        typedef BOOL (WINAPI *DeviceIoProc)(DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
        static DeviceIoProc (*vxd_get_proc)(HANDLE);
        DeviceIoProc proc = NULL;

        if (!vxd_get_proc) vxd_get_proc = (void *)GetProcAddress( GetModuleHandleW(L"krnl386.exe16"),
                                                                  "__wine_vxd_get_proc" );
        if (vxd_get_proc) proc = vxd_get_proc( hDevice );
        if (proc) return proc( dwIoControlCode, lpvInBuffer, cbInBuffer,
                               lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped );
    }

    /* Not a VxD, let ntdll handle it */

    if (lpOverlapped)
    {
        LPVOID cvalue = ((ULONG_PTR)lpOverlapped->hEvent & 1) ? NULL : lpOverlapped;
        lpOverlapped->Internal = STATUS_PENDING;
        lpOverlapped->InternalHigh = 0;
        if (HIWORD(dwIoControlCode) == FILE_DEVICE_FILE_SYSTEM)
            status = NtFsControlFile(hDevice, lpOverlapped->hEvent,
                                     NULL, cvalue, (PIO_STATUS_BLOCK)lpOverlapped,
                                     dwIoControlCode, lpvInBuffer, cbInBuffer,
                                     lpvOutBuffer, cbOutBuffer);
        else
            status = NtDeviceIoControlFile(hDevice, lpOverlapped->hEvent,
                                           NULL, cvalue, (PIO_STATUS_BLOCK)lpOverlapped,
                                           dwIoControlCode, lpvInBuffer, cbInBuffer,
                                           lpvOutBuffer, cbOutBuffer);
        if (lpcbBytesReturned) *lpcbBytesReturned = lpOverlapped->InternalHigh;
    }
    else
    {
        IO_STATUS_BLOCK iosb;

        if (HIWORD(dwIoControlCode) == FILE_DEVICE_FILE_SYSTEM)
            status = NtFsControlFile(hDevice, NULL, NULL, NULL, &iosb,
                                     dwIoControlCode, lpvInBuffer, cbInBuffer,
                                     lpvOutBuffer, cbOutBuffer);
        else
            status = NtDeviceIoControlFile(hDevice, NULL, NULL, NULL, &iosb,
                                           dwIoControlCode, lpvInBuffer, cbInBuffer,
                                           lpvOutBuffer, cbOutBuffer);
        if (lpcbBytesReturned) *lpcbBytesReturned = iosb.Information;
    }
    return set_ntstatus( status );
}


/***********************************************************************
 *           OpenFile   (KERNEL32.@)
 */
HFILE WINAPI OpenFile( LPCSTR name, OFSTRUCT *ofs, UINT mode )
{
    HANDLE handle;
    FILETIME filetime;
    WORD filedatetime[2];
    DWORD len;

    if (!ofs) return HFILE_ERROR;

    TRACE("%s %s %s %s%s%s%s%s%s%s%s%s\n",name,
          ((mode & 0x3 )==OF_READ)?"OF_READ":
          ((mode & 0x3 )==OF_WRITE)?"OF_WRITE":
          ((mode & 0x3 )==OF_READWRITE)?"OF_READWRITE":"unknown",
          ((mode & 0x70 )==OF_SHARE_COMPAT)?"OF_SHARE_COMPAT":
          ((mode & 0x70 )==OF_SHARE_DENY_NONE)?"OF_SHARE_DENY_NONE":
          ((mode & 0x70 )==OF_SHARE_DENY_READ)?"OF_SHARE_DENY_READ":
          ((mode & 0x70 )==OF_SHARE_DENY_WRITE)?"OF_SHARE_DENY_WRITE":
          ((mode & 0x70 )==OF_SHARE_EXCLUSIVE)?"OF_SHARE_EXCLUSIVE":"unknown",
          ((mode & OF_PARSE )==OF_PARSE)?"OF_PARSE ":"",
          ((mode & OF_DELETE )==OF_DELETE)?"OF_DELETE ":"",
          ((mode & OF_VERIFY )==OF_VERIFY)?"OF_VERIFY ":"",
          ((mode & OF_SEARCH )==OF_SEARCH)?"OF_SEARCH ":"",
          ((mode & OF_CANCEL )==OF_CANCEL)?"OF_CANCEL ":"",
          ((mode & OF_CREATE )==OF_CREATE)?"OF_CREATE ":"",
          ((mode & OF_PROMPT )==OF_PROMPT)?"OF_PROMPT ":"",
          ((mode & OF_EXIST )==OF_EXIST)?"OF_EXIST ":"",
          ((mode & OF_REOPEN )==OF_REOPEN)?"OF_REOPEN ":""
        );


    ofs->cBytes = sizeof(OFSTRUCT);
    ofs->nErrCode = 0;
    if (mode & OF_REOPEN) name = ofs->szPathName;

    if (!name) return HFILE_ERROR;

    TRACE("%s %04x\n", name, mode );

    /* the watcom 10.6 IDE relies on a valid path returned in ofs->szPathName
       Are there any cases where getting the path here is wrong?
       Uwe Bonnes 1997 Apr 2 */
    len = GetFullPathNameA( name, sizeof(ofs->szPathName), ofs->szPathName, NULL );
    if (!len) goto error;
    if (len >= sizeof(ofs->szPathName))
    {
        SetLastError(ERROR_INVALID_DATA);
        goto error;
    }

    /* OF_PARSE simply fills the structure */

    if (mode & OF_PARSE)
    {
        ofs->fFixedDisk = (GetDriveTypeA( ofs->szPathName ) != DRIVE_REMOVABLE);
        TRACE("(%s): OF_PARSE, res = '%s'\n", name, ofs->szPathName );
        return 0;
    }

    /* OF_CREATE is completely different from all other options, so
       handle it first */

    if (mode & OF_CREATE)
    {
        if ((handle = create_file_OF( name, mode )) == INVALID_HANDLE_VALUE)
            goto error;
    }
    else
    {
        /* Now look for the file */

        len = SearchPathA( NULL, name, NULL, sizeof(ofs->szPathName), ofs->szPathName, NULL );
        if (!len) goto error;
        if (len >= sizeof(ofs->szPathName))
        {
            SetLastError(ERROR_INVALID_DATA);
            goto error;
        }

        TRACE("found %s\n", debugstr_a(ofs->szPathName) );

        if (mode & OF_DELETE)
        {
            if (!DeleteFileA( ofs->szPathName )) goto error;
            TRACE("(%s): OF_DELETE return = OK\n", name);
            return TRUE;
        }

        handle = LongToHandle(_lopen( ofs->szPathName, mode ));
        if (handle == INVALID_HANDLE_VALUE) goto error;

        GetFileTime( handle, NULL, NULL, &filetime );
        FileTimeToDosDateTime( &filetime, &filedatetime[0], &filedatetime[1] );
        if ((mode & OF_VERIFY) && (mode & OF_REOPEN))
        {
            if (ofs->Reserved1 != filedatetime[0] || ofs->Reserved2 != filedatetime[1] )
            {
                CloseHandle( handle );
                WARN("(%s): OF_VERIFY failed\n", name );
                /* FIXME: what error here? */
                SetLastError( ERROR_FILE_NOT_FOUND );
                goto error;
            }
        }
        ofs->Reserved1 = filedatetime[0];
        ofs->Reserved2 = filedatetime[1];
    }
    TRACE("(%s): OK, return = %p\n", name, handle );
    if (mode & OF_EXIST)  /* Return TRUE instead of a handle */
    {
        CloseHandle( handle );
        return TRUE;
    }
    return HandleToLong(handle);

error:  /* We get here if there was an error opening the file */
    ofs->nErrCode = GetLastError();
    WARN("(%s): return = HFILE_ERROR error= %d\n", name,ofs->nErrCode );
    return HFILE_ERROR;
}


/***********************************************************************
 *             OpenFileById (KERNEL32.@)
 */
HANDLE WINAPI OpenFileById( HANDLE handle, LPFILE_ID_DESCRIPTOR id, DWORD access,
                            DWORD share, LPSECURITY_ATTRIBUTES sec_attr, DWORD flags )
{
    UINT options;
    HANDLE result;
    OBJECT_ATTRIBUTES attr;
    NTSTATUS status;
    IO_STATUS_BLOCK io;
    UNICODE_STRING objectName;

    if (!id)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return INVALID_HANDLE_VALUE;
    }

    options = FILE_OPEN_BY_FILE_ID;
    if (flags & FILE_FLAG_BACKUP_SEMANTICS)
        options |= FILE_OPEN_FOR_BACKUP_INTENT;
    else
        options |= FILE_NON_DIRECTORY_FILE;
    if (flags & FILE_FLAG_NO_BUFFERING) options |= FILE_NO_INTERMEDIATE_BUFFERING;
    if (!(flags & FILE_FLAG_OVERLAPPED)) options |= FILE_SYNCHRONOUS_IO_NONALERT;
    if (flags & FILE_FLAG_RANDOM_ACCESS) options |= FILE_RANDOM_ACCESS;
    flags &= FILE_ATTRIBUTE_VALID_FLAGS;

    objectName.Length             = sizeof(ULONGLONG);
    objectName.Buffer             = (WCHAR *)&id->u.FileId;
    attr.Length                   = sizeof(attr);
    attr.RootDirectory            = handle;
    attr.Attributes               = 0;
    attr.ObjectName               = &objectName;
    attr.SecurityDescriptor       = sec_attr ? sec_attr->lpSecurityDescriptor : NULL;
    attr.SecurityQualityOfService = NULL;
    if (sec_attr && sec_attr->bInheritHandle) attr.Attributes |= OBJ_INHERIT;

    status = NtCreateFile( &result, access | SYNCHRONIZE, &attr, &io, NULL, flags,
                           share, OPEN_EXISTING, options, NULL, 0 );
    if (status != STATUS_SUCCESS)
    {
        SetLastError( RtlNtStatusToDosError( status ) );
        return INVALID_HANDLE_VALUE;
    }
    return result;
}

/***********************************************************************
 *             ReOpenFile (KERNEL32.@)
 */
HANDLE WINAPI ReOpenFile(HANDLE handle_original, DWORD access, DWORD sharing, DWORD flags)
{
    FIXME("(%p, %d, %d, %d): stub\n", handle_original, access, sharing, flags);

    return INVALID_HANDLE_VALUE;
}


/***********************************************************************
 *           K32EnumDeviceDrivers (KERNEL32.@)
 */
BOOL WINAPI K32EnumDeviceDrivers(void **image_base, DWORD cb, DWORD *needed)
{
    unsigned int index = 0;
    unsigned int total_bytes;
    void *cur_driver;
    NTSTATUS status;
    
    FIXME("(%p, %d, %p): stub\n", image_base, cb, needed);
    
    while(TRUE)
    {
        SERVER_START_REQ(enum_drivers)
        {
            req->index = index;
            status = wine_server_call( req );
            cur_driver = reply->address;
            index = reply->next;
        }SERVER_END_REQ;

        if(status == STATUS_NO_MORE_ENTRIES) break;
        if( cb < (index * sizeof(void*)) ) continue;
        image_base[index-1] = cur_driver;
    }
    FIXME("index=%u\n", index);
    total_bytes = (index * sizeof(void*));

    if(needed)
        *needed = (DWORD) total_bytes;

    return TRUE;
}

/***********************************************************************
 *          K32GetDeviceDriverBaseNameA (KERNEL32.@)
 */
DWORD WINAPI K32GetDeviceDriverBaseNameA(void *image_base, LPSTR base_name, DWORD size)
{
    FIXME("(%p, %p, %d): stub\n", image_base, base_name, size);

    if (base_name && size)
        base_name[0] = '\0';

    return 0;
}

/***********************************************************************
 *           K32GetDeviceDriverBaseNameW (KERNEL32.@)
 */
DWORD WINAPI K32GetDeviceDriverBaseNameW(void *image_base, LPWSTR base_name, DWORD size)
{
    FIXME("(%p, %p, %d): stub\n", image_base, base_name, size);

    if (base_name && size)
        base_name[0] = '\0';

    return 0;
}

/***********************************************************************
 *           K32GetDeviceDriverFileNameA (KERNEL32.@)
 */
DWORD WINAPI K32GetDeviceDriverFileNameA(void *image_base, LPSTR file_name, DWORD size)
{
    FIXME("(%p, %p, %d): stub\n", image_base, file_name, size);

    if (file_name && size)
        file_name[0] = '\0';

    return 0;
}

/***********************************************************************
 *           K32GetDeviceDriverFileNameW (KERNEL32.@)
 */
DWORD WINAPI K32GetDeviceDriverFileNameW(void *image_base, LPWSTR file_name, DWORD size)
{
    WCHAR path[size];
    UNICODE_STRING nt_path;
    NTSTATUS status;

    FIXME("(%p, %p, %d): stub\n", image_base, file_name, size);

    SERVER_START_REQ( get_driver_info )
    {
        req->driver = (client_ptr_t) image_base;
        wine_server_set_reply( req, path, sizeof(path)) ;
        wine_server_call( req );
    }
    SERVER_END_REQ;

    status = RtlDosPathNameToNtPathName_U_WithStatus(path, &nt_path, NULL, NULL);

    if(status)
    {
        SetLastError(RtlNtStatusToDosError(status));
        return 0;
    }

    RtlCopyMemory(file_name, nt_path.Buffer, size * sizeof(WCHAR));
    file_name[size] = 0;

    return 1;
}

/***********************************************************************
 *           GetFinalPathNameByHandleW (KERNEL32.@)
 */
DWORD WINAPI GetFinalPathNameByHandleW(HANDLE file, LPWSTR path, DWORD charcount, DWORD flags)
{
    WCHAR buffer[sizeof(OBJECT_NAME_INFORMATION) + MAX_PATH + 1];
    OBJECT_NAME_INFORMATION *info = (OBJECT_NAME_INFORMATION*)&buffer;
    WCHAR drive_part[MAX_PATH];
    DWORD drive_part_len = 0;
    NTSTATUS status;
    DWORD result = 0;
    ULONG dummy;
    WCHAR *ptr;

    TRACE( "(%p,%p,%d,%x)\n", file, path, charcount, flags );

    if (flags & ~(FILE_NAME_OPENED | VOLUME_NAME_GUID | VOLUME_NAME_NONE | VOLUME_NAME_NT))
    {
        WARN("Unknown flags: %x\n", flags);
        SetLastError( ERROR_INVALID_PARAMETER );
        return 0;
    }

    /* get object name */
    status = NtQueryObject( file, ObjectNameInformation, &buffer, sizeof(buffer) - sizeof(WCHAR), &dummy );
    if (status != STATUS_SUCCESS)
    {
        SetLastError( RtlNtStatusToDosError( status ) );
        return 0;
    }
    if (!info->Name.Buffer)
    {
        SetLastError( ERROR_INVALID_HANDLE );
        return 0;
    }
    if (info->Name.Length < 4 * sizeof(WCHAR) || info->Name.Buffer[0] != '\\' ||
             info->Name.Buffer[1] != '?' || info->Name.Buffer[2] != '?' || info->Name.Buffer[3] != '\\' )
    {
        FIXME("Unexpected object name: %s\n", debugstr_wn(info->Name.Buffer, info->Name.Length / sizeof(WCHAR)));
        SetLastError( ERROR_GEN_FAILURE );
        return 0;
    }

    /* add terminating null character, remove "\\??\\" */
    info->Name.Buffer[info->Name.Length / sizeof(WCHAR)] = 0;
    info->Name.Length -= 4 * sizeof(WCHAR);
    info->Name.Buffer += 4;

    /* FILE_NAME_OPENED is not supported yet, and would require Wineserver changes */
    if (flags & FILE_NAME_OPENED)
    {
        FIXME("FILE_NAME_OPENED not supported\n");
        flags &= ~FILE_NAME_OPENED;
    }

    /* Get information required for VOLUME_NAME_NONE, VOLUME_NAME_GUID and VOLUME_NAME_NT */
    if (flags == VOLUME_NAME_NONE || flags == VOLUME_NAME_GUID || flags == VOLUME_NAME_NT)
    {
        if (!GetVolumePathNameW( info->Name.Buffer, drive_part, MAX_PATH ))
            return 0;

        drive_part_len = strlenW(drive_part);
        if (!drive_part_len || drive_part_len > strlenW(info->Name.Buffer) ||
                drive_part[drive_part_len-1] != '\\' ||
                strncmpiW( info->Name.Buffer, drive_part, drive_part_len ))
        {
            FIXME("Path %s returned by GetVolumePathNameW does not match file path %s\n",
                debugstr_w(drive_part), debugstr_w(info->Name.Buffer));
            SetLastError( ERROR_GEN_FAILURE );
            return 0;
        }
    }

    if (flags == VOLUME_NAME_NONE)
    {
        ptr    = info->Name.Buffer + drive_part_len - 1;
        result = strlenW(ptr);
        if (result < charcount)
            memcpy(path, ptr, (result + 1) * sizeof(WCHAR));
        else result++;
    }
    else if (flags == VOLUME_NAME_GUID)
    {
        WCHAR volume_prefix[51];

        /* GetVolumeNameForVolumeMountPointW sets error code on failure */
        if (!GetVolumeNameForVolumeMountPointW( drive_part, volume_prefix, 50 ))
            return 0;

        ptr    = info->Name.Buffer + drive_part_len;
        result = strlenW(volume_prefix) + strlenW(ptr);
        if (result < charcount)
        {
            path[0] = 0;
            strcatW(path, volume_prefix);
            strcatW(path, ptr);
        }
        else
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            result++;
        }
    }
    else if (flags == VOLUME_NAME_NT)
    {
        WCHAR nt_prefix[MAX_PATH];

        /* QueryDosDeviceW sets error code on failure */
        drive_part[drive_part_len - 1] = 0;
        if (!QueryDosDeviceW( drive_part, nt_prefix, MAX_PATH ))
            return 0;

        ptr    = info->Name.Buffer + drive_part_len - 1;
        result = strlenW(nt_prefix) + strlenW(ptr);
        if (result < charcount)
        {
            path[0] = 0;
            strcatW(path, nt_prefix);
            strcatW(path, ptr);
        }
        else
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            result++;
        }
    }
    else if (flags == VOLUME_NAME_DOS)
    {
        static const WCHAR dos_prefix[] = {'\\','\\','?','\\', '\0'};

        result = strlenW(dos_prefix) + strlenW(info->Name.Buffer);
        if (result < charcount)
        {
            path[0] = 0;
            strcatW(path, dos_prefix);
            strcatW(path, info->Name.Buffer);
        }
        else
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            result++;
        }
    }
    else
    {
        /* Windows crashes here, but we prefer returning ERROR_INVALID_PARAMETER */
        WARN("Invalid combination of flags: %x\n", flags);
        SetLastError( ERROR_INVALID_PARAMETER );
    }

    return result;
}

/***********************************************************************
 *           GetFinalPathNameByHandleA (KERNEL32.@)
 */
DWORD WINAPI GetFinalPathNameByHandleA(HANDLE file, LPSTR path, DWORD charcount, DWORD flags)
{
    WCHAR *str;
    DWORD result, len, cp;

    TRACE( "(%p,%p,%d,%x)\n", file, path, charcount, flags);

    len = GetFinalPathNameByHandleW(file, NULL, 0, flags);
    if (len == 0)
        return 0;

    str = HeapAlloc(GetProcessHeap(), 0, len * sizeof(WCHAR));
    if (!str)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }

    result = GetFinalPathNameByHandleW(file, str, len, flags);
    if (result != len - 1)
    {
        HeapFree(GetProcessHeap(), 0, str);
        WARN("GetFinalPathNameByHandleW failed unexpectedly: %u\n", result);
        return 0;
    }

    cp = oem_file_apis ? CP_OEMCP : CP_ACP;

    len = WideCharToMultiByte(cp, 0, str, -1, NULL, 0, NULL, NULL);
    if (!len)
    {
        HeapFree(GetProcessHeap(), 0, str);
        WARN("Failed to get multibyte length\n");
        return 0;
    }

    if (charcount < len)
    {
        HeapFree(GetProcessHeap(), 0, str);
        return len - 1;
    }

    len = WideCharToMultiByte(cp, 0, str, -1, path, charcount, NULL, NULL);
    if (!len)
    {
        HeapFree(GetProcessHeap(), 0, str);
        WARN("WideCharToMultiByte failed\n");
        return 0;
    }

    HeapFree(GetProcessHeap(), 0, str);

    return len - 1;
}
