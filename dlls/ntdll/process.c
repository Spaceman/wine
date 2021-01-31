/*
 * NT process handling
 *
 * Copyright 1996-1998 Marcus Meissner
 * Copyright 2018 Alexandre Julliard
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
#include "config.h"
#include <errno.h>
#include <fcntl.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "wine/debug.h"
#include "windef.h"
#include "winternl.h"
#include "ntdll_misc.h"
#include "wine/exception.h"
#include "wine/server.h"
#include "wine/unicode.h"

WINE_DEFAULT_DEBUG_CHANNEL(process);


/******************************************************************************
 *  RtlGetCurrentPeb  [NTDLL.@]
 *
 */
PEB * WINAPI RtlGetCurrentPeb(void)
{
    return NtCurrentTeb()->Peb;
}


/**********************************************************************
 *           RtlCreateUserProcess  (NTDLL.@)
 */
NTSTATUS WINAPI RtlCreateUserProcess( UNICODE_STRING *path, ULONG attributes,
                                      RTL_USER_PROCESS_PARAMETERS *params,
                                      SECURITY_DESCRIPTOR *process_descr,
                                      SECURITY_DESCRIPTOR *thread_descr,
                                      HANDLE parent, BOOLEAN inherit, HANDLE debug, HANDLE token,
                                      RTL_USER_PROCESS_INFORMATION *info )
{
    OBJECT_ATTRIBUTES process_attr, thread_attr;
    PS_CREATE_INFO create_info;
    ULONG_PTR buffer[offsetof( PS_ATTRIBUTE_LIST, Attributes[6] ) / sizeof(ULONG_PTR)];
    PS_ATTRIBUTE_LIST *attr = (PS_ATTRIBUTE_LIST *)buffer;
    UINT pos = 0;

    RtlNormalizeProcessParams( params );

    attr->Attributes[pos].Attribute    = PS_ATTRIBUTE_IMAGE_NAME;
    attr->Attributes[pos].Size         = path->Length;
    attr->Attributes[pos].ValuePtr     = path->Buffer;
    attr->Attributes[pos].ReturnLength = NULL;
    pos++;
    attr->Attributes[pos].Attribute    = PS_ATTRIBUTE_CLIENT_ID;
    attr->Attributes[pos].Size         = sizeof(info->ClientId);
    attr->Attributes[pos].ValuePtr     = &info->ClientId;
    attr->Attributes[pos].ReturnLength = NULL;
    pos++;
    attr->Attributes[pos].Attribute    = PS_ATTRIBUTE_IMAGE_INFO;
    attr->Attributes[pos].Size         = sizeof(info->ImageInformation);
    attr->Attributes[pos].ValuePtr     = &info->ImageInformation;
    attr->Attributes[pos].ReturnLength = NULL;
    pos++;
    if (parent)
    {
        attr->Attributes[pos].Attribute    = PS_ATTRIBUTE_PARENT_PROCESS;
        attr->Attributes[pos].Size         = sizeof(parent);
        attr->Attributes[pos].ValuePtr     = parent;
        attr->Attributes[pos].ReturnLength = NULL;
        pos++;
    }
    if (debug)
    {
        attr->Attributes[pos].Attribute    = PS_ATTRIBUTE_DEBUG_PORT;
        attr->Attributes[pos].Size         = sizeof(debug);
        attr->Attributes[pos].ValuePtr     = debug;
        attr->Attributes[pos].ReturnLength = NULL;
        pos++;
    }
    if (token)
    {
        attr->Attributes[pos].Attribute    = PS_ATTRIBUTE_TOKEN;
        attr->Attributes[pos].Size         = sizeof(token);
        attr->Attributes[pos].ValuePtr     = token;
        attr->Attributes[pos].ReturnLength = NULL;
        pos++;
    }
    attr->TotalLength = offsetof( PS_ATTRIBUTE_LIST, Attributes[pos] );

    InitializeObjectAttributes( &process_attr, NULL, 0, NULL, process_descr );
    InitializeObjectAttributes( &thread_attr, NULL, 0, NULL, thread_descr );

    return NtCreateUserProcess( &info->Process, &info->Thread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
                                &process_attr, &thread_attr,
                                inherit ? PROCESS_CREATE_FLAGS_INHERIT_HANDLES : 0,
                                THREAD_CREATE_FLAGS_CREATE_SUSPENDED, params,
                                &create_info, attr );
}

/***********************************************************************
 *      DbgUiGetThreadDebugObject (NTDLL.@)
 */
HANDLE WINAPI DbgUiGetThreadDebugObject(void)
{
    return NtCurrentTeb()->DbgSsReserved[1];
}

/***********************************************************************
 *      DbgUiSetThreadDebugObject (NTDLL.@)
 */
void WINAPI DbgUiSetThreadDebugObject( HANDLE handle )
{
    NtCurrentTeb()->DbgSsReserved[1] = handle;
}

/***********************************************************************
 *      DbgUiConnectToDbg (NTDLL.@)
 */
NTSTATUS WINAPI DbgUiConnectToDbg(void)
{
    HANDLE handle;
    NTSTATUS status;
    OBJECT_ATTRIBUTES attr = { sizeof(attr) };

    if (DbgUiGetThreadDebugObject()) return STATUS_SUCCESS;  /* already connected */

    status = NtCreateDebugObject( &handle, DEBUG_ALL_ACCESS, &attr, DEBUG_KILL_ON_CLOSE );
    if (!status) DbgUiSetThreadDebugObject( handle );
    return status;
}

/***********************************************************************
 *      DbgUiRemoteBreakin (NTDLL.@)
 */
void WINAPI DbgUiRemoteBreakin( void *arg )
{
    TRACE( "\n" );
    if (NtCurrentTeb()->Peb->BeingDebugged)
    {
        __TRY
        {
            DbgBreakPoint();
        }
        __EXCEPT_ALL
        {
            /* do nothing */
        }
        __ENDTRY
    }
    RtlExitUserThread( STATUS_SUCCESS );
}

/***********************************************************************
 *      DbgUiIssueRemoteBreakin (NTDLL.@)
 */
NTSTATUS WINAPI DbgUiIssueRemoteBreakin( HANDLE process )
{
    return unix_funcs->DbgUiIssueRemoteBreakin( process );
}

#define NE_FFLAGS_LIBMODULE  0x8000

enum binary_type
{
    BINARY_UNKNOWN = 0,
    BINARY_PE,
    BINARY_WIN16,
    BINARY_OS216,
    BINARY_DOS,
    BINARY_UNIX_EXE,
    BINARY_UNIX_LIB
};

#define BINARY_FLAG_DLL     0x01
#define BINARY_FLAG_64BIT   0x02
#define BINARY_FLAG_FAKEDLL 0x04

struct binary_info
{
    enum binary_type type;
    DWORD            arch;
    DWORD            flags;
    ULONGLONG        res_start;
    ULONGLONG        res_end;
};

static DWORD MODULE_Decide_OS2_OldWin(HANDLE hfile, const IMAGE_DOS_HEADER *mz, const IMAGE_OS2_HEADER *ne)
{
    DWORD ret = BINARY_OS216;
    LPWORD modtab = NULL;
    LPSTR nametab = NULL;
    int i;
    LARGE_INTEGER li;
    IO_STATUS_BLOCK io;

    /* read modref table */
    li.QuadPart = (mz->e_lfanew + ne->ne_modtab);
    if ( (!(modtab = RtlAllocateHeap( GetProcessHeap(), 0, ne->ne_cmod*sizeof(WORD))))
      || (NtReadFile(hfile, NULL, NULL, NULL, &io, modtab, ne->ne_cmod*sizeof(WORD), &li, NULL))
      || (io.Information != ne->ne_cmod*sizeof(WORD)) )
	goto done;

    /* read imported names table */
    li.QuadPart = (mz->e_lfanew + ne->ne_imptab);
    if ( (!(nametab = RtlAllocateHeap( GetProcessHeap(), 0, ne->ne_enttab - ne->ne_imptab)))
      || (NtReadFile(hfile, NULL, NULL, NULL, &io, nametab, ne->ne_enttab - ne->ne_imptab, &li, NULL))
      || (io.Information != ne->ne_enttab - ne->ne_imptab) )
	goto done;

    for (i=0; i < ne->ne_cmod; i++)
    {
        LPSTR module = &nametab[modtab[i]];
        TRACE("modref: %.*s\n", module[0], &module[1]);
        if (!(strncmp(&module[1], "KERNEL", module[0])))
        { /* very old Windows file */
            MESSAGE("This seems to be a very old (pre-3.0) Windows executable. Expect crashes, especially if this is a real-mode binary !\n");
            ret = BINARY_WIN16;
            break;
        }
    }

done:
    RtlFreeHeap( GetProcessHeap(), 0, modtab);
    RtlFreeHeap( GetProcessHeap(), 0, nametab);
    return ret;
}

/***********************************************************************
 *           get_binary_info
 */
void get_binary_info( HANDLE hfile, struct binary_info *info )
{
    union
    {
        struct
        {
            unsigned char magic[4];
            unsigned char class;
            unsigned char data;
            unsigned char ignored1[10];
            unsigned short type;
            unsigned short machine;
            unsigned char ignored2[8];
            unsigned int phoff;
            unsigned char ignored3[12];
            unsigned short phnum;
        } elf;
        struct
        {
            unsigned char magic[4];
            unsigned char class;
            unsigned char data;
            unsigned char ignored1[10];
            unsigned short type;
            unsigned short machine;
            unsigned char ignored2[12];
            unsigned __int64 phoff;
            unsigned char ignored3[16];
            unsigned short phnum;
        } elf64;
        struct
        {
            unsigned int magic;
            unsigned int cputype;
            unsigned int cpusubtype;
            unsigned int filetype;
        } macho;
        IMAGE_DOS_HEADER mz;
    } header;

    IO_STATUS_BLOCK io;
    LARGE_INTEGER li;
    NTSTATUS status;

    memset( info, 0, sizeof(*info) );

    /* Seek to the start of the file and read the header information. */
    li.QuadPart = 0;
    if( (status = NtReadFile(hfile, NULL, NULL, NULL, &io, &header, sizeof(header), &li, NULL)) ) return;

    if (!memcmp( header.elf.magic, "\177ELF", 4 ))
    {
#ifdef WORDS_BIGENDIAN
        BOOL byteswap = (header.elf.data == 1);
#else
        BOOL byteswap = (header.elf.data == 2);
#endif
        if (header.elf.class == 2) info->flags |= BINARY_FLAG_64BIT;
        if (byteswap)
        {
            header.elf.type = RtlUshortByteSwap( header.elf.type );
            header.elf.machine = RtlUshortByteSwap( header.elf.machine );
        }
        switch(header.elf.type)
        {
        case 2:
            info->type = BINARY_UNIX_EXE;
            break;
        case 3:
        {
            LARGE_INTEGER phoff;
            unsigned short phnum;
            unsigned int type;
            if (header.elf.class == 2)
            {
                phoff.QuadPart = byteswap ? RtlUlonglongByteSwap( header.elf64.phoff ) : header.elf64.phoff;
                phnum = byteswap ? RtlUshortByteSwap( header.elf64.phnum ) : header.elf64.phnum;
            }
            else
            {
                phoff.QuadPart = byteswap ? RtlUlongByteSwap( header.elf.phoff ) : header.elf.phoff;
                phnum = byteswap ? RtlUshortByteSwap( header.elf.phnum ) : header.elf.phnum;
            }
            while (phnum--)
            {
                if ( NtReadFile( hfile, NULL, NULL, NULL, &io, &type, sizeof(type), &phoff, NULL ) ) return;
                if (byteswap) type = RtlUlongByteSwap( type );
                if (type == 3)
                {
                    info->type = BINARY_UNIX_EXE;
                    break;
                }
                phoff.QuadPart += (header.elf.class == 2) ? 56 : 32;
            }
            if (!info->type) info->type = BINARY_UNIX_LIB;
            break;
        }
        default:
            return;
        }
        switch(header.elf.machine)
        {
        case 3:   info->arch = IMAGE_FILE_MACHINE_I386; break;
        case 20:  info->arch = IMAGE_FILE_MACHINE_POWERPC; break;
        case 40:  info->arch = IMAGE_FILE_MACHINE_ARMNT; break;
        case 50:  info->arch = IMAGE_FILE_MACHINE_IA64; break;
        case 62:  info->arch = IMAGE_FILE_MACHINE_AMD64; break;
        case 183: info->arch = IMAGE_FILE_MACHINE_ARM64; break;
        }
    }
    /* Mach-o File with Endian set to Big Endian or Little Endian */
    else if (header.macho.magic == 0xfeedface || header.macho.magic == 0xcefaedfe ||
             header.macho.magic == 0xfeedfacf || header.macho.magic == 0xcffaedfe)
    {
        if ((header.macho.cputype >> 24) == 1) info->flags |= BINARY_FLAG_64BIT;
        if (header.macho.magic == 0xcefaedfe || header.macho.magic == 0xcffaedfe)
        {
            header.macho.filetype = RtlUlongByteSwap( header.macho.filetype );
            header.macho.cputype = RtlUlongByteSwap( header.macho.cputype );
        }
        switch(header.macho.filetype)
        {
        case 2: info->type = BINARY_UNIX_EXE; break;
        case 8: info->type = BINARY_UNIX_LIB; break;
        }
        switch(header.macho.cputype)
        {
        case 0x00000007: info->arch = IMAGE_FILE_MACHINE_I386; break;
        case 0x01000007: info->arch = IMAGE_FILE_MACHINE_AMD64; break;
        case 0x0000000c: info->arch = IMAGE_FILE_MACHINE_ARMNT; break;
        case 0x0100000c: info->arch = IMAGE_FILE_MACHINE_ARM64; break;
        case 0x00000012: info->arch = IMAGE_FILE_MACHINE_POWERPC; break;
        }
    }
    /* Not ELF, try DOS */
    else if (header.mz.e_magic == IMAGE_DOS_SIGNATURE)
    {
        union
        {
            IMAGE_OS2_HEADER os2;
            IMAGE_NT_HEADERS32 nt;
            IMAGE_NT_HEADERS64 nt64;
        } ext_header;

        /* We do have a DOS image so we will now try to seek into
         * the file by the amount indicated by the field
         * "Offset to extended header" and read in the
         * "magic" field information at that location.
         * This will tell us if there is more header information
         * to read or not.
         */
        info->type = BINARY_DOS;
        info->arch = IMAGE_FILE_MACHINE_I386;
        li.QuadPart = header.mz.e_lfanew;
        if (NtReadFile(hfile, NULL, NULL, NULL, &io, &ext_header, sizeof(ext_header), &li, NULL)) return;


        /* Reading the magic field succeeded so
         * we will try to determine what type it is.
         */
        if (!memcmp( &ext_header.nt.Signature, "PE\0\0", 4 ))
        {
            if (io.Information >= sizeof(ext_header.nt.FileHeader))
            {
                static const char fakedll_signature[] = "Wine placeholder DLL";
                char buffer[sizeof(fakedll_signature)];

                info->type = BINARY_PE;
                info->arch = ext_header.nt.FileHeader.Machine;
                if (ext_header.nt.FileHeader.Characteristics & IMAGE_FILE_DLL)
                    info->flags |= BINARY_FLAG_DLL;
                if (io.Information < sizeof(ext_header))  /* clear remaining part of header if missing */
                    memset( (char *)&ext_header + io.Information, 0, sizeof(ext_header) - io.Information );
                switch (ext_header.nt.OptionalHeader.Magic)
                {
                case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                    info->res_start = ext_header.nt.OptionalHeader.ImageBase;
                    info->res_end = info->res_start + ext_header.nt.OptionalHeader.SizeOfImage;
                    break;
                case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                    info->res_start = ext_header.nt64.OptionalHeader.ImageBase;
                    info->res_end = info->res_start + ext_header.nt64.OptionalHeader.SizeOfImage;
                    info->flags |= BINARY_FLAG_64BIT;
                    break;
                }

                li.QuadPart = sizeof(header.mz);
                if (header.mz.e_lfanew >= sizeof(header.mz) + sizeof(fakedll_signature) &&
                    !NtReadFile( hfile, NULL, NULL, NULL, &io, buffer, sizeof(fakedll_signature), &li, NULL ) &&
                    io.Information == sizeof(fakedll_signature) &&
                    !memcmp( buffer, fakedll_signature, sizeof(fakedll_signature) ))
                {
                    info->flags |= BINARY_FLAG_FAKEDLL;
                }
            }
        }
        else if (!memcmp( &ext_header.os2.ne_magic, "NE", 2 ))
        {
            /* This is a Windows executable (NE) header.  This can
             * mean either a 16-bit OS/2 or a 16-bit Windows or even a
             * DOS program (running under a DOS extender).  To decide
             * which, we'll have to read the NE header.
             */
            if (io.Information >= sizeof(ext_header.os2))
            {
                if (ext_header.os2.ne_flags & NE_FFLAGS_LIBMODULE) info->flags |= BINARY_FLAG_DLL;
                switch ( ext_header.os2.ne_exetyp )
                {
                case 1:  info->type = BINARY_OS216; break; /* OS/2 */
                case 2:  info->type = BINARY_WIN16; break; /* Windows */
                case 3:  info->type = BINARY_DOS; break; /* European MS-DOS 4.x */
                case 4:  info->type = BINARY_WIN16; break; /* Windows 386; FIXME: is this 32bit??? */
                case 5:  info->type = BINARY_DOS; break; /* BOSS, Borland Operating System Services */
                /* other types, e.g. 0 is: "unknown" */
                default: info->type = MODULE_Decide_OS2_OldWin(hfile, &header.mz, &ext_header.os2); break;
                }
            }
        }
    }
}

static HANDLE open_exe_file( const WCHAR *name, struct binary_info *binary_info, NTSTATUS* ret )
{
    HANDLE handle;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    UNICODE_STRING nameW;

    TRACE("looking for %s\n", debugstr_w(name) );

    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    RtlDosPathNameToNtPathName_U(name, &nameW, NULL, NULL);
    attr.ObjectName = &nameW;
    attr.SecurityDescriptor = NULL;
    attr.SecurityQualityOfService = NULL;

    *ret = NtCreateFile(&handle, GENERIC_READ, &attr, &io, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ|FILE_SHARE_DELETE, FILE_OPEN, 0, 0, 0);

    if (handle != INVALID_HANDLE_VALUE)
        get_binary_info( handle, binary_info ); /* Move this function to ntdll */;
    
    return handle;
}

static int get_process_cpu( const WCHAR *filename, const struct binary_info *binary_info )
{
    switch (binary_info->arch)
    {
    case IMAGE_FILE_MACHINE_I386:    return CPU_x86;
    case IMAGE_FILE_MACHINE_AMD64:   return CPU_x86_64;
    case IMAGE_FILE_MACHINE_POWERPC: return CPU_POWERPC;
    case IMAGE_FILE_MACHINE_ARM:
    case IMAGE_FILE_MACHINE_THUMB:
    case IMAGE_FILE_MACHINE_ARMNT:   return CPU_ARM;
    case IMAGE_FILE_MACHINE_ARM64:   return CPU_ARM64;
    }
    ERR( "%s uses unsupported architecture (%04x)\n", debugstr_w(filename), binary_info->arch );
    return -1;
}

static startup_info_t *create_startup_info(PRTL_USER_PROCESS_PARAMETERS startup, DWORD *info_size)
{
    const RTL_USER_PROCESS_PARAMETERS *cur_params;
    startup_info_t *info;
    DWORD size;
    void *ptr;
    HANDLE hstdin, hstdout, hstderr;
    
    
    cur_params = NtCurrentTeb()->Peb->ProcessParameters;
    
    /* convert ImagePathName and CommandLine to DOS format*/
    if(startup->ImagePathName.Buffer[5] == ':')
    {
        DWORD len = startup->ImagePathName.Length - 4 * sizeof(WCHAR);
        memmove( startup->ImagePathName.Buffer, startup->ImagePathName.Buffer + 4, len );
        startup->ImagePathName.Buffer[len / sizeof(WCHAR)] = 0;
        startup->ImagePathName.Length = len;
    }
    
    if(startup->CommandLine.Buffer[5] == ':')
    {
        DWORD len = startup->CommandLine.Length - 4 * sizeof(WCHAR);
        memmove( startup->CommandLine.Buffer, startup->CommandLine.Buffer + 4, len );
        startup->CommandLine.Buffer[len / sizeof(WCHAR)] = 0;
        startup->CommandLine.Length = len;
    }
    
    size = sizeof(*info);
    size += startup->CurrentDirectory.DosPath.Length;
    size += startup->DllPath.Length;
    size += startup->ImagePathName.Length;
    size += startup->CommandLine.Length;
    size += startup->WindowTitle.Length;
    size += startup->Desktop.Length;
    size += startup->ShellInfo.Length;
    size += startup->RuntimeInfo.Length;
    
    *info_size = size;
    
    info = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if(!info) FIXME("broke1");
    
    info->console_flags = startup->ConsoleFlags;
    
    if(startup->dwFlags & STARTF_USESTDHANDLES)
    {
        hstdin  = startup->hStdInput;
        hstdout = startup->hStdOutput;
        hstderr = startup->hStdError;
    }else {
        hstdin  = cur_params->hStdInput;
        hstdout = cur_params->hStdOutput;
        hstderr = cur_params->hStdError;
    }
    
    info->hstdin  = wine_server_obj_handle( hstdin );
    info->hstdout = wine_server_obj_handle( hstdout );
    info->hstderr = wine_server_obj_handle( hstderr );
    
    if (is_console_handle(hstdin))  info->hstdin  = console_handle_unmap(hstdin);
    if (is_console_handle(hstdout)) info->hstdout = console_handle_unmap(hstdout);
    if (is_console_handle(hstderr)) info->hstderr = console_handle_unmap(hstderr);
    
    info->x         = startup->dwX;
    info->y         = startup->dwY;
    info->xsize     = startup->dwXSize;
    info->ysize     = startup->dwYSize;
    info->xchars    = startup->dwXCountChars;
    info->ychars    = startup->dwYCountChars;
    info->attribute = startup->dwFillAttribute;
    info->flags     = startup->dwFlags;
    info->show      = startup->wShowWindow;
    
    /* add the strings */
    ptr = info + 1;
    
    info->curdir_len = startup->CurrentDirectory.DosPath.Length;
    memcpy( ptr, startup->CurrentDirectory.DosPath.Buffer, startup->CurrentDirectory.DosPath.Length );
    ptr = (char *)ptr + startup->CurrentDirectory.DosPath.Length;
    
    info->dllpath_len = startup->DllPath.Length;
    memcpy( ptr, startup->DllPath.Buffer, startup->DllPath.Length );
    ptr = (char *)ptr + startup->DllPath.Length;
    
    info->imagepath_len = startup->ImagePathName.Length;
    memcpy( ptr, startup->ImagePathName.Buffer, startup->ImagePathName.Length );
    ptr = (char *)ptr + startup->ImagePathName.Length;
    
    info->cmdline_len = startup->CommandLine.Length;
    memcpy( ptr, startup->CommandLine.Buffer, startup->CommandLine.Length );
    ptr = (char *)ptr + startup->CommandLine.Length;
    
    
    info->title_len = startup->WindowTitle.Length;
    memcpy( ptr, startup->WindowTitle.Buffer, startup->WindowTitle.Length );
    ptr = (char *)ptr + startup->WindowTitle.Length;
    
    
    info->desktop_len = startup->Desktop.Length;
    memcpy( ptr, startup->Desktop.Buffer, startup->Desktop.Length );
    ptr = (char *)ptr + startup->Desktop.Length;
    
    info->shellinfo_len = startup->ShellInfo.Length;
    memcpy( ptr, startup->ShellInfo.Buffer, startup->ShellInfo.Length );
    ptr = (char *)ptr + startup->ShellInfo.Length;
    
    info->runtime_len = startup->RuntimeInfo.Length;
    memcpy( ptr, startup->RuntimeInfo.Buffer, startup->RuntimeInfo.Length );
    ptr = (char *)ptr + startup->RuntimeInfo.Length;
    
    return info;
}

static const BOOL is_win64 = (sizeof(void *) > sizeof(int));

/***********************************************************************
 *           get_alternate_loader
 *
 * Get the name of the alternate (32 or 64 bit) Wine loader.
 */
static const char *get_alternate_loader( char **ret_env )
{
    char *env;
    const char *loader = NULL;
    const char *loader_env = getenv( "WINELOADER" );

    *ret_env = NULL;

    if (wine_get_build_dir()) loader = is_win64 ? "loader/wine" : "server/../loader/wine64";

    if (loader_env)
    {
        int len = strlen( loader_env );
        if (!is_win64)
        {
            if (!(env = RtlAllocateHeap( GetProcessHeap(), 0, sizeof("WINELOADER=") + len + 2 ))) return NULL;
            strcpy( env, "WINELOADER=" );
            strcat( env, loader_env );
            strcat( env, "64" );
        }
        else
        {
            if (!(env = RtlAllocateHeap( GetProcessHeap(), 0, sizeof("WINELOADER=") + len ))) return NULL;
            strcpy( env, "WINELOADER=" );
            strcat( env, loader_env );
            len += sizeof("WINELOADER=") - 1;
            if (!strcmp( env + len - 2, "64" )) env[len - 2] = 0;
        }
        if (!loader)
        {
            if ((loader = strrchr( env, '/' ))) loader++;
            else loader = env;
        }
        *ret_env = env;
    }
    if (!loader) loader = is_win64 ? "wine" : "wine64";
    return loader;
}

/***********************************************************************
 *           build_argv
 *
 * Build an argv array from a command-line.
 * 'reserved' is the number of args to reserve before the first one.
 */
static char **build_argv( const WCHAR *cmdlineW, int reserved )
{
    int argc;
    char** argv;
    char *arg,*s,*d,*cmdline;
    int in_quotes,bcount,len;

    len = ntdll_wcstoumbs( 0, cmdlineW, strlenW(cmdlineW), NULL, 0, NULL, NULL );
    if (!(cmdline = RtlAllocateHeap( GetProcessHeap(), 0, len ))) return NULL;
    ntdll_wcstoumbs( 0, cmdlineW, strlenW(cmdlineW), cmdline, len, NULL, NULL );

    argc=reserved+1;
    bcount=0;
    in_quotes=0;
    s=cmdline;
    while (1) {
        if (*s=='\0' || ((*s==' ' || *s=='\t') && !in_quotes)) {
            /* space */
            argc++;
            /* skip the remaining spaces */
            while (*s==' ' || *s=='\t') {
                s++;
            }
            if (*s=='\0')
                break;
            bcount=0;
            continue;
        } else if (*s=='\\') {
            /* '\', count them */
            bcount++;
        } else if ((*s=='"') && ((bcount & 1)==0)) {
            /* unescaped '"' */
            in_quotes=!in_quotes;
            bcount=0;
        } else {
            /* a regular character */
            bcount=0;
        }
        s++;
    }
    if (!(argv = RtlAllocateHeap( GetProcessHeap(), 0, argc*sizeof(*argv) + len )))
    {
        RtlFreeHeap( GetProcessHeap(), 0, cmdline );
        return NULL;
    }

    arg = d = s = (char *)(argv + argc);
    memcpy( d, cmdline, len );
    bcount=0;
    in_quotes=0;
    argc=reserved;
    while (*s) {
        if ((*s==' ' || *s=='\t') && !in_quotes) {
            /* Close the argument and copy it */
            *d=0;
            argv[argc++]=arg;

            /* skip the remaining spaces */
            do {
                s++;
            } while (*s==' ' || *s=='\t');

            /* Start with a new argument */
            arg=d=s;
            bcount=0;
        } else if (*s=='\\') {
            /* '\\' */
            *d++=*s++;
            bcount++;
        } else if (*s=='"') {
            /* '"' */
            if ((bcount & 1)==0) {
                /* Preceded by an even number of '\', this is half that
                 * number of '\', plus a '"' which we discard.
                 */
                d-=bcount/2;
                s++;
                in_quotes=!in_quotes;
            } else {
                /* Preceded by an odd number of '\', this is half that
                 * number of '\' followed by a '"'
                 */
                d=d-bcount/2-1;
                *d++='"';
                s++;
            }
            bcount=0;
        } else {
            /* a regular character */
            *d++=*s++;
            bcount=0;
        }
    }
    if (*arg) {
        *d='\0';
        argv[argc++]=arg;
    }
    argv[argc]=NULL;

    RtlFreeHeap( GetProcessHeap(), 0, cmdline );
    return argv;
}

static pid_t exec_loader( LPCWSTR cmd_line, int socketfd,
                          int stdin_fd, int stdout_fd, const char *unixdir, char *winedebug,
                          const struct binary_info *binary_info )
{
    pid_t pid;
    char *wineloader = NULL;
    const char *loader = NULL;
    char **argv;

    argv = build_argv( cmd_line, 1 );

    if (!is_win64 ^ !(binary_info->flags & BINARY_FLAG_64BIT))
        loader = get_alternate_loader( &wineloader );

    if (!(pid = fork()))  /* child */
    {
        if (!(pid = fork()))  /* grandchild */
        {
            char preloader_reserve[64], socket_env[64];

            
            if (stdin_fd != -1) dup2( stdin_fd, 0 );
            if (stdout_fd != -1) dup2( stdout_fd, 1 );
            

            if (stdin_fd != -1) close( stdin_fd );
            if (stdout_fd != -1) close( stdout_fd );

            /* Reset signals that we previously set to SIG_IGN */
            signal( SIGPIPE, SIG_DFL );

            sprintf( socket_env, "WINESERVERSOCKET=%u", socketfd );
            sprintf( preloader_reserve, "WINEPRELOADRESERVE=%x%08x-%x%08x",
                     (ULONG)(binary_info->res_start >> 32), (ULONG)binary_info->res_start,
                     (ULONG)(binary_info->res_end >> 32), (ULONG)binary_info->res_end );

            putenv( preloader_reserve );
            putenv( socket_env );
            if (winedebug) putenv( winedebug );
            if (wineloader) putenv( wineloader );
            if (unixdir) chdir(unixdir);

            if (argv)
            {
                do
                {
                    wine_exec_wine_binary( loader, argv, getenv("WINELOADER") );
                }while (0);
            }
            _exit(1);
        }

        _exit(pid == -1);
    }

    if (pid != -1)
    {
        /* reap child */
        pid_t wret;
        do {
            wret = waitpid(pid, NULL, 0);
        } while (wret < 0 && errno == EINTR);
    }

    RtlFreeHeap( GetProcessHeap(), 0, wineloader );
    RtlFreeHeap( GetProcessHeap(), 0, argv );
    return pid;
}

static NTSTATUS create_process( HANDLE hFile, LPCWSTR filename,
                            PSECURITY_DESCRIPTOR psd, PSECURITY_DESCRIPTOR tsd,
                            BOOL inherit, DWORD flags, PRTL_USER_PROCESS_PARAMETERS startup,
                            PRTL_USER_PROCESS_INFORMATION info, LPCSTR unixdir,
                            const struct binary_info *binary_info)
{
    static const char *cpu_names[] = { "x86", "x86_64", "PowerPC", "ARM", "ARM64" };
    NTSTATUS status;
    NTSTATUS ret;
    BOOL success = FALSE;
    HANDLE process_info;
    WCHAR *env_end;
    char *winedebug = NULL;
    startup_info_t *startup_info;
    DWORD startup_info_size;
    int socketfd[2], stdin_fd = -1, stdout_fd = -1;
    pid_t pid;
    int cpu;
    
    if ((cpu = get_process_cpu( filename, binary_info )) == -1)
    {
        return STATUS_BAD_INITIAL_PC;
    }
    
    /* create the socket for the new process */

    if (socketpair( AF_UNIX, SOCK_STREAM, 0, socketfd ) == -1)
    {
        return STATUS_TOO_MANY_OPENED_FILES;
    }
#ifdef SO_PASSCRED
    else
    {
        int enable = 1;
        setsockopt( socketfd[0], SOL_SOCKET, SO_PASSCRED, &enable, sizeof(enable) );
    }
#endif

    RtlAcquirePebLock();
    
    if (!(startup_info = create_startup_info( startup, &startup_info_size )))
    {
        RtlReleasePebLock();
        close( socketfd[0] );
        close( socketfd[1] );
        return STATUS_NO_MEMORY;
    }
    
    if (!startup->Environment) startup->Environment = NtCurrentTeb()->Peb->ProcessParameters->Environment;
    
    env_end = startup->Environment;
    while (*env_end)
    {
        static const WCHAR WINEDEBUG[] = {'W','I','N','E','D','E','B','U','G','=',0};
        if (!winedebug && !strncmpW( env_end, WINEDEBUG, sizeof(WINEDEBUG)/sizeof(WCHAR) - 1 ))
        {
            DWORD len = ntdll_wcstoumbs(0, env_end, strlenW(env_end), NULL, 0, NULL, NULL);
            if ((winedebug = RtlAllocateHeap( GetProcessHeap(), 0, len )))
                ntdll_wcstoumbs( 0, env_end, strlenW(env_end), winedebug, len, NULL, NULL );
        }
        env_end += strlenW(env_end) + 1;
    }
    env_end++;
    
    wine_server_send_fd( socketfd[1] );
    close( socketfd[1] );
    
    /* create the process on the server side */
    SERVER_START_REQ( new_process )
    {
        req->inherit_all    = inherit;
        req->create_flags   = flags;
        req->socket_fd      = socketfd[1];
        req->exe_file       = wine_server_obj_handle( hFile );
        req->process_access = PROCESS_ALL_ACCESS;
        req->process_attr   = 0;
        req->thread_access  = THREAD_ALL_ACCESS;
        req->thread_attr    = 0;
        req->cpu            = cpu;
        req->info_size      = startup_info_size;

        wine_server_add_data( req, startup_info, startup_info_size );
        wine_server_add_data( req, startup->Environment, (env_end - startup->Environment) * sizeof(WCHAR) );
        if (!(status = wine_server_call( req )))
        {
            info->ClientId.UniqueProcess = (HANDLE)(unsigned long)reply->pid; /* HANDLEs are 64 bit but wineserver returns a 64 bit int */
            info->ClientId.UniqueThread  = (HANDLE)(unsigned long)reply->tid;
            info->Process    = wine_server_ptr_handle( reply->phandle );
            info->Thread     = wine_server_ptr_handle( reply->thandle );
            
        }
        process_info = wine_server_ptr_handle( reply->info );
    }
    SERVER_END_REQ;
    
    RtlReleasePebLock();
    
    if (status)
    {
        switch (status)
        {
        case STATUS_INVALID_IMAGE_WIN_64:
            ERR( "64-bit application %s not supported in 32-bit prefix\n", debugstr_w(filename) );
            break;
        case STATUS_INVALID_IMAGE_FORMAT:
            ERR( "%s not supported on this installation (%s binary)\n",
                 debugstr_w(filename), cpu_names[cpu] );
            break;
        }
        close( socketfd[0] );
        RtlFreeHeap( GetProcessHeap(), 0, startup_info );
        RtlFreeHeap( GetProcessHeap(), 0, winedebug );
        return status;
    }
    
    if (!(flags & (CREATE_NEW_CONSOLE | DETACHED_PROCESS)))
    {
        if (startup_info->hstdin)
            wine_server_handle_to_fd( wine_server_ptr_handle(startup_info->hstdin),
                                      FILE_READ_DATA, &stdin_fd, NULL );
        if (startup_info->hstdout)
            wine_server_handle_to_fd( wine_server_ptr_handle(startup_info->hstdout),
                                      FILE_WRITE_DATA, &stdout_fd, NULL );
    }
    RtlFreeHeap( GetProcessHeap(), 0, startup_info );
    
    /* create the child process */
    
    pid = exec_loader(startup->CommandLine.Buffer, socketfd[0], stdin_fd, stdout_fd, unixdir, winedebug, binary_info );
    
    if (stdin_fd != -1) close( stdin_fd );
    if (stdout_fd != -1) close( stdout_fd );
    close( socketfd[0] );
    RtlFreeHeap( GetProcessHeap(), 0, winedebug );
    if (pid == -1)
    {
        ret = STATUS_INTERNAL_ERROR;
        goto error;
    }
    
    /* wait for the new process info to be ready */
    
    NtWaitForSingleObject( process_info, FALSE, NULL );
    
    SERVER_START_REQ( get_new_process_info )
    {
        req->info = wine_server_obj_handle( process_info );
        wine_server_call( req );
        success = reply->success;
    }
    SERVER_END_REQ;
    
    if(!success)
    {
        ret = STATUS_INTERNAL_ERROR;
        goto error;
    }
    
    info->Length = sizeof(*info);
    
    return STATUS_SUCCESS;
    
error:
    NtClose( process_info );
    NtClose( info->Process );
    NtClose( info->Thread );
    info->Process = info->Thread = 0;
    info->ClientId.UniqueProcess = info->ClientId.UniqueThread = 0;
    return ret;
}

/**********************************************************************
 *           RtlCreateUserProcess [NTDLL.@]
 */
NTSTATUS WINAPI RtlCreateUserProcess(UNICODE_STRING *path, ULONG attributes, RTL_USER_PROCESS_PARAMETERS *parameters,
                                     SECURITY_DESCRIPTOR *process_descriptor, SECURITY_DESCRIPTOR *thread_descriptor,
                                     HANDLE parent, BOOLEAN inherit, HANDLE debug, HANDLE exception,
                                     RTL_USER_PROCESS_INFORMATION *info)
{
    
    NTSTATUS ret;
    HANDLE hFile;
    UNICODE_STRING dos_exe_path;
    char *unixdir = NULL;
    struct binary_info binary_info;
    
    parameters = RtlNormalizeProcessParams(parameters);
    
    /* convert nt name to dos name by removing ?? */
    dos_exe_path.MaximumLength = path->MaximumLength;
    dos_exe_path.Buffer = RtlAllocateHeap(GetProcessHeap(), 0, path->MaximumLength);
    RtlCopyUnicodeString(&dos_exe_path, path);
    if(dos_exe_path.Buffer[5] == ':')
    {
        DWORD len = dos_exe_path.Length - 4 * sizeof(WCHAR);
        memmove( dos_exe_path.Buffer, dos_exe_path.Buffer + 4, len );
        dos_exe_path.Buffer[len / sizeof(WCHAR)] = 0;
        dos_exe_path.Length = len;
    }
    
    /* get file handle from path, else return failure */
    hFile = open_exe_file(dos_exe_path.Buffer, &binary_info, &ret);
    if(hFile == INVALID_HANDLE_VALUE)
    {
        goto done;
    }

    /* get unix directory, current directory if not specified in parameters*/
    if(parameters->CurrentDirectory.DosPath.Length)
    {
        UNICODE_STRING nt_name;
        ANSI_STRING    unix_name;
        
        if(!RtlDosPathNameToNtPathName_U(parameters->CurrentDirectory.DosPath.Buffer, &nt_name, NULL, NULL)){ret = STATUS_BAD_CURRENT_DIRECTORY; goto done;}
        ret = wine_nt_to_unix_file_name(&nt_name, &unix_name, FILE_OPEN_IF, FALSE);
        unixdir = unix_name.Buffer;
        
        if (ret)
        {
            ret = STATUS_BAD_CURRENT_DIRECTORY;
            goto done;
        }
    }else{
        UNICODE_STRING nt_name;
        ANSI_STRING    unix_name;
        
        WCHAR buf[MAX_PATH];
        if (RtlGetCurrentDirectory_U(MAX_PATH * sizeof(WCHAR), buf))
        {
            RtlDosPathNameToNtPathName_U(buf, &nt_name, NULL, NULL);
            wine_nt_to_unix_file_name( &nt_name, &unix_name, FILE_OPEN_IF, FALSE );
            unixdir = unix_name.Buffer;
        }
    }

    info->Process = info->Thread = 0;
    info->ClientId.UniqueProcess = info->ClientId.UniqueThread = 0;
    /* TODO: Length and SectionImageInformation */
    
    /* Now we finally start what is called create_process in kernel32 */
    if(binary_info.type == BINARY_PE)
    {
        ret = create_process(hFile, parameters->ImagePathName.Buffer, process_descriptor, thread_descriptor, inherit, 0x00000004, parameters, info, unixdir, &binary_info);
    }else{
        return 1;
    }
    
    if (hFile) NtClose( hFile );

    done:
    return ret;
}


