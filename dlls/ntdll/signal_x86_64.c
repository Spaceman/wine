/*
 * x86-64 signal handling routines
 *
 * Copyright 1999, 2005 Alexandre Julliard
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

#ifdef __x86_64__

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>

#define NONAMELESSUNION
#define NONAMELESSSTRUCT
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/exception.h"
#include "wine/list.h"
#include "ntdll_misc.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(seh);

typedef struct _SCOPE_TABLE
{
    ULONG Count;
    struct
    {
        ULONG BeginAddress;
        ULONG EndAddress;
        ULONG HandlerAddress;
        ULONG JumpTarget;
    } ScopeRecord[1];
} SCOPE_TABLE, *PSCOPE_TABLE;


/* layering violation: the setjmp buffer is defined in msvcrt, but used by RtlUnwindEx */
struct MSVCRT_JUMP_BUFFER
{
    ULONG64 Frame;
    ULONG64 Rbx;
    ULONG64 Rsp;
    ULONG64 Rbp;
    ULONG64 Rsi;
    ULONG64 Rdi;
    ULONG64 R12;
    ULONG64 R13;
    ULONG64 R14;
    ULONG64 R15;
    ULONG64 Rip;
    ULONG64 Spare;
    M128A   Xmm6;
    M128A   Xmm7;
    M128A   Xmm8;
    M128A   Xmm9;
    M128A   Xmm10;
    M128A   Xmm11;
    M128A   Xmm12;
    M128A   Xmm13;
    M128A   Xmm14;
    M128A   Xmm15;
};

/***********************************************************************
 * Definitions for Win32 unwind tables
 */

union handler_data
{
    RUNTIME_FUNCTION chain;
    ULONG handler;
};

struct opcode
{
    BYTE offset;
    BYTE code : 4;
    BYTE info : 4;
};

struct UNWIND_INFO
{
    BYTE version : 3;
    BYTE flags : 5;
    BYTE prolog;
    BYTE count;
    BYTE frame_reg : 4;
    BYTE frame_offset : 4;
    struct opcode opcodes[1];  /* info->count entries */
    /* followed by handler_data */
};

#define UWOP_PUSH_NONVOL     0
#define UWOP_ALLOC_LARGE     1
#define UWOP_ALLOC_SMALL     2
#define UWOP_SET_FPREG       3
#define UWOP_SAVE_NONVOL     4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_EPILOG          6
#define UWOP_SAVE_XMM128     8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME  10

static void dump_unwind_info( ULONG64 base, RUNTIME_FUNCTION *function )
{
    static const char * const reg_names[16] =
        { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
          "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15" };

    union handler_data *handler_data;
    struct UNWIND_INFO *info;
    unsigned int i, count;

    TRACE( "**** func %x-%x\n", function->BeginAddress, function->EndAddress );
    for (;;)
    {
        if (function->UnwindData & 1)
        {
            RUNTIME_FUNCTION *next = (RUNTIME_FUNCTION *)((char *)base + (function->UnwindData & ~1));
            TRACE( "unwind info for function %p-%p chained to function %p-%p\n",
                   (char *)base + function->BeginAddress, (char *)base + function->EndAddress,
                   (char *)base + next->BeginAddress, (char *)base + next->EndAddress );
            function = next;
            continue;
        }
        info = (struct UNWIND_INFO *)((char *)base + function->UnwindData);

        TRACE( "unwind info at %p flags %x prolog 0x%x bytes function %p-%p\n",
               info, info->flags, info->prolog,
               (char *)base + function->BeginAddress, (char *)base + function->EndAddress );

        if (info->frame_reg)
            TRACE( "    frame register %s offset 0x%x(%%rsp)\n",
                   reg_names[info->frame_reg], info->frame_offset * 16 );

        for (i = 0; i < info->count; i++)
        {
            TRACE( "    0x%x: ", info->opcodes[i].offset );
            switch (info->opcodes[i].code)
            {
            case UWOP_PUSH_NONVOL:
                TRACE( "pushq %%%s\n", reg_names[info->opcodes[i].info] );
                break;
            case UWOP_ALLOC_LARGE:
                if (info->opcodes[i].info)
                {
                    count = *(DWORD *)&info->opcodes[i+1];
                    i += 2;
                }
                else
                {
                    count = *(USHORT *)&info->opcodes[i+1] * 8;
                    i++;
                }
                TRACE( "subq $0x%x,%%rsp\n", count );
                break;
            case UWOP_ALLOC_SMALL:
                count = (info->opcodes[i].info + 1) * 8;
                TRACE( "subq $0x%x,%%rsp\n", count );
                break;
            case UWOP_SET_FPREG:
                TRACE( "leaq 0x%x(%%rsp),%s\n",
                     info->frame_offset * 16, reg_names[info->frame_reg] );
                break;
            case UWOP_SAVE_NONVOL:
                count = *(USHORT *)&info->opcodes[i+1] * 8;
                TRACE( "movq %%%s,0x%x(%%rsp)\n", reg_names[info->opcodes[i].info], count );
                i++;
                break;
            case UWOP_SAVE_NONVOL_FAR:
                count = *(DWORD *)&info->opcodes[i+1];
                TRACE( "movq %%%s,0x%x(%%rsp)\n", reg_names[info->opcodes[i].info], count );
                i += 2;
                break;
            case UWOP_SAVE_XMM128:
                count = *(USHORT *)&info->opcodes[i+1] * 16;
                TRACE( "movaps %%xmm%u,0x%x(%%rsp)\n", info->opcodes[i].info, count );
                i++;
                break;
            case UWOP_SAVE_XMM128_FAR:
                count = *(DWORD *)&info->opcodes[i+1];
                TRACE( "movaps %%xmm%u,0x%x(%%rsp)\n", info->opcodes[i].info, count );
                i += 2;
                break;
            case UWOP_PUSH_MACHFRAME:
                TRACE( "PUSH_MACHFRAME %u\n", info->opcodes[i].info );
                break;
            case UWOP_EPILOG:
                if (info->version == 2)
                {
                    unsigned int offset;
                    if (info->opcodes[i].info)
                        offset = info->opcodes[i].offset;
                    else
                        offset = (info->opcodes[i+1].info << 8) + info->opcodes[i+1].offset;
                    TRACE("epilog %p-%p\n", (char *)base + function->EndAddress - offset,
                            (char *)base + function->EndAddress - offset + info->opcodes[i].offset );
                    i += 1;
                    break;
                }
            default:
                FIXME( "unknown code %u\n", info->opcodes[i].code );
                break;
            }
        }

        handler_data = (union handler_data *)&info->opcodes[(info->count + 1) & ~1];
        if (info->flags & UNW_FLAG_CHAININFO)
        {
            TRACE( "    chained to function %p-%p\n",
                   (char *)base + handler_data->chain.BeginAddress,
                   (char *)base + handler_data->chain.EndAddress );
            function = &handler_data->chain;
            continue;
        }
        if (info->flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER))
            TRACE( "    handler %p data at %p\n",
                   (char *)base + handler_data->handler, &handler_data->handler + 1 );
        break;
    }
}

static void dump_scope_table( ULONG64 base, const SCOPE_TABLE *table )
{
    unsigned int i;

    TRACE( "scope table at %p\n", table );
    for (i = 0; i < table->Count; i++)
        TRACE( "  %u: %p-%p handler %p target %p\n", i,
               (char *)base + table->ScopeRecord[i].BeginAddress,
               (char *)base + table->ScopeRecord[i].EndAddress,
               (char *)base + table->ScopeRecord[i].HandlerAddress,
               (char *)base + table->ScopeRecord[i].JumpTarget );
}


/***********************************************************************
 *           virtual_unwind
 */
static NTSTATUS virtual_unwind( ULONG type, DISPATCHER_CONTEXT *dispatch, CONTEXT *context )
{
    LDR_DATA_TABLE_ENTRY *module;
    NTSTATUS status;

    dispatch->ImageBase = 0;
    dispatch->ScopeIndex = 0;
    dispatch->ControlPc = context->Rip;

    /* first look for PE exception information */

    if ((dispatch->FunctionEntry = lookup_function_info( context->Rip, &dispatch->ImageBase, &module )))
    {
        dispatch->LanguageHandler = RtlVirtualUnwind( type, dispatch->ImageBase, context->Rip,
                                                      dispatch->FunctionEntry, context,
                                                      &dispatch->HandlerData, &dispatch->EstablisherFrame,
                                                      NULL );
        return STATUS_SUCCESS;
    }

    /* then look for host system exception information */

    if (!module || (module->Flags & LDR_WINE_INTERNAL))
    {
        status = unix_funcs->unwind_builtin_dll( type, dispatch, context );

        if (!status && dispatch->LanguageHandler && !module)
        {
            FIXME( "calling personality routine in system library not supported yet\n" );
            dispatch->LanguageHandler = NULL;
        }
        if (status != STATUS_UNSUCCESSFUL) return status;
    }
    else WARN( "exception data not found in %s\n", debugstr_w(module->BaseDllName.Buffer) );

    /* no exception information, treat as a leaf function */

    dispatch->EstablisherFrame = context->Rsp;
    dispatch->LanguageHandler = NULL;
    context->Rip = *(ULONG64 *)context->Rsp;
    context->Rsp = context->Rsp + sizeof(ULONG64);
    return STATUS_SUCCESS;
}


/**************************************************************************
 *		__chkstk (NTDLL.@)
 *
 * Supposed to touch all the stack pages, but we shouldn't need that.
 */
__ASM_GLOBAL_FUNC( __chkstk, "ret" );


/***********************************************************************
 *		RtlCaptureContext (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( RtlCaptureContext,
                   "pushfq\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset 8\n\t")
                   "movl $0x10000f,0x30(%rcx)\n\t"  /* context->ContextFlags */
                   "stmxcsr 0x34(%rcx)\n\t"         /* context->MxCsr */
                   "movw %cs,0x38(%rcx)\n\t"        /* context->SegCs */
                   "movw %ds,0x3a(%rcx)\n\t"        /* context->SegDs */
                   "movw %es,0x3c(%rcx)\n\t"        /* context->SegEs */
                   "movw %fs,0x3e(%rcx)\n\t"        /* context->SegFs */
                   "movw %gs,0x40(%rcx)\n\t"        /* context->SegGs */
                   "movw %ss,0x42(%rcx)\n\t"        /* context->SegSs */
                   "popq 0x44(%rcx)\n\t"            /* context->Eflags */
                   __ASM_CFI(".cfi_adjust_cfa_offset -8\n\t")
                   "movq %rax,0x78(%rcx)\n\t"       /* context->Rax */
                   "movq %rcx,0x80(%rcx)\n\t"       /* context->Rcx */
                   "movq %rdx,0x88(%rcx)\n\t"       /* context->Rdx */
                   "movq %rbx,0x90(%rcx)\n\t"       /* context->Rbx */
                   "leaq 8(%rsp),%rax\n\t"
                   "movq %rax,0x98(%rcx)\n\t"       /* context->Rsp */
                   "movq %rbp,0xa0(%rcx)\n\t"       /* context->Rbp */
                   "movq %rsi,0xa8(%rcx)\n\t"       /* context->Rsi */
                   "movq %rdi,0xb0(%rcx)\n\t"       /* context->Rdi */
                   "movq %r8,0xb8(%rcx)\n\t"        /* context->R8 */
                   "movq %r9,0xc0(%rcx)\n\t"        /* context->R9 */
                   "movq %r10,0xc8(%rcx)\n\t"       /* context->R10 */
                   "movq %r11,0xd0(%rcx)\n\t"       /* context->R11 */
                   "movq %r12,0xd8(%rcx)\n\t"       /* context->R12 */
                   "movq %r13,0xe0(%rcx)\n\t"       /* context->R13 */
                   "movq %r14,0xe8(%rcx)\n\t"       /* context->R14 */
                   "movq %r15,0xf0(%rcx)\n\t"       /* context->R15 */
                   "movq (%rsp),%rax\n\t"
                   "movq %rax,0xf8(%rcx)\n\t"       /* context->Rip */
                   "fxsave 0x100(%rcx)\n\t"         /* context->FltSave */
                   "ret" );

/******************************************************************************
 *              RtlWow64GetThreadContext  (NTDLL.@)
 */
NTSTATUS WINAPI RtlWow64GetThreadContext( HANDLE handle, WOW64_CONTEXT *context )
{
    BOOL self;
    NTSTATUS ret;
    context_t server_context;
    unsigned int server_flags = wow64_get_server_context_flags( context->ContextFlags );

    if ((ret = get_thread_context( handle, &server_context, server_flags, &self ))) return ret;
    if (self) return STATUS_INVALID_PARAMETER;
    return wow64_context_from_server( context, &server_context );
}


/******************************************************************************
 *              RtlWow64SetThreadContext  (NTDLL.@)
 */
NTSTATUS WINAPI RtlWow64SetThreadContext( HANDLE handle, const WOW64_CONTEXT *context )
{
    BOOL self;
    context_t server_context;

    wow64_context_to_server( &server_context, context );
    return set_thread_context( handle, &server_context, &self );
}


extern void raise_func_trampoline( EXCEPTION_RECORD *rec, CONTEXT *context, raise_func func );
__ASM_GLOBAL_FUNC( raise_func_trampoline,
                   __ASM_CFI(".cfi_signal_frame\n\t")
                   __ASM_CFI(".cfi_def_cfa %rbp,160\n\t")  /* red zone + rip + rbp + rdi + rsi */
                   __ASM_CFI(".cfi_rel_offset %rip,24\n\t")
                   __ASM_CFI(".cfi_rel_offset %rbp,16\n\t")
                   __ASM_CFI(".cfi_rel_offset %rdi,8\n\t")
                   __ASM_CFI(".cfi_rel_offset %rsi,0\n\t")
                   "call *%rdx\n\t"
                   "int $3")

/***********************************************************************
 *           setup_exception
 *
 * Setup a proper stack frame for the raise function, and modify the
 * sigcontext so that the return from the signal handler will call
 * the raise function.
 */
static EXCEPTION_RECORD *setup_exception( ucontext_t *sigcontext, raise_func func )
{
    struct stack_layout
    {
        CONTEXT           context;
        EXCEPTION_RECORD  rec;
        ULONG64           rsi;
        ULONG64           rdi;
        ULONG64           rbp;
        ULONG64           rip;
        ULONG64           red_zone[16];
    } *stack;
    ULONG64 *rsp_ptr;
    DWORD exception_code = 0;

    stack = (struct stack_layout *)(RSP_sig(sigcontext) & ~15);

    /* stack sanity checks */

    if (is_inside_signal_stack( stack ))
    {
        ERR( "nested exception on signal stack in thread %04x eip %016lx esp %016lx stack %p-%p\n",
             GetCurrentThreadId(), (ULONG_PTR)RIP_sig(sigcontext), (ULONG_PTR)RSP_sig(sigcontext),
             NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
        abort_thread(1);
    }

    if (stack - 1 > stack || /* check for overflow in subtraction */
        (char *)stack <= (char *)NtCurrentTeb()->DeallocationStack ||
        (char *)stack > (char *)NtCurrentTeb()->Tib.StackBase)
    {
        WARN( "exception outside of stack limits in thread %04x eip %016lx esp %016lx stack %p-%p\n",
              GetCurrentThreadId(), (ULONG_PTR)RIP_sig(sigcontext), (ULONG_PTR)RSP_sig(sigcontext),
              NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
    }
    else if ((char *)(stack - 1) < (char *)NtCurrentTeb()->DeallocationStack + 4096)
    {
        /* stack overflow on last page, unrecoverable */
        UINT diff = (char *)NtCurrentTeb()->DeallocationStack + 4096 - (char *)(stack - 1);
        ERR( "stack overflow %u bytes in thread %04x eip %016lx esp %016lx stack %p-%p-%p\n",
             diff, GetCurrentThreadId(), (ULONG_PTR)RIP_sig(sigcontext),
             (ULONG_PTR)RSP_sig(sigcontext), NtCurrentTeb()->DeallocationStack,
             NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
        abort_thread(1);
    }
    else if ((char *)(stack - 1) < (char *)NtCurrentTeb()->Tib.StackLimit)
    {
        /* stack access below stack limit, may be recoverable */
        if (virtual_handle_stack_fault( stack - 1 )) exception_code = EXCEPTION_STACK_OVERFLOW;
        else
        {
            UINT diff = (char *)NtCurrentTeb()->Tib.StackLimit - (char *)(stack - 1);
            ERR( "stack overflow %u bytes in thread %04x eip %016lx esp %016lx stack %p-%p-%p\n",
                 diff, GetCurrentThreadId(), (ULONG_PTR)RIP_sig(sigcontext),
                 (ULONG_PTR)RSP_sig(sigcontext), NtCurrentTeb()->DeallocationStack,
                 NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
            abort_thread(1);
        }
    }

    stack--;  /* push the stack_layout structure */
#if defined(VALGRIND_MAKE_MEM_UNDEFINED)
    VALGRIND_MAKE_MEM_UNDEFINED(stack, sizeof(*stack));
#elif defined(VALGRIND_MAKE_WRITABLE)
    VALGRIND_MAKE_WRITABLE(stack, sizeof(*stack));
#endif
    stack->rec.ExceptionRecord  = NULL;
    stack->rec.ExceptionCode    = exception_code;
    stack->rec.ExceptionFlags   = EXCEPTION_CONTINUABLE;
    stack->rec.ExceptionAddress = (void *)RIP_sig(sigcontext);
    stack->rec.NumberParameters = 0;
    save_context( &stack->context, sigcontext );

    /* store return address and %rbp without aligning, so that the offset is fixed */
    rsp_ptr = (ULONG64 *)RSP_sig(sigcontext) - 16;
    *(--rsp_ptr) = RIP_sig(sigcontext);
    *(--rsp_ptr) = RBP_sig(sigcontext);
    *(--rsp_ptr) = RDI_sig(sigcontext);
    *(--rsp_ptr) = RSI_sig(sigcontext);

    /* now modify the sigcontext to return to the raise function */
    RIP_sig(sigcontext) = (ULONG_PTR)raise_func_trampoline;
    RDI_sig(sigcontext) = (ULONG_PTR)&stack->rec;
    RSI_sig(sigcontext) = (ULONG_PTR)&stack->context;
    RDX_sig(sigcontext) = (ULONG_PTR)func;
    RBP_sig(sigcontext) = (ULONG_PTR)rsp_ptr;
    RSP_sig(sigcontext) = (ULONG_PTR)stack;
    /* clear single-step, direction, and align check flag */
    EFL_sig(sigcontext) &= ~(0x100|0x400|0x40000);

    return &stack->rec;
}


/***********************************************************************
 *           get_exception_context
 *
 * Get a pointer to the context built by setup_exception.
 */
static inline CONTEXT *get_exception_context( EXCEPTION_RECORD *rec )
{
    return (CONTEXT *)rec - 1;  /* cf. stack_layout structure */
}


/**********************************************************************
 *           find_function_info
 */
static RUNTIME_FUNCTION *find_function_info( ULONG64 pc, HMODULE module,
                                             RUNTIME_FUNCTION *func, ULONG size )
{
    int min = 0;
    int max = size/sizeof(*func) - 1;

    while (min <= max)
    {
        int pos = (min + max) / 2;
        if ((char *)pc < (char *)module + func[pos].BeginAddress) max = pos - 1;
        else if ((char *)pc >= (char *)module + func[pos].EndAddress) min = pos + 1;
        else
        {
            func += pos;
            while (func->UnwindData & 1)  /* follow chained entry */
                func = (RUNTIME_FUNCTION *)((char *)module + (func->UnwindData & ~1));
            return func;
        }
    }
    return NULL;
}

/**********************************************************************
 *           lookup_function_info
 */
static RUNTIME_FUNCTION *lookup_function_info( ULONG64 pc, ULONG64 *base, LDR_MODULE **module )
{
    RUNTIME_FUNCTION *func = NULL;
    struct dynamic_unwind_entry *entry;
    ULONG size;

    /* PE module or wine module */
    if (!LdrFindEntryForAddress( (void *)pc, module ))
    {
        *base = (ULONG64)(*module)->BaseAddress;
        if ((func = RtlImageDirectoryEntryToData( (*module)->BaseAddress, TRUE,
                                                  IMAGE_DIRECTORY_ENTRY_EXCEPTION, &size )))
        {
            /* lookup in function table */
            func = find_function_info( pc, (*module)->BaseAddress, func, size );
        }
    }
    else
    {
        *module = NULL;

        RtlEnterCriticalSection( &dynamic_unwind_section );
        LIST_FOR_EACH_ENTRY( entry, &dynamic_unwind_list, struct dynamic_unwind_entry, entry )
        {
            if (pc >= entry->base && pc < entry->base + entry->size)
            {
                *base = entry->base;

                /* use callback or lookup in function table */
                if (entry->callback)
                    func = entry->callback( pc, entry->context );
                else
                    func = find_function_info( pc, (HMODULE)entry->base, entry->table, entry->table_size );
                break;
            }
        }
        RtlLeaveCriticalSection( &dynamic_unwind_section );
    }

    return func;
}

static DWORD nested_exception_handler( EXCEPTION_RECORD *rec, EXCEPTION_REGISTRATION_RECORD *frame,
                                       CONTEXT *context, EXCEPTION_REGISTRATION_RECORD **dispatcher )
{
    if (rec->ExceptionFlags & (EH_UNWINDING | EH_EXIT_UNWIND)) return ExceptionContinueSearch;

    /* FIXME */
    return ExceptionNestedException;
}

/**********************************************************************
 *           call_handler
 *
 * Call a single exception handler.
 * FIXME: Handle nested exceptions.
 */
static DWORD call_handler( EXCEPTION_RECORD *rec, CONTEXT *context, DISPATCHER_CONTEXT *dispatch )
{
    EXCEPTION_REGISTRATION_RECORD frame;
    DWORD res;

    frame.Handler = nested_exception_handler;
    __wine_push_frame( &frame );

    TRACE( "calling handler %p (rec=%p, frame=0x%lx context=%p, dispatch=%p)\n",
           dispatch->LanguageHandler, rec, dispatch->EstablisherFrame, dispatch->ContextRecord, dispatch );
    res = dispatch->LanguageHandler( rec, dispatch->EstablisherFrame, context, dispatch );
    TRACE( "handler at %p returned %u\n", dispatch->LanguageHandler, res );

    __wine_pop_frame( &frame );
    return res;
}


/**********************************************************************
 *           call_teb_handler
 *
 * Call a single exception handler from the TEB chain.
 * FIXME: Handle nested exceptions.
 */
static DWORD call_teb_handler( EXCEPTION_RECORD *rec, CONTEXT *context, DISPATCHER_CONTEXT *dispatch,
                                  EXCEPTION_REGISTRATION_RECORD *teb_frame )
{
    DWORD res;

    TRACE( "calling TEB handler %p (rec=%p, frame=%p context=%p, dispatch=%p)\n",
           teb_frame->Handler, rec, teb_frame, dispatch->ContextRecord, dispatch );
    res = teb_frame->Handler( rec, teb_frame, context, (EXCEPTION_REGISTRATION_RECORD**)dispatch );
    TRACE( "handler at %p returned %u\n", teb_frame->Handler, res );
    return res;
}


/**********************************************************************
 *           call_stack_handlers
 *
 * Call the stack handlers chain.
 */
static NTSTATUS call_stack_handlers( EXCEPTION_RECORD *rec, CONTEXT *orig_context )
{
    EXCEPTION_REGISTRATION_RECORD *teb_frame = NtCurrentTeb()->Tib.ExceptionList;
    UNWIND_HISTORY_TABLE table;
    DISPATCHER_CONTEXT dispatch;
    CONTEXT context;
    LDR_MODULE *module;
    NTSTATUS status;

    context = *orig_context;
    dispatch.TargetIp      = 0;
    dispatch.ContextRecord = &context;
    dispatch.HistoryTable  = &table;
    for (;;)
    {
        /* FIXME: should use the history table to make things faster */

        dispatch.ImageBase = 0;
        dispatch.ControlPc = context.Rip;
        dispatch.ScopeIndex = 0;

        /* first look for PE exception information */

        if ((dispatch.FunctionEntry = lookup_function_info( dispatch.ControlPc, &dispatch.ImageBase, &module )))
        {
            dispatch.LanguageHandler = RtlVirtualUnwind( UNW_FLAG_EHANDLER, dispatch.ImageBase,
                                                         dispatch.ControlPc, dispatch.FunctionEntry,
                                                         &context, &dispatch.HandlerData,
                                                         &dispatch.EstablisherFrame, NULL );
            goto unwind_done;
        }

        /* then look for host system exception information */

        if (!module || (module->Flags & LDR_WINE_INTERNAL))
        {
            BOOL got_info = FALSE;
            struct dwarf_eh_bases bases;
            const struct dwarf_fde *fde = _Unwind_Find_FDE( (void *)(dispatch.ControlPc - 1), &bases );

            if (fde)
            {
                status = dwarf_virtual_unwind( dispatch.ControlPc, &dispatch.EstablisherFrame, &context,
                                               fde, &bases, &dispatch.LanguageHandler, &dispatch.HandlerData );
                if (status != STATUS_SUCCESS) return status;
                got_info = TRUE;
            }
#ifdef HAVE_LIBUNWIND_H
            else
            {
                status = libunwind_virtual_unwind( dispatch.ControlPc, &got_info, &dispatch.EstablisherFrame, &context,
                                                   &dispatch.LanguageHandler, &dispatch.HandlerData );
                if (status != STATUS_SUCCESS) return status;
            }
#endif

            if (got_info)
            {
                dispatch.FunctionEntry = NULL;
                if (dispatch.LanguageHandler && !module)
                {
                    FIXME( "calling personality routine in system library not supported yet\n" );
                    dispatch.LanguageHandler = NULL;
                }
                goto unwind_done;
            }
        }
        else WARN( "exception data not found in %s\n", debugstr_w(module->BaseDllName.Buffer) );

        context.Rip = *(ULONG64 *)context.Rsp;
        context.Rsp = context.Rsp + sizeof(ULONG64);
        dispatch.EstablisherFrame = context.Rsp;
        dispatch.LanguageHandler = NULL;

    unwind_done:
        if (!dispatch.EstablisherFrame) break;

        if ((dispatch.EstablisherFrame & 7) ||
            dispatch.EstablisherFrame < (ULONG64)NtCurrentTeb()->Tib.StackLimit ||
            dispatch.EstablisherFrame > (ULONG64)NtCurrentTeb()->Tib.StackBase)
        {
            ERR( "invalid frame %lx (%p-%p)\n", dispatch.EstablisherFrame,
                 NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
            rec->ExceptionFlags |= EH_STACK_INVALID;
            break;
        }

        if (dispatch.LanguageHandler)
        {
            switch (call_handler( rec, orig_context, &dispatch ))
            {
            case ExceptionContinueExecution:
                if (rec->ExceptionFlags & EH_NONCONTINUABLE) return STATUS_NONCONTINUABLE_EXCEPTION;
                return STATUS_SUCCESS;
            case ExceptionContinueSearch:
                break;
            case ExceptionNestedException:
                FIXME( "nested exception\n" );
                break;
            case ExceptionCollidedUnwind: {
                ULONG64 frame;

                context = *dispatch.ContextRecord;
                dispatch.ContextRecord = &context;
                RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase,
                        dispatch.ControlPc, dispatch.FunctionEntry,
                        &context, NULL, &frame, NULL );
                goto unwind_done;
            }
            default:
                return STATUS_INVALID_DISPOSITION;
            }
        }
        /* hack: call wine handlers registered in the tib list */
        else while ((ULONG64)teb_frame < context.Rsp)
        {
            TRACE( "found wine frame %p rsp %lx handler %p\n",
                    teb_frame, context.Rsp, teb_frame->Handler );
            dispatch.EstablisherFrame = (ULONG64)teb_frame;
            switch (call_teb_handler( rec, orig_context, &dispatch, teb_frame ))
            {
            case ExceptionContinueExecution:
                if (rec->ExceptionFlags & EH_NONCONTINUABLE) return STATUS_NONCONTINUABLE_EXCEPTION;
                return STATUS_SUCCESS;
            case ExceptionContinueSearch:
                break;
            case ExceptionNestedException:
                FIXME( "nested exception\n" );
                break;
            case ExceptionCollidedUnwind: {
                ULONG64 frame;

                context = *dispatch.ContextRecord;
                dispatch.ContextRecord = &context;
                RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase,
                        dispatch.ControlPc, dispatch.FunctionEntry,
                        &context, NULL, &frame, NULL );
                teb_frame = teb_frame->Prev;
                goto unwind_done;
            }
            default:
                return STATUS_INVALID_DISPOSITION;
            }
            teb_frame = teb_frame->Prev;
        }

        if (context.Rsp == (ULONG64)NtCurrentTeb()->Tib.StackBase) break;
    }
    return STATUS_UNHANDLED_EXCEPTION;
}


/*******************************************************************
 *		NtRaiseException (NTDLL.@)
 */
NTSTATUS WINAPI NtRaiseException( EXCEPTION_RECORD *rec, CONTEXT *context, BOOL first_chance )
{
    NTSTATUS status;

    if (first_chance)
    {
        DWORD c;

        TRACE( "code=%x flags=%x addr=%p ip=%lx tid=%04x\n",
               rec->ExceptionCode, rec->ExceptionFlags, rec->ExceptionAddress,
               context->Rip, GetCurrentThreadId() );
        for (c = 0; c < min( EXCEPTION_MAXIMUM_PARAMETERS, rec->NumberParameters ); c++)
            TRACE( " info[%d]=%016lx\n", c, rec->ExceptionInformation[c] );
        if (rec->ExceptionCode == EXCEPTION_WINE_STUB)
        {
            if (rec->ExceptionInformation[1] >> 16)
                MESSAGE( "wine: Call from %p to unimplemented function %s.%s, aborting\n",
                         rec->ExceptionAddress,
                         (char*)rec->ExceptionInformation[0], (char*)rec->ExceptionInformation[1] );
            else
                MESSAGE( "wine: Call from %p to unimplemented function %s.%ld, aborting\n",
                         rec->ExceptionAddress,
                         (char*)rec->ExceptionInformation[0], rec->ExceptionInformation[1] );
        }
        else
        {
            TRACE(" rax=%016lx rbx=%016lx rcx=%016lx rdx=%016lx\n",
                  context->Rax, context->Rbx, context->Rcx, context->Rdx );
            TRACE(" rsi=%016lx rdi=%016lx rbp=%016lx rsp=%016lx\n",
                  context->Rsi, context->Rdi, context->Rbp, context->Rsp );
            TRACE("  r8=%016lx  r9=%016lx r10=%016lx r11=%016lx\n",
                  context->R8, context->R9, context->R10, context->R11 );
            TRACE(" r12=%016lx r13=%016lx r14=%016lx r15=%016lx\n",
                  context->R12, context->R13, context->R14, context->R15 );
        }
        status = send_debug_event( rec, TRUE, context );
        if (status == DBG_CONTINUE || status == DBG_EXCEPTION_HANDLED) goto done;

        /* fix up instruction pointer in context for EXCEPTION_BREAKPOINT */
        if (rec->ExceptionCode == EXCEPTION_BREAKPOINT) context->Rip--;

        if (call_vectored_handlers( rec, context ) == EXCEPTION_CONTINUE_EXECUTION) goto done;

        if ((status = call_stack_handlers( rec, context )) == STATUS_SUCCESS) goto done;
        if (status != STATUS_UNHANDLED_EXCEPTION) return status;
    }

    /* last chance exception */

    status = send_debug_event( rec, FALSE, context );
    if (status != DBG_CONTINUE)
    {
        if (rec->ExceptionFlags & EH_STACK_INVALID)
            ERR("Exception frame is not in stack limits => unable to dispatch exception.\n");
        else if (rec->ExceptionCode == STATUS_NONCONTINUABLE_EXCEPTION)
            ERR("Process attempted to continue execution after noncontinuable exception.\n");
        else
            ERR("Unhandled exception code %x flags %x addr %p\n",
                rec->ExceptionCode, rec->ExceptionFlags, rec->ExceptionAddress );
        NtTerminateProcess( NtCurrentProcess(), rec->ExceptionCode );
    }

done:
    return NtSetContextThread( GetCurrentThread(), context );
}


/**********************************************************************
 *		raise_segv_exception
 */
static void raise_segv_exception( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    NTSTATUS status;

    switch(rec->ExceptionCode)
    {
    case EXCEPTION_ACCESS_VIOLATION:
        if (rec->NumberParameters == 2)
        {
            if (!(rec->ExceptionCode = virtual_handle_fault( (void *)rec->ExceptionInformation[1],
                                                             rec->ExceptionInformation[0], FALSE )))
                set_cpu_context( context );
        }
        break;
    case EXCEPTION_BREAKPOINT:
        switch (rec->ExceptionInformation[0])
        {
            case 1: /* BREAKPOINT_PRINT */
            case 3: /* BREAKPOINT_LOAD_SYMBOLS */
            case 4: /* BREAKPOINT_UNLOAD_SYMBOLS */
            case 5: /* BREAKPOINT_COMMAND_STRING (>= Win2003) */
                set_cpu_context( context );
        }
        break;
    }
    status = NtRaiseException( rec, context, TRUE );
    raise_status( status, rec );
}


/**********************************************************************
 *		raise_trap_exception
 */
static void raise_trap_exception( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    NTSTATUS status;

    if (rec->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        /* when single stepping can't tell whether this is a hw bp or a
         * single step interrupt. try to avoid as much overhead as possible
         * and only do a server call if there is any hw bp enabled. */

        if( !(context->EFlags & 0x100) || (amd64_thread_data()->dr7 & 0xff) )
        {
            /* (possible) hardware breakpoint, fetch the debug registers */
            DWORD saved_flags = context->ContextFlags;
            context->ContextFlags = CONTEXT_DEBUG_REGISTERS;
            NtGetContextThread(GetCurrentThread(), context);
            context->ContextFlags |= saved_flags;  /* restore flags */
        }

        context->EFlags &= ~0x100;  /* clear single-step flag */
    }

    status = NtRaiseException( rec, context, TRUE );
    raise_status( status, rec );
}


/**********************************************************************
 *		raise_generic_exception
 *
 * Generic raise function for exceptions that don't need special treatment.
 */
static void raise_generic_exception( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    NTSTATUS status = NtRaiseException( rec, context, TRUE );
    raise_status( status, rec );
}


/***********************************************************************
 *           is_privileged_instr
 *
 * Check if the fault location is a privileged instruction.
 */
static inline DWORD is_privileged_instr( CONTEXT *context )
{
    const BYTE *instr = (BYTE *)context->Rip;
    unsigned int prefix_count = 0;

    for (;;) switch(*instr)
    {
    /* instruction prefixes */
    case 0x2e:  /* %cs: */
    case 0x36:  /* %ss: */
    case 0x3e:  /* %ds: */
    case 0x26:  /* %es: */
    case 0x40:  /* rex */
    case 0x41:  /* rex */
    case 0x42:  /* rex */
    case 0x43:  /* rex */
    case 0x44:  /* rex */
    case 0x45:  /* rex */
    case 0x46:  /* rex */
    case 0x47:  /* rex */
    case 0x48:  /* rex */
    case 0x49:  /* rex */
    case 0x4a:  /* rex */
    case 0x4b:  /* rex */
    case 0x4c:  /* rex */
    case 0x4d:  /* rex */
    case 0x4e:  /* rex */
    case 0x4f:  /* rex */
    case 0x64:  /* %fs: */
    case 0x65:  /* %gs: */
    case 0x66:  /* opcode size */
    case 0x67:  /* addr size */
    case 0xf0:  /* lock */
    case 0xf2:  /* repne */
    case 0xf3:  /* repe */
        if (++prefix_count >= 15) return EXCEPTION_ILLEGAL_INSTRUCTION;
        instr++;
        continue;

    case 0x0f: /* extended instruction */
        switch(instr[1])
        {
        case 0x06: /* clts */
        case 0x08: /* invd */
        case 0x09: /* wbinvd */
        case 0x20: /* mov crX, reg */
        case 0x21: /* mov drX, reg */
        case 0x22: /* mov reg, crX */
        case 0x23: /* mov reg drX */
            return EXCEPTION_PRIV_INSTRUCTION;
        }
        return 0;
    case 0x6c: /* insb (%dx) */
    case 0x6d: /* insl (%dx) */
    case 0x6e: /* outsb (%dx) */
    case 0x6f: /* outsl (%dx) */
    case 0xcd: /* int $xx */
    case 0xe4: /* inb al,XX */
    case 0xe5: /* in (e)ax,XX */
    case 0xe6: /* outb XX,al */
    case 0xe7: /* out XX,(e)ax */
    case 0xec: /* inb (%dx),%al */
    case 0xed: /* inl (%dx),%eax */
    case 0xee: /* outb %al,(%dx) */
    case 0xef: /* outl %eax,(%dx) */
    case 0xf4: /* hlt */
    case 0xfa: /* cli */
    case 0xfb: /* sti */
        return EXCEPTION_PRIV_INSTRUCTION;
    default:
        return 0;
    }
}


/***********************************************************************
 *           handle_interrupt
 *
 * Handle an interrupt.
 */
static inline BOOL handle_interrupt( unsigned int interrupt, EXCEPTION_RECORD *rec, CONTEXT *context )
{
    switch(interrupt)
    {
    case 0x2c:
        rec->ExceptionCode = STATUS_ASSERTION_FAILURE;
        return TRUE;
    case 0x2d:
        context->Rip += 3;
        rec->ExceptionCode = EXCEPTION_BREAKPOINT;
        rec->ExceptionAddress = (void *)context->Rip;
        rec->NumberParameters = 1;
        rec->ExceptionInformation[0] = context->Rax;
        return TRUE;
    default:
        return FALSE;
    }
}

DWORD mapping_tls_index;
static int is_winedevice_stored = -1;
static int is_winedevice(void)
{
    if(is_winedevice_stored != -1) return is_winedevice_stored;
    /* detect whether we are 64-bit winedevice */
    UNICODE_STRING winedeviceUS;
    static const WCHAR winedeviceW[] = {'C',':','\\','w','i','n','d','o','w','s','\\','s','y','s','t','e','m','3','2','\\','w','i','n','e','d','e','v','i','c','e','.','e','x','e',0};

    RtlCreateUnicodeString(&winedeviceUS, winedeviceW);

    is_winedevice_stored = !RtlCompareUnicodeString(&winedeviceUS, &NtCurrentTeb()->Peb->ProcessParameters->ImagePathName, TRUE);
    return is_winedevice_stored;
}


static int map_userspace(siginfo_t *siginfo, ucontext_t *sigcontext, HANDLE process)
{
    void *fault_addr;
    void *page_addr;
    SIZE_T bytes_read;
    NTSTATUS stat;

    fault_addr = siginfo->si_addr;

    if(fault_addr < (void*) 0x0000FFFF)
    {
        /* probably a null pointer issue */
        return 0;
    }

    FIXME("trying to access address %p in \"user-space\"\n", fault_addr);

    /* if the access is read, we don't handle this */
    if(ERROR_sig(sigcontext) & 0x2)
    {
        FIXME("we don't handle write operations\n");
        return 0;
    }

    if(!process)
    {
        FIXME("no user-space process known\n");
        return 0;
    }

    /* round down the address to a page*/
    page_addr = fault_addr - ((long) fault_addr % getpagesize());

    /* map the memory*/
    if(page_addr != mmap(page_addr, getpagesize() * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0))
    {
        FIXME("unable to map memory for user-space access\n");
        return 0;
    }

    /* read the memory from the desired process into our map, 32 is the maximum bytes read by one instruction */
    stat = NtReadVirtualMemory(process, fault_addr, fault_addr, 32, &bytes_read);

    if(stat || !bytes_read)
    {
        /* try again, read one byte this time*/
        stat = NtReadVirtualMemory(process, fault_addr, fault_addr, 1, &bytes_read);

        if(stat || !bytes_read)
        {
            FIXME("Unable to read memory from user space stat=%u bytes_read=%lu", stat, bytes_read);
            munmap(page_addr, getpagesize() * 2);
            return 0;
        }
    }

    /* enable tracing so we unmap after instruction */
    sigcontext->uc_mcontext.gregs[REG_EFL] |= 0x100;

    NtCurrentTeb()->TlsSlots[mapping_tls_index] = page_addr;

    return 1;
}


/**********************************************************************
 *		segv_handler
 *
 * Handler for SIGSEGV and related errors.
 */
static void segv_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD *rec;
    ucontext_t *ucontext = sigcontext;

    if(is_winedevice() && TRAP_sig(ucontext) == TRAP_x86_PAGEFLT)
    {
      /* see if we can access user space address */
      if(map_userspace(siginfo, ucontext, (HANDLE)(ULONGLONG) NtCurrentTeb()->Peb->Reserved[0]))
        return;
    }

    /* check for page fault inside the thread stack */
    if (TRAP_sig(ucontext) == TRAP_x86_PAGEFLT &&
        (char *)siginfo->si_addr >= (char *)NtCurrentTeb()->DeallocationStack &&
        (char *)siginfo->si_addr < (char *)NtCurrentTeb()->Tib.StackBase &&
        virtual_handle_stack_fault( siginfo->si_addr ))
    {
        /* check if this was the last guard page */
        if ((char *)siginfo->si_addr < (char *)NtCurrentTeb()->DeallocationStack + 2*4096)
        {
            rec = setup_exception( sigcontext, raise_segv_exception );
            rec->ExceptionCode = EXCEPTION_STACK_OVERFLOW;
        }
        return;
    }

    rec = setup_exception( sigcontext, raise_segv_exception );
    if (rec->ExceptionCode == EXCEPTION_STACK_OVERFLOW) return;

    switch(TRAP_sig(ucontext))
    {
    case TRAP_x86_OFLOW:   /* Overflow exception */
        rec->ExceptionCode = EXCEPTION_INT_OVERFLOW;
        break;
    case TRAP_x86_BOUND:   /* Bound range exception */
        rec->ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
        break;
    case TRAP_x86_PRIVINFLT:   /* Invalid opcode exception */
        rec->ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;
        break;
    case TRAP_x86_STKFLT:  /* Stack fault */
        rec->ExceptionCode = EXCEPTION_STACK_OVERFLOW;
        break;
    case TRAP_x86_SEGNPFLT:  /* Segment not present exception */
    case TRAP_x86_PROTFLT:   /* General protection fault */
    case TRAP_x86_UNKNOWN:   /* Unknown fault code */
        {
            CONTEXT *win_context = get_exception_context( rec );
            WORD err = ERROR_sig(ucontext);
            if (!err && (rec->ExceptionCode = is_privileged_instr( win_context ))) break;
            if ((err & 7) == 2 && handle_interrupt( err >> 3, rec, win_context )) break;
            rec->ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
            rec->NumberParameters = 2;
            rec->ExceptionInformation[0] = 0;
            rec->ExceptionInformation[1] = 0xffffffffffffffff;
        }
        break;
    case TRAP_x86_PAGEFLT:  /* Page fault */
        rec->ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
        rec->NumberParameters = 2;
        rec->ExceptionInformation[0] = (ERROR_sig(ucontext) >> 1) & 0x09;
        rec->ExceptionInformation[1] = (ULONG_PTR)siginfo->si_addr;
        break;
    case TRAP_x86_ALIGNFLT:  /* Alignment check exception */
        rec->ExceptionCode = EXCEPTION_DATATYPE_MISALIGNMENT;
        break;
    default:
        ERR( "Got unexpected trap %ld\n", (ULONG_PTR)TRAP_sig(ucontext) );
        /* fall through */
    case TRAP_x86_NMI:       /* NMI interrupt */
    case TRAP_x86_DNA:       /* Device not available exception */
    case TRAP_x86_DOUBLEFLT: /* Double fault exception */
    case TRAP_x86_TSSFLT:    /* Invalid TSS exception */
    case TRAP_x86_MCHK:      /* Machine check exception */
    case TRAP_x86_CACHEFLT:  /* Cache flush exception */
        rec->ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;
        break;
    }
}

static int unmap_userspace(siginfo_t *siginfo, void *sigcontext)
{
    ucontext_t *ucontext;
    void *mapping;

    ucontext = (ucontext_t *) sigcontext;
    mapping = NtCurrentTeb()->TlsSlots[mapping_tls_index];

    /* TODO: validate instruction pointer */
    if(!mapping) return 1;

    if(munmap(mapping, getpagesize() * 2))
    {
        FIXME("unmap unsuccessful");
    }

    ucontext->uc_mcontext.gregs[REG_EFL] &= 0xFFFFFEFF;

    NtCurrentTeb()->TlsSlots[mapping_tls_index] = 0;

    return 1;
}

/**********************************************************************
 *		trap_handler
 *
 * Handler for SIGTRAP.
 */
static void trap_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD *rec;

    if(siginfo->si_code == TRAP_TRACE && is_winedevice() && unmap_userspace(siginfo, sigcontext)) return;

    rec = setup_exception( sigcontext, raise_trap_exception );

    switch (siginfo->si_code)
    {
    case TRAP_TRACE:  /* Single-step exception */
    case 4 /* TRAP_HWBKPT */: /* Hardware breakpoint exception */
        rec->ExceptionCode = EXCEPTION_SINGLE_STEP;
        break;
    case TRAP_BRKPT:   /* Breakpoint exception */
        /* Check if this is actuallly icebp instruction */
        if (((unsigned char *)rec->ExceptionAddress)[-1] == 0xF1)
        {
            rec->ExceptionCode = EXCEPTION_SINGLE_STEP;
            break;
        }
        rec->ExceptionAddress = (char *)rec->ExceptionAddress - 1;  /* back up over the int3 instruction */
        /* fall through */
    default:
        rec->ExceptionCode = EXCEPTION_BREAKPOINT;
        rec->NumberParameters = 1;
        rec->ExceptionInformation[0] = 0;
        break;
    }
}

/**********************************************************************
 *		fpe_handler
 *
 * Handler for SIGFPE.
 */
static void fpe_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD *rec = setup_exception( sigcontext, raise_generic_exception );

    switch (siginfo->si_code)
    {
    case FPE_FLTSUB:
        rec->ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
        break;
    case FPE_INTDIV:
        rec->ExceptionCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
        break;
    case FPE_INTOVF:
        rec->ExceptionCode = EXCEPTION_INT_OVERFLOW;
        break;
    case FPE_FLTDIV:
        rec->ExceptionCode = EXCEPTION_FLT_DIVIDE_BY_ZERO;
        break;
    case FPE_FLTOVF:
        rec->ExceptionCode = EXCEPTION_FLT_OVERFLOW;
        break;
    case FPE_FLTUND:
        rec->ExceptionCode = EXCEPTION_FLT_UNDERFLOW;
        break;
    case FPE_FLTRES:
        rec->ExceptionCode = EXCEPTION_FLT_INEXACT_RESULT;
        break;
    case FPE_FLTINV:
    default:
        rec->ExceptionCode = EXCEPTION_FLT_INVALID_OPERATION;
        break;
    }
}

/**********************************************************************
 *		int_handler
 *
 * Handler for SIGINT.
 */
static void int_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    if (!dispatch_signal(SIGINT))
    {
        EXCEPTION_RECORD *rec = setup_exception( sigcontext, raise_generic_exception );
        rec->ExceptionCode = CONTROL_C_EXIT;
    }
}


/**********************************************************************
 *		abrt_handler
 *
 * Handler for SIGABRT.
 */
static void abrt_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD *rec = setup_exception( sigcontext, raise_generic_exception );
    rec->ExceptionCode = EXCEPTION_WINE_ASSERTION;
    rec->ExceptionFlags = EH_NONCONTINUABLE;
}


/**********************************************************************
 *		quit_handler
 *
 * Handler for SIGQUIT.
 */
static void quit_handler( int signal, siginfo_t *siginfo, void *ucontext )
{
    abort_thread(0);
}


/**********************************************************************
 *		usr1_handler
 *
 * Handler for SIGUSR1, used to signal a thread that it got suspended.
 */
static void usr1_handler( int signal, siginfo_t *siginfo, void *ucontext )
{
    CONTEXT context;

    save_context( &context, ucontext );
    wait_suspend( &context );
    restore_context( &context, ucontext );
}


/***********************************************************************
 *           __wine_set_signal_handler   (NTDLL.@)
 */
int CDECL __wine_set_signal_handler(unsigned int sig, wine_signal_handler wsh)
{
    if (sig >= ARRAY_SIZE(handlers)) return -1;
    if (handlers[sig] != NULL) return -2;
    handlers[sig] = wsh;
    return 0;
}


/**********************************************************************
 *		signal_alloc_thread
 */
NTSTATUS signal_alloc_thread( TEB **teb )
{
    static size_t sigstack_zero_bits;
    SIZE_T size;
    NTSTATUS status;

    if (!sigstack_zero_bits)
    {
        size_t min_size = teb_size + max( MINSIGSTKSZ, 8192 );
        /* find the first power of two not smaller than min_size */
        sigstack_zero_bits = 12;
        while ((1u << sigstack_zero_bits) < min_size) sigstack_zero_bits++;
        signal_stack_size = (1 << sigstack_zero_bits) - teb_size;
        assert( sizeof(TEB) <= teb_size );
    }

    size = 1 << sigstack_zero_bits;
    *teb = NULL;
    if (!(status = NtAllocateVirtualMemory( NtCurrentProcess(), (void **)teb, sigstack_zero_bits,
                                            &size, MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE )))
    {
        (*teb)->Tib.Self = &(*teb)->Tib;
        (*teb)->Tib.ExceptionList = (void *)~0UL;
    }
    return status;
}


/**********************************************************************
 *		signal_free_thread
 */
void signal_free_thread( TEB *teb )
{
    SIZE_T size = 0;

    NtFreeVirtualMemory( NtCurrentProcess(), (void **)&teb, &size, MEM_RELEASE );
}

#ifdef __APPLE__
/**********************************************************************
 *		mac_thread_gsbase
 */
static void *mac_thread_gsbase(void)
{
    static int gsbase_offset = -1;
    void *ret;

    if (gsbase_offset < 0)
    {
        /* Search for the array of TLS slots within the pthread data structure.
           That's what the macOS pthread implementation uses for gsbase. */
        const void* const sentinel1 = (const void*)0x2bffb6b4f11228ae;
        const void* const sentinel2 = (const void*)0x0845a7ff6ab76707;
        int rc;
        pthread_key_t key;
        const void** p = (const void**)pthread_self();
        int i;

        gsbase_offset = 0;
        if ((rc = pthread_key_create(&key, NULL)))
        {
            ERR("failed to create sentinel key for gsbase search: %d\n", rc);
            return NULL;
        }

        pthread_setspecific(key, sentinel1);

        for (i = key + 1; i < 2000; i++) /* arbitrary limit */
        {
            if (p[i] == sentinel1)
            {
                pthread_setspecific(key, sentinel2);

                if (p[i] == sentinel2)
                {
                    gsbase_offset = (i - key) * sizeof(*p);
                    break;
                }

                pthread_setspecific(key, sentinel1);
            }
        }

        pthread_key_delete(key);
    }

    if (gsbase_offset)
    {
        ret = (char*)pthread_self() + gsbase_offset;
        TRACE("pthread_self() %p + offset 0x%08x -> gsbase %p\n", pthread_self(), gsbase_offset, ret);
    }
    else
    {
        ret = NULL;
        ERR("failed to locate gsbase; won't be able to poke ThreadLocalStoragePointer into pthread TLS; expect crashes\n");
    }

    return ret;
}
#endif


/**********************************************************************
 *		signal_init_thread
 */
void signal_init_thread( TEB *teb )
{
    const WORD fpu_cw = 0x27f;
    stack_t ss;

#if defined __linux__
    arch_prctl( ARCH_SET_GS, teb );
#elif defined (__FreeBSD__) || defined (__FreeBSD_kernel__)
    amd64_set_gsbase( teb );
#elif defined(__NetBSD__)
    sysarch( X86_64_SET_GSBASE, &teb );
#elif defined (__APPLE__)
    __asm__ volatile (".byte 0x65\n\tmovq %0,%c1"
                      :
                      : "r" (teb->Tib.Self), "n" (FIELD_OFFSET(TEB, Tib.Self)));
    __asm__ volatile (".byte 0x65\n\tmovq %0,%c1"
                      :
                      : "r" (teb->ThreadLocalStoragePointer), "n" (FIELD_OFFSET(TEB, ThreadLocalStoragePointer)));

    /* alloc_tls_slot() needs to poke a value to an address relative to each
       thread's gsbase.  Have each thread record its gsbase pointer into its
       TEB so alloc_tls_slot() can find it. */
    teb->Reserved5[0] = mac_thread_gsbase();
#else
# error Please define setting %gs for your architecture
#endif

    ss.ss_sp    = (char *)teb + teb_size;
    ss.ss_size  = signal_stack_size;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) == -1) perror( "sigaltstack" );

#ifdef __GNUC__
    __asm__ volatile ("fninit; fldcw %0" : : "m" (fpu_cw));
#else
    FIXME("FPU setup not implemented for this platform.\n");
#endif
}

/**********************************************************************
 *		signal_init_process
 */
void signal_init_process(void)
{
    struct sigaction sig_act;

    sig_act.sa_mask = server_block_set;
    sig_act.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;

    sig_act.sa_sigaction = int_handler;
    if (sigaction( SIGINT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = fpe_handler;
    if (sigaction( SIGFPE, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = abrt_handler;
    if (sigaction( SIGABRT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = quit_handler;
    if (sigaction( SIGQUIT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = usr1_handler;
    if (sigaction( SIGUSR1, &sig_act, NULL ) == -1) goto error;

    sig_act.sa_sigaction = segv_handler;
    if (sigaction( SIGSEGV, &sig_act, NULL ) == -1) goto error;
    if (sigaction( SIGILL, &sig_act, NULL ) == -1) goto error;
#ifdef SIGBUS
    if (sigaction( SIGBUS, &sig_act, NULL ) == -1) goto error;
#endif

#ifdef SIGTRAP
    sig_act.sa_sigaction = trap_handler;
    if (sigaction( SIGTRAP, &sig_act, NULL ) == -1) goto error;
#else
    goto error;
#endif

    /* manually do what TlsAlloc does */
    RtlAcquirePebLock();
    mapping_tls_index = RtlFindClearBits( NtCurrentTeb()->Peb->TlsBitmap, 1, 1);
    RtlReleasePebLock();
    if(mapping_tls_index == ~0U) goto error;
    NtCurrentTeb()->TlsSlots[mapping_tls_index] = 0;

    return;

 error:
    perror("sigaction");
    exit(1);
}


/******************************************************************************
 *              RtlWow64SetThreadContext  (NTDLL.@)
 */
NTSTATUS WINAPI RtlWow64SetThreadContext( HANDLE handle, const WOW64_CONTEXT *context )
{
    return NtSetInformationThread( handle, ThreadWow64Context, context, sizeof(*context) );
}


static DWORD __cdecl nested_exception_handler( EXCEPTION_RECORD *rec, EXCEPTION_REGISTRATION_RECORD *frame,
                                               CONTEXT *context, EXCEPTION_REGISTRATION_RECORD **dispatcher )
{
    if (!(rec->ExceptionFlags & (EH_UNWINDING | EH_EXIT_UNWIND)))
        rec->ExceptionFlags |= EH_NESTED_CALL;

    return ExceptionContinueSearch;
}

/**********************************************************************
 *           call_handler
 *
 * Call a single exception handler.
 * FIXME: Handle nested exceptions.
 */
static DWORD call_handler( EXCEPTION_RECORD *rec, CONTEXT *context, DISPATCHER_CONTEXT *dispatch )
{
    EXCEPTION_REGISTRATION_RECORD frame;
    DWORD res;

    frame.Handler = nested_exception_handler;
    __wine_push_frame( &frame );

    TRACE( "calling handler %p (rec=%p, frame=%p context=%p, dispatch=%p)\n",
           dispatch->LanguageHandler, rec, (void *)dispatch->EstablisherFrame, dispatch->ContextRecord, dispatch );
    res = dispatch->LanguageHandler( rec, (void *)dispatch->EstablisherFrame, context, dispatch );
    TRACE( "handler at %p returned %u\n", dispatch->LanguageHandler, res );

    rec->ExceptionFlags &= EH_NONCONTINUABLE;
    __wine_pop_frame( &frame );
    return res;
}


/**********************************************************************
 *           call_teb_handler
 *
 * Call a single exception handler from the TEB chain.
 * FIXME: Handle nested exceptions.
 */
static DWORD call_teb_handler( EXCEPTION_RECORD *rec, CONTEXT *context, DISPATCHER_CONTEXT *dispatch,
                                  EXCEPTION_REGISTRATION_RECORD *teb_frame )
{
    DWORD res;

    TRACE( "calling TEB handler %p (rec=%p, frame=%p context=%p, dispatch=%p)\n",
           teb_frame->Handler, rec, teb_frame, dispatch->ContextRecord, dispatch );
    res = teb_frame->Handler( rec, teb_frame, context, (EXCEPTION_REGISTRATION_RECORD**)dispatch );
    TRACE( "handler at %p returned %u\n", teb_frame->Handler, res );
    return res;
}


/**********************************************************************
 *           call_stack_handlers
 *
 * Call the stack handlers chain.
 */
static NTSTATUS call_stack_handlers( EXCEPTION_RECORD *rec, CONTEXT *orig_context )
{
    EXCEPTION_REGISTRATION_RECORD *teb_frame = NtCurrentTeb()->Tib.ExceptionList;
    UNWIND_HISTORY_TABLE table;
    DISPATCHER_CONTEXT dispatch;
    CONTEXT context;
    NTSTATUS status;

    context = *orig_context;
    context.ContextFlags &= ~0x40; /* Clear xstate flag. */

    dispatch.TargetIp      = 0;
    dispatch.ContextRecord = &context;
    dispatch.HistoryTable  = &table;
    for (;;)
    {
        status = virtual_unwind( UNW_FLAG_EHANDLER, &dispatch, &context );
        if (status != STATUS_SUCCESS) return status;

    unwind_done:
        if (!dispatch.EstablisherFrame) break;

        if ((dispatch.EstablisherFrame & 7) ||
            dispatch.EstablisherFrame < (ULONG64)NtCurrentTeb()->Tib.StackLimit ||
            dispatch.EstablisherFrame > (ULONG64)NtCurrentTeb()->Tib.StackBase)
        {
            ERR( "invalid frame %p (%p-%p)\n", (void *)dispatch.EstablisherFrame,
                 NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
            rec->ExceptionFlags |= EH_STACK_INVALID;
            break;
        }

        if (dispatch.LanguageHandler)
        {
            switch (call_handler( rec, orig_context, &dispatch ))
            {
            case ExceptionContinueExecution:
                if (rec->ExceptionFlags & EH_NONCONTINUABLE) return STATUS_NONCONTINUABLE_EXCEPTION;
                return STATUS_SUCCESS;
            case ExceptionContinueSearch:
                break;
            case ExceptionNestedException:
                FIXME( "nested exception\n" );
                break;
            case ExceptionCollidedUnwind: {
                ULONG64 frame;

                context = *dispatch.ContextRecord;
                dispatch.ContextRecord = &context;
                RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase,
                        dispatch.ControlPc, dispatch.FunctionEntry,
                        &context, NULL, &frame, NULL );
                goto unwind_done;
            }
            default:
                return STATUS_INVALID_DISPOSITION;
            }
        }
        /* hack: call wine handlers registered in the tib list */
        else while ((ULONG64)teb_frame < context.Rsp)
        {
            TRACE( "found wine frame %p rsp %p handler %p\n",
                   teb_frame, (void *)context.Rsp, teb_frame->Handler );
            dispatch.EstablisherFrame = (ULONG64)teb_frame;
            switch (call_teb_handler( rec, orig_context, &dispatch, teb_frame ))
            {
            case ExceptionContinueExecution:
                if (rec->ExceptionFlags & EH_NONCONTINUABLE) return STATUS_NONCONTINUABLE_EXCEPTION;
                return STATUS_SUCCESS;
            case ExceptionContinueSearch:
                break;
            case ExceptionNestedException:
                FIXME( "nested exception\n" );
                break;
            case ExceptionCollidedUnwind: {
                ULONG64 frame;

                context = *dispatch.ContextRecord;
                dispatch.ContextRecord = &context;
                RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase,
                        dispatch.ControlPc, dispatch.FunctionEntry,
                        &context, NULL, &frame, NULL );
                teb_frame = teb_frame->Prev;
                goto unwind_done;
            }
            default:
                return STATUS_INVALID_DISPOSITION;
            }
            teb_frame = teb_frame->Prev;
        }

        if (context.Rsp == (ULONG64)NtCurrentTeb()->Tib.StackBase) break;
    }
    return STATUS_UNHANDLED_EXCEPTION;
}


NTSTATUS WINAPI dispatch_exception( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    NTSTATUS status;
    DWORD c;

    TRACE( "code=%x flags=%x addr=%p ip=%p tid=%04x\n",
           rec->ExceptionCode, rec->ExceptionFlags, rec->ExceptionAddress,
           (void *)context->Rip, GetCurrentThreadId() );
    for (c = 0; c < min( EXCEPTION_MAXIMUM_PARAMETERS, rec->NumberParameters ); c++)
        TRACE( " info[%d]=%016lx\n", c, rec->ExceptionInformation[c] );

    if (rec->ExceptionCode == EXCEPTION_WINE_STUB)
    {
        if (rec->ExceptionInformation[1] >> 16)
            MESSAGE( "wine: Call from %p to unimplemented function %s.%s, aborting\n",
                     rec->ExceptionAddress,
                     (char*)rec->ExceptionInformation[0], (char*)rec->ExceptionInformation[1] );
        else
            MESSAGE( "wine: Call from %p to unimplemented function %s.%ld, aborting\n",
                     rec->ExceptionAddress,
                     (char*)rec->ExceptionInformation[0], rec->ExceptionInformation[1] );
    }
    else
    {
        TRACE(" rax=%016lx rbx=%016lx rcx=%016lx rdx=%016lx\n",
              context->Rax, context->Rbx, context->Rcx, context->Rdx );
        TRACE(" rsi=%016lx rdi=%016lx rbp=%016lx rsp=%016lx\n",
              context->Rsi, context->Rdi, context->Rbp, context->Rsp );
        TRACE("  r8=%016lx  r9=%016lx r10=%016lx r11=%016lx\n",
              context->R8, context->R9, context->R10, context->R11 );
        TRACE(" r12=%016lx r13=%016lx r14=%016lx r15=%016lx\n",
              context->R12, context->R13, context->R14, context->R15 );
    }

    if (call_vectored_handlers( rec, context ) == EXCEPTION_CONTINUE_EXECUTION)
        NtContinue( context, FALSE );

    if ((status = call_stack_handlers( rec, context )) == STATUS_SUCCESS)
        NtContinue( context, FALSE );

    if (status != STATUS_UNHANDLED_EXCEPTION) RtlRaiseStatus( status );
    return NtRaiseException( rec, context, FALSE );
}


/*******************************************************************
 *		KiUserExceptionDispatcher (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( KiUserExceptionDispatcher,
                  "mov 0x98(%rsp),%rcx\n\t" /* context->Rsp */
                  "mov 0xf8(%rsp),%rdx\n\t" /* context->Rip */
                  "mov %rdx,-0x8(%rcx)\n\t"
                  "mov %rbp,-0x10(%rcx)\n\t"
                  "mov %rdi,-0x18(%rcx)\n\t"
                  "mov %rsi,-0x20(%rcx)\n\t"
                  "lea -0x20(%rcx),%rbp\n\t"
                  "mov %rsp,%rdx\n\t" /* context */
                  "lea 0x4f0(%rsp),%rcx\n\t" /* rec */
                  __ASM_SEH(".seh_pushreg %rbp\n\t")
                  __ASM_SEH(".seh_pushreg %rdi\n\t")
                  __ASM_SEH(".seh_pushreg %rsi\n\t")
                  __ASM_SEH(".seh_setframe %rbp,0\n\t")
                  __ASM_SEH(".seh_endprologue\n\t")

                  __ASM_CFI(".cfi_signal_frame\n\t")
                  __ASM_CFI(".cfi_adjust_cfa_offset 0x20\n\t")
                  __ASM_CFI(".cfi_def_cfa %rbp,0x20\n\t")
                  __ASM_CFI(".cfi_rel_offset %rip,0x18\n\t")
                  __ASM_CFI(".cfi_rel_offset %rbp,0x10\n\t")
                  __ASM_CFI(".cfi_rel_offset %rdi,0x8\n\t")
                  __ASM_CFI(".cfi_rel_offset %rsi,0\n\t")
                   "call " __ASM_NAME("dispatch_exception") "\n\t"
                  "int3")


/*******************************************************************
 *		KiUserApcDispatcher (NTDLL.@)
 */
void WINAPI dispatch_apc( CONTEXT *context, ULONG_PTR ctx, ULONG_PTR arg1, ULONG_PTR arg2,
                          PNTAPCFUNC func )
{
    func( ctx, arg1, arg2 );
    NtContinue( context, TRUE );
}

__ASM_GLOBAL_FUNC( KiUserApcDispatcher,
                  "addq $0x8,%rsp\n\t"
                  "mov 0x98(%rcx),%r10\n\t" /* context->Rsp */
                  "mov 0xf8(%rcx),%r11\n\t" /* context->Rip */
                  "mov %r11,-0x8(%r10)\n\t"
                  "mov %rbp,-0x10(%r10)\n\t"
                  "lea -0x10(%r10),%rbp\n\t"
                  __ASM_SEH(".seh_pushreg %rbp\n\t")
                  __ASM_SEH(".seh_setframe %rbp,0\n\t")
                  __ASM_SEH(".seh_endprologue\n\t")
                  __ASM_CFI(".cfi_signal_frame\n\t")
                  __ASM_CFI(".cfi_adjust_cfa_offset 0x10\n\t")
                  __ASM_CFI(".cfi_def_cfa %rbp,0x10\n\t")
                  __ASM_CFI(".cfi_rel_offset %rip,0x8\n\t")
                  __ASM_CFI(".cfi_rel_offset %rbp,0\n\t")
                   "call " __ASM_NAME("dispatch_apc") "\n\t"
                   "int3")


static ULONG64 get_int_reg( CONTEXT *context, int reg )
{
    return *(&context->Rax + reg);
}

static void set_int_reg( CONTEXT *context, KNONVOLATILE_CONTEXT_POINTERS *ctx_ptr, int reg, ULONG64 *val )
{
    *(&context->Rax + reg) = *val;
    if (ctx_ptr) ctx_ptr->u2.IntegerContext[reg] = val;
}

static void set_float_reg( CONTEXT *context, KNONVOLATILE_CONTEXT_POINTERS *ctx_ptr, int reg, M128A *val )
{
    /* Use a memcpy() to avoid issues if val is misaligned. */
    memcpy(&context->u.s.Xmm0 + reg, val, sizeof(*val));
    if (ctx_ptr) ctx_ptr->u.FloatingContext[reg] = val;
}

static int get_opcode_size( struct opcode op )
{
    switch (op.code)
    {
    case UWOP_ALLOC_LARGE:
        return 2 + (op.info != 0);
    case UWOP_SAVE_NONVOL:
    case UWOP_SAVE_XMM128:
    case UWOP_EPILOG:
        return 2;
    case UWOP_SAVE_NONVOL_FAR:
    case UWOP_SAVE_XMM128_FAR:
        return 3;
    default:
        return 1;
    }
}

static BOOL is_inside_epilog( BYTE *pc, ULONG64 base, const RUNTIME_FUNCTION *function )
{
    /* add or lea must be the first instruction, and it must have a rex.W prefix */
    if ((pc[0] & 0xf8) == 0x48)
    {
        switch (pc[1])
        {
        case 0x81: /* add $nnnn,%rsp */
            if (pc[0] == 0x48 && pc[2] == 0xc4)
            {
                pc += 7;
                break;
            }
            return FALSE;
        case 0x83: /* add $n,%rsp */
            if (pc[0] == 0x48 && pc[2] == 0xc4)
            {
                pc += 4;
                break;
            }
            return FALSE;
        case 0x8d: /* lea n(reg),%rsp */
            if (pc[0] & 0x06) return FALSE;  /* rex.RX must be cleared */
            if (((pc[2] >> 3) & 7) != 4) return FALSE;  /* dest reg mus be %rsp */
            if ((pc[2] & 7) == 4) return FALSE;  /* no SIB byte allowed */
            if ((pc[2] >> 6) == 1)  /* 8-bit offset */
            {
                pc += 4;
                break;
            }
            if ((pc[2] >> 6) == 2)  /* 32-bit offset */
            {
                pc += 7;
                break;
            }
            return FALSE;
        }
    }

    /* now check for various pop instructions */

    for (;;)
    {
        if ((*pc & 0xf0) == 0x40) pc++;  /* rex prefix */

        switch (*pc)
        {
        case 0x58: /* pop %rax/%r8 */
        case 0x59: /* pop %rcx/%r9 */
        case 0x5a: /* pop %rdx/%r10 */
        case 0x5b: /* pop %rbx/%r11 */
        case 0x5c: /* pop %rsp/%r12 */
        case 0x5d: /* pop %rbp/%r13 */
        case 0x5e: /* pop %rsi/%r14 */
        case 0x5f: /* pop %rdi/%r15 */
            pc++;
            continue;
        case 0xc2: /* ret $nn */
        case 0xc3: /* ret */
            return TRUE;
        case 0xe9: /* jmp nnnn */
            pc += 5 + *(LONG *)(pc + 1);
            if (pc - (BYTE *)base >= function->BeginAddress && pc - (BYTE *)base < function->EndAddress)
                continue;
            break;
        case 0xeb: /* jmp n */
            pc += 2 + (signed char)pc[1];
            if (pc - (BYTE *)base >= function->BeginAddress && pc - (BYTE *)base < function->EndAddress)
                continue;
            break;
        case 0xf3: /* rep; ret (for amd64 prediction bug) */
            return pc[1] == 0xc3;
        }
        return FALSE;
    }
}

/* execute a function epilog, which must have been validated with is_inside_epilog() */
static void interpret_epilog( BYTE *pc, CONTEXT *context, KNONVOLATILE_CONTEXT_POINTERS *ctx_ptr )
{
    for (;;)
    {
        BYTE rex = 0;

        if ((*pc & 0xf0) == 0x40) rex = *pc++ & 0x0f;  /* rex prefix */

        switch (*pc)
        {
        case 0x58: /* pop %rax/r8 */
        case 0x59: /* pop %rcx/r9 */
        case 0x5a: /* pop %rdx/r10 */
        case 0x5b: /* pop %rbx/r11 */
        case 0x5c: /* pop %rsp/r12 */
        case 0x5d: /* pop %rbp/r13 */
        case 0x5e: /* pop %rsi/r14 */
        case 0x5f: /* pop %rdi/r15 */
            set_int_reg( context, ctx_ptr, *pc - 0x58 + (rex & 1) * 8, (ULONG64 *)context->Rsp );
            context->Rsp += sizeof(ULONG64);
            pc++;
            continue;
        case 0x81: /* add $nnnn,%rsp */
            context->Rsp += *(LONG *)(pc + 2);
            pc += 2 + sizeof(LONG);
            continue;
        case 0x83: /* add $n,%rsp */
            context->Rsp += (signed char)pc[2];
            pc += 3;
            continue;
        case 0x8d:
            if ((pc[1] >> 6) == 1)  /* lea n(reg),%rsp */
            {
                context->Rsp = get_int_reg( context, (pc[1] & 7) + (rex & 1) * 8 ) + (signed char)pc[2];
                pc += 3;
            }
            else  /* lea nnnn(reg),%rsp */
            {
                context->Rsp = get_int_reg( context, (pc[1] & 7) + (rex & 1) * 8 ) + *(LONG *)(pc + 2);
                pc += 2 + sizeof(LONG);
            }
            continue;
        case 0xc2: /* ret $nn */
            context->Rip = *(ULONG64 *)context->Rsp;
            context->Rsp += sizeof(ULONG64) + *(WORD *)(pc + 1);
            return;
        case 0xc3: /* ret */
        case 0xf3: /* rep; ret */
            context->Rip = *(ULONG64 *)context->Rsp;
            context->Rsp += sizeof(ULONG64);
            return;
        case 0xe9: /* jmp nnnn */
            pc += 5 + *(LONG *)(pc + 1);
            continue;
        case 0xeb: /* jmp n */
            pc += 2 + (signed char)pc[1];
            continue;
        }
        return;
    }
}

/**********************************************************************
 *              RtlVirtualUnwind   (NTDLL.@)
 */
PVOID WINAPI RtlVirtualUnwind( ULONG type, ULONG64 base, ULONG64 pc,
                               RUNTIME_FUNCTION *function, CONTEXT *context,
                               PVOID *data, ULONG64 *frame_ret,
                               KNONVOLATILE_CONTEXT_POINTERS *ctx_ptr )
{
    union handler_data *handler_data;
    ULONG64 frame, off;
    struct UNWIND_INFO *info;
    unsigned int i, prolog_offset;
    BOOL mach_frame = FALSE;

    TRACE( "type %x rip %p rsp %p\n", type, (void *)pc, (void *)context->Rsp );
    if (TRACE_ON(seh)) dump_unwind_info( base, function );

    frame = *frame_ret = context->Rsp;
    for (;;)
    {
        info = (struct UNWIND_INFO *)((char *)base + function->UnwindData);
        handler_data = (union handler_data *)&info->opcodes[(info->count + 1) & ~1];

        if (info->version != 1 && info->version != 2)
        {
            FIXME( "unknown unwind info version %u at %p\n", info->version, info );
            return NULL;
        }

        if (info->frame_reg)
            frame = get_int_reg( context, info->frame_reg ) - info->frame_offset * 16;

        /* check if in prolog */
        if (pc >= base + function->BeginAddress && pc < base + function->BeginAddress + info->prolog)
        {
            TRACE("inside prolog.\n");
            prolog_offset = pc - base - function->BeginAddress;
        }
        else
        {
            prolog_offset = ~0;
            /* Since Win10 1809 epilogue does not have a special treatment in case of zero opcode count. */
            if (info->count && is_inside_epilog( (BYTE *)pc, base, function ))
            {
                TRACE("inside epilog.\n");
                interpret_epilog( (BYTE *)pc, context, ctx_ptr );
                *frame_ret = frame;
                return NULL;
            }
        }

        for (i = 0; i < info->count; i += get_opcode_size(info->opcodes[i]))
        {
            if (prolog_offset < info->opcodes[i].offset) continue; /* skip it */

            switch (info->opcodes[i].code)
            {
            case UWOP_PUSH_NONVOL:  /* pushq %reg */
                set_int_reg( context, ctx_ptr, info->opcodes[i].info, (ULONG64 *)context->Rsp );
                context->Rsp += sizeof(ULONG64);
                break;
            case UWOP_ALLOC_LARGE:  /* subq $nn,%rsp */
                if (info->opcodes[i].info) context->Rsp += *(DWORD *)&info->opcodes[i+1];
                else context->Rsp += *(USHORT *)&info->opcodes[i+1] * 8;
                break;
            case UWOP_ALLOC_SMALL:  /* subq $n,%rsp */
                context->Rsp += (info->opcodes[i].info + 1) * 8;
                break;
            case UWOP_SET_FPREG:  /* leaq nn(%rsp),%framereg */
                context->Rsp = *frame_ret = frame;
                break;
            case UWOP_SAVE_NONVOL:  /* movq %reg,n(%rsp) */
                off = frame + *(USHORT *)&info->opcodes[i+1] * 8;
                set_int_reg( context, ctx_ptr, info->opcodes[i].info, (ULONG64 *)off );
                break;
            case UWOP_SAVE_NONVOL_FAR:  /* movq %reg,nn(%rsp) */
                off = frame + *(DWORD *)&info->opcodes[i+1];
                set_int_reg( context, ctx_ptr, info->opcodes[i].info, (ULONG64 *)off );
                break;
            case UWOP_SAVE_XMM128:  /* movaps %xmmreg,n(%rsp) */
                off = frame + *(USHORT *)&info->opcodes[i+1] * 16;
                set_float_reg( context, ctx_ptr, info->opcodes[i].info, (M128A *)off );
                break;
            case UWOP_SAVE_XMM128_FAR:  /* movaps %xmmreg,nn(%rsp) */
                off = frame + *(DWORD *)&info->opcodes[i+1];
                set_float_reg( context, ctx_ptr, info->opcodes[i].info, (M128A *)off );
                break;
            case UWOP_PUSH_MACHFRAME:
                if (info->flags & UNW_FLAG_CHAININFO)
                {
                    FIXME("PUSH_MACHFRAME with chained unwind info.\n");
                    break;
                }
                if (i + get_opcode_size(info->opcodes[i]) < info->count )
                {
                    FIXME("PUSH_MACHFRAME is not the last opcode.\n");
                    break;
                }

                if (info->opcodes[i].info)
                    context->Rsp += 0x8;

                context->Rip = *(ULONG64 *)context->Rsp;
                context->Rsp = *(ULONG64 *)(context->Rsp + 24);
                mach_frame = TRUE;
                break;
            case UWOP_EPILOG:
                if (info->version == 2)
                    break; /* nothing to do */
            default:
                FIXME( "unknown code %u\n", info->opcodes[i].code );
                break;
            }
        }

        if (!(info->flags & UNW_FLAG_CHAININFO)) break;
        function = &handler_data->chain;  /* restart with the chained info */
    }

    if (!mach_frame)
    {
        /* now pop return address */
        context->Rip = *(ULONG64 *)context->Rsp;
        context->Rsp += sizeof(ULONG64);
    }

    if (!(info->flags & type)) return NULL;  /* no matching handler */
    if (prolog_offset != ~0) return NULL;  /* inside prolog */

    *data = &handler_data->handler + 1;
    return (char *)base + handler_data->handler;
}

struct unwind_exception_frame
{
    EXCEPTION_REGISTRATION_RECORD frame;
    DISPATCHER_CONTEXT *dispatch;
};

/**********************************************************************
 *           unwind_exception_handler
 *
 * Handler for exceptions happening while calling an unwind handler.
 */
static DWORD __cdecl unwind_exception_handler( EXCEPTION_RECORD *rec, EXCEPTION_REGISTRATION_RECORD *frame,
                                               CONTEXT *context, EXCEPTION_REGISTRATION_RECORD **dispatcher )
{
    struct unwind_exception_frame *unwind_frame = (struct unwind_exception_frame *)frame;
    DISPATCHER_CONTEXT *dispatch = (DISPATCHER_CONTEXT *)dispatcher;

    /* copy the original dispatcher into the current one, except for the TargetIp */
    dispatch->ControlPc        = unwind_frame->dispatch->ControlPc;
    dispatch->ImageBase        = unwind_frame->dispatch->ImageBase;
    dispatch->FunctionEntry    = unwind_frame->dispatch->FunctionEntry;
    dispatch->EstablisherFrame = unwind_frame->dispatch->EstablisherFrame;
    dispatch->ContextRecord    = unwind_frame->dispatch->ContextRecord;
    dispatch->LanguageHandler  = unwind_frame->dispatch->LanguageHandler;
    dispatch->HandlerData      = unwind_frame->dispatch->HandlerData;
    dispatch->HistoryTable     = unwind_frame->dispatch->HistoryTable;
    dispatch->ScopeIndex       = unwind_frame->dispatch->ScopeIndex;
    TRACE( "detected collided unwind\n" );
    return ExceptionCollidedUnwind;
}

/**********************************************************************
 *           call_unwind_handler
 *
 * Call a single unwind handler.
 */
static DWORD call_unwind_handler( EXCEPTION_RECORD *rec, DISPATCHER_CONTEXT *dispatch )
{
    struct unwind_exception_frame frame;
    DWORD res;

    frame.frame.Handler = unwind_exception_handler;
    frame.dispatch = dispatch;
    __wine_push_frame( &frame.frame );

    TRACE( "calling handler %p (rec=%p, frame=%p context=%p, dispatch=%p)\n",
           dispatch->LanguageHandler, rec, (void *)dispatch->EstablisherFrame, dispatch->ContextRecord, dispatch );
    res = dispatch->LanguageHandler( rec, (void *)dispatch->EstablisherFrame, dispatch->ContextRecord, dispatch );
    TRACE( "handler %p returned %x\n", dispatch->LanguageHandler, res );

    __wine_pop_frame( &frame.frame );

    switch (res)
    {
    case ExceptionContinueSearch:
    case ExceptionCollidedUnwind:
        break;
    default:
        raise_status( STATUS_INVALID_DISPOSITION, rec );
        break;
    }

    return res;
}


/**********************************************************************
 *           call_teb_unwind_handler
 *
 * Call a single unwind handler from the TEB chain.
 */
static DWORD call_teb_unwind_handler( EXCEPTION_RECORD *rec, DISPATCHER_CONTEXT *dispatch,
                                     EXCEPTION_REGISTRATION_RECORD *teb_frame )
{
    DWORD res;

    TRACE( "calling TEB handler %p (rec=%p, frame=%p context=%p, dispatch=%p)\n",
           teb_frame->Handler, rec, teb_frame, dispatch->ContextRecord, dispatch );
    res = teb_frame->Handler( rec, teb_frame, dispatch->ContextRecord, (EXCEPTION_REGISTRATION_RECORD**)dispatch );
    TRACE( "handler at %p returned %u\n", teb_frame->Handler, res );

    switch (res)
    {
    case ExceptionContinueSearch:
    case ExceptionCollidedUnwind:
        break;
    default:
        raise_status( STATUS_INVALID_DISPOSITION, rec );
        break;
    }

    return res;
}


/**********************************************************************
 *           call_consolidate_callback
 *
 * Wrapper function to call a consolidate callback from a fake frame.
 * If the callback executes RtlUnwindEx (like for example done in C++ handlers),
 * we have to skip all frames which were already processed. To do that we
 * trick the unwinding functions into thinking the call came from the specified
 * context. All CFI instructions are either DW_CFA_def_cfa_expression or
 * DW_CFA_expression, and the expressions have the following format:
 *
 * DW_OP_breg6; sleb128 0x10            | Load %rbp + 0x10
 * DW_OP_deref                          | Get *(%rbp + 0x10) == context
 * DW_OP_plus_uconst; uleb128 <OFFSET>  | Add offset to get struct member
 * [DW_OP_deref]                        | Dereference, only for CFA
 */
extern void * WINAPI call_consolidate_callback( CONTEXT *context,
                                                void *(CALLBACK *callback)(EXCEPTION_RECORD *),
                                                EXCEPTION_RECORD *rec );
__ASM_GLOBAL_FUNC( call_consolidate_callback,
                   "pushq %rbp\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset 8\n\t")
                   __ASM_CFI(".cfi_rel_offset %rbp,0\n\t")
                   "movq %rsp,%rbp\n\t"
                   __ASM_CFI(".cfi_def_cfa_register %rbp\n\t")

                   /* Setup SEH machine frame. */
                   "subq $0x28,%rsp\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset 0x28\n\t")
                   "movq 0xf8(%rcx),%rax\n\t" /* Context->Rip */
                   "movq %rax,(%rsp)\n\t"
                   "movq 0x98(%rcx),%rax\n\t" /* context->Rsp */
                   "movq %rax,0x18(%rsp)\n\t"
                   __ASM_SEH(".seh_pushframe\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")

                   "subq $0x108,%rsp\n\t" /* 10*16 (float regs) + 8*8 (int regs) + 32 (shadow store) + 8 (align). */
                   __ASM_SEH(".seh_stackalloc 0x108\n\t")
                   __ASM_CFI(".cfi_adjust_cfa_offset 0x108\n\t")

                   /* Setup CFI unwind to context. */
                   "movq %rcx,0x10(%rbp)\n\t"
                   __ASM_CFI(".cfi_remember_state\n\t")
                   __ASM_CFI(".cfi_escape 0x0f,0x07,0x76,0x10,0x06,0x23,0x98,0x01,0x06\n\t") /* CFA    */
                   __ASM_CFI(".cfi_escape 0x10,0x03,0x06,0x76,0x10,0x06,0x23,0x90,0x01\n\t") /* %rbx   */
                   __ASM_CFI(".cfi_escape 0x10,0x04,0x06,0x76,0x10,0x06,0x23,0xa8,0x01\n\t") /* %rsi   */
                   __ASM_CFI(".cfi_escape 0x10,0x05,0x06,0x76,0x10,0x06,0x23,0xb0,0x01\n\t") /* %rdi   */
                   __ASM_CFI(".cfi_escape 0x10,0x06,0x06,0x76,0x10,0x06,0x23,0xa0,0x01\n\t") /* %rbp   */
                   __ASM_CFI(".cfi_escape 0x10,0x0c,0x06,0x76,0x10,0x06,0x23,0xd8,0x01\n\t") /* %r12   */
                   __ASM_CFI(".cfi_escape 0x10,0x0d,0x06,0x76,0x10,0x06,0x23,0xe0,0x01\n\t") /* %r13   */
                   __ASM_CFI(".cfi_escape 0x10,0x0e,0x06,0x76,0x10,0x06,0x23,0xe8,0x01\n\t") /* %r14   */
                   __ASM_CFI(".cfi_escape 0x10,0x0f,0x06,0x76,0x10,0x06,0x23,0xf0,0x01\n\t") /* %r15   */
                   __ASM_CFI(".cfi_escape 0x10,0x10,0x06,0x76,0x10,0x06,0x23,0xf8,0x01\n\t") /* %rip   */
                   __ASM_CFI(".cfi_escape 0x10,0x17,0x06,0x76,0x10,0x06,0x23,0x80,0x04\n\t") /* %xmm6  */
                   __ASM_CFI(".cfi_escape 0x10,0x18,0x06,0x76,0x10,0x06,0x23,0x90,0x04\n\t") /* %xmm7  */
                   __ASM_CFI(".cfi_escape 0x10,0x19,0x06,0x76,0x10,0x06,0x23,0xa0,0x04\n\t") /* %xmm8  */
                   __ASM_CFI(".cfi_escape 0x10,0x1a,0x06,0x76,0x10,0x06,0x23,0xb0,0x04\n\t") /* %xmm9  */
                   __ASM_CFI(".cfi_escape 0x10,0x1b,0x06,0x76,0x10,0x06,0x23,0xc0,0x04\n\t") /* %xmm10 */
                   __ASM_CFI(".cfi_escape 0x10,0x1c,0x06,0x76,0x10,0x06,0x23,0xd0,0x04\n\t") /* %xmm11 */
                   __ASM_CFI(".cfi_escape 0x10,0x1d,0x06,0x76,0x10,0x06,0x23,0xe0,0x04\n\t") /* %xmm12 */
                   __ASM_CFI(".cfi_escape 0x10,0x1e,0x06,0x76,0x10,0x06,0x23,0xf0,0x04\n\t") /* %xmm13 */
                   __ASM_CFI(".cfi_escape 0x10,0x1f,0x06,0x76,0x10,0x06,0x23,0x80,0x05\n\t") /* %xmm14 */
                   __ASM_CFI(".cfi_escape 0x10,0x20,0x06,0x76,0x10,0x06,0x23,0x90,0x05\n\t") /* %xmm15 */

                   /* Setup SEH unwind registers restore. */
                   "movq 0xa0(%rcx),%rax\n\t" /* context->Rbp */
                   "movq %rax,0x100(%rsp)\n\t"
                   __ASM_SEH(".seh_savereg %rbp, 0x100\n\t")
                   "movq 0x90(%rcx),%rax\n\t" /* context->Rbx */
                   "movq %rax,0x20(%rsp)\n\t"
                   __ASM_SEH(".seh_savereg %rbx, 0x20\n\t")
                   "movq 0xa8(%rcx),%rax\n\t" /* context->Rsi */
                   "movq %rax,0x28(%rsp)\n\t"
                   __ASM_SEH(".seh_savereg %rsi, 0x28\n\t")
                   "movq 0xb0(%rcx),%rax\n\t" /* context->Rdi */
                   "movq %rax,0x30(%rsp)\n\t"
                   __ASM_SEH(".seh_savereg %rdi, 0x30\n\t")

                   "movq 0xd8(%rcx),%rax\n\t" /* context->R12 */
                   "movq %rax,0x38(%rsp)\n\t"
                   __ASM_SEH(".seh_savereg %r12, 0x38\n\t")
                   "movq 0xe0(%rcx),%rax\n\t" /* context->R13 */
                   "movq %rax,0x40(%rsp)\n\t"
                   __ASM_SEH(".seh_savereg %r13, 0x40\n\t")
                   "movq 0xe8(%rcx),%rax\n\t" /* context->R14 */
                   "movq %rax,0x48(%rsp)\n\t"
                   __ASM_SEH(".seh_savereg %r14, 0x48\n\t")
                   "movq 0xf0(%rcx),%rax\n\t" /* context->R15 */
                   "movq %rax,0x50(%rsp)\n\t"
                   __ASM_SEH(".seh_savereg %r15, 0x50\n\t")
                   "pushq %rsi\n\t"
                   "pushq %rdi\n\t"
                   "leaq 0x200(%rcx),%rsi\n\t"
                   "leaq 0x70(%rsp),%rdi\n\t"
                   "movq $0x14,%rcx\n\t"
                   "cld\n\t"
                   "rep; movsq\n\t"
                   "popq %rdi\n\t"
                   "popq %rsi\n\t"
                   __ASM_SEH(".seh_savexmm %xmm6, 0x60\n\t")
                   __ASM_SEH(".seh_savexmm %xmm7, 0x70\n\t")
                   __ASM_SEH(".seh_savexmm %xmm8, 0x80\n\t")
                   __ASM_SEH(".seh_savexmm %xmm9, 0x90\n\t")
                   __ASM_SEH(".seh_savexmm %xmm10, 0xa0\n\t")
                   __ASM_SEH(".seh_savexmm %xmm11, 0xb0\n\t")
                   __ASM_SEH(".seh_savexmm %xmm12, 0xc0\n\t")
                   __ASM_SEH(".seh_savexmm %xmm13, 0xd0\n\t")
                   __ASM_SEH(".seh_savexmm %xmm14, 0xe0\n\t")
                   __ASM_SEH(".seh_savexmm %xmm15, 0xf0\n\t")

                   /* call the callback. */
                   "movq %r8,%rcx\n\t"
                   "callq *%rdx\n\t"
                   __ASM_CFI(".cfi_restore_state\n\t")
                   "nop\n\t" /* Otherwise RtlVirtualUnwind() will think we are inside epilogue and
                              * interpret / execute the rest of opcodes here instead of unwind through
                              * machine frame. */
                   "leaq 0(%rbp),%rsp\n\t"
                   __ASM_CFI(".cfi_def_cfa_register %rsp\n\t")
                   "popq %rbp\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset -8\n\t")
                   __ASM_CFI(".cfi_same_value %rbp\n\t")
                   "ret")

/*******************************************************************
 *              RtlRestoreContext (NTDLL.@)
 */
void CDECL RtlRestoreContext( CONTEXT *context, EXCEPTION_RECORD *rec )
{
    EXCEPTION_REGISTRATION_RECORD *teb_frame = NtCurrentTeb()->Tib.ExceptionList;

    if (rec && rec->ExceptionCode == STATUS_LONGJUMP && rec->NumberParameters >= 1)
    {
        struct MSVCRT_JUMP_BUFFER *jmp = (struct MSVCRT_JUMP_BUFFER *)rec->ExceptionInformation[0];
        context->Rbx       = jmp->Rbx;
        context->Rsp       = jmp->Rsp;
        context->Rbp       = jmp->Rbp;
        context->Rsi       = jmp->Rsi;
        context->Rdi       = jmp->Rdi;
        context->R12       = jmp->R12;
        context->R13       = jmp->R13;
        context->R14       = jmp->R14;
        context->R15       = jmp->R15;
        context->Rip       = jmp->Rip;
        context->u.s.Xmm6  = jmp->Xmm6;
        context->u.s.Xmm7  = jmp->Xmm7;
        context->u.s.Xmm8  = jmp->Xmm8;
        context->u.s.Xmm9  = jmp->Xmm9;
        context->u.s.Xmm10 = jmp->Xmm10;
        context->u.s.Xmm11 = jmp->Xmm11;
        context->u.s.Xmm12 = jmp->Xmm12;
        context->u.s.Xmm13 = jmp->Xmm13;
        context->u.s.Xmm14 = jmp->Xmm14;
        context->u.s.Xmm15 = jmp->Xmm15;
    }
    else if (rec && rec->ExceptionCode == STATUS_UNWIND_CONSOLIDATE && rec->NumberParameters >= 1)
    {
        PVOID (CALLBACK *consolidate)(EXCEPTION_RECORD *) = (void *)rec->ExceptionInformation[0];
        TRACE( "calling consolidate callback %p (rec=%p)\n", consolidate, rec );
        context->Rip = (ULONG64)call_consolidate_callback( context, consolidate, rec );
    }

    /* hack: remove no longer accessible TEB frames */
    while ((ULONG64)teb_frame < context->Rsp)
    {
        TRACE( "removing TEB frame: %p\n", teb_frame );
        teb_frame = __wine_pop_frame( teb_frame );
    }

    TRACE( "returning to %p stack %p\n", (void *)context->Rip, (void *)context->Rsp );
    NtSetContextThread( GetCurrentThread(), context );
}


/*******************************************************************
 *		RtlUnwindEx (NTDLL.@)
 */
void WINAPI RtlUnwindEx( PVOID end_frame, PVOID target_ip, EXCEPTION_RECORD *rec,
                         PVOID retval, CONTEXT *context, UNWIND_HISTORY_TABLE *table )
{
    EXCEPTION_REGISTRATION_RECORD *teb_frame = NtCurrentTeb()->Tib.ExceptionList;
    EXCEPTION_RECORD record;
    DISPATCHER_CONTEXT dispatch;
    CONTEXT new_context;
    NTSTATUS status;
    DWORD i;

    RtlCaptureContext( context );
    new_context = *context;

    /* build an exception record, if we do not have one */
    if (!rec)
    {
        record.ExceptionCode    = STATUS_UNWIND;
        record.ExceptionFlags   = 0;
        record.ExceptionRecord  = NULL;
        record.ExceptionAddress = (void *)context->Rip;
        record.NumberParameters = 0;
        rec = &record;
    }

    rec->ExceptionFlags |= EH_UNWINDING | (end_frame ? 0 : EH_EXIT_UNWIND);

    TRACE( "code=%x flags=%x end_frame=%p target_ip=%p rip=%016lx\n",
           rec->ExceptionCode, rec->ExceptionFlags, end_frame, target_ip, context->Rip );
    for (i = 0; i < min( EXCEPTION_MAXIMUM_PARAMETERS, rec->NumberParameters ); i++)
        TRACE( " info[%d]=%016lx\n", i, rec->ExceptionInformation[i] );
    TRACE(" rax=%016lx rbx=%016lx rcx=%016lx rdx=%016lx\n",
          context->Rax, context->Rbx, context->Rcx, context->Rdx );
    TRACE(" rsi=%016lx rdi=%016lx rbp=%016lx rsp=%016lx\n",
          context->Rsi, context->Rdi, context->Rbp, context->Rsp );
    TRACE("  r8=%016lx  r9=%016lx r10=%016lx r11=%016lx\n",
          context->R8, context->R9, context->R10, context->R11 );
    TRACE(" r12=%016lx r13=%016lx r14=%016lx r15=%016lx\n",
          context->R12, context->R13, context->R14, context->R15 );

    dispatch.EstablisherFrame = context->Rsp;
    dispatch.TargetIp         = (ULONG64)target_ip;
    dispatch.ContextRecord    = context;
    dispatch.HistoryTable     = table;

    for (;;)
    {
        status = virtual_unwind( UNW_FLAG_UHANDLER, &dispatch, &new_context );
        if (status != STATUS_SUCCESS) raise_status( status, rec );

    unwind_done:
        if (!dispatch.EstablisherFrame) break;

        if ((dispatch.EstablisherFrame & 7) ||
            dispatch.EstablisherFrame < (ULONG64)NtCurrentTeb()->Tib.StackLimit ||
            dispatch.EstablisherFrame > (ULONG64)NtCurrentTeb()->Tib.StackBase)
        {
            ERR( "invalid frame %p (%p-%p)\n", (void *)dispatch.EstablisherFrame,
                 NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
            rec->ExceptionFlags |= EH_STACK_INVALID;
            break;
        }

        if (dispatch.LanguageHandler)
        {
            if (end_frame && (dispatch.EstablisherFrame > (ULONG64)end_frame))
            {
                ERR( "invalid end frame %p/%p\n", (void *)dispatch.EstablisherFrame, end_frame );
                raise_status( STATUS_INVALID_UNWIND_TARGET, rec );
            }
            if (dispatch.EstablisherFrame == (ULONG64)end_frame) rec->ExceptionFlags |= EH_TARGET_UNWIND;
            if (call_unwind_handler( rec, &dispatch ) == ExceptionCollidedUnwind)
            {
                ULONG64 frame;

                new_context = *dispatch.ContextRecord;
                new_context.ContextFlags &= ~0x40;
                *context = new_context;
                dispatch.ContextRecord = context;
                RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase,
                        dispatch.ControlPc, dispatch.FunctionEntry,
                        &new_context, NULL, &frame, NULL );
                rec->ExceptionFlags |= EH_COLLIDED_UNWIND;
                goto unwind_done;
            }
            rec->ExceptionFlags &= ~EH_COLLIDED_UNWIND;
        }
        else  /* hack: call builtin handlers registered in the tib list */
        {
            DWORD64 backup_frame = dispatch.EstablisherFrame;
            while ((ULONG64)teb_frame < new_context.Rsp && (ULONG64)teb_frame < (ULONG64)end_frame)
            {
                TRACE( "found builtin frame %p handler %p\n", teb_frame, teb_frame->Handler );
                dispatch.EstablisherFrame = (ULONG64)teb_frame;
                if (call_teb_unwind_handler( rec, &dispatch, teb_frame ) == ExceptionCollidedUnwind)
                {
                    ULONG64 frame;

                    teb_frame = __wine_pop_frame( teb_frame );

                    new_context = *dispatch.ContextRecord;
                    new_context.ContextFlags &= ~0x40;
                    *context = new_context;
                    dispatch.ContextRecord = context;
                    RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase,
                            dispatch.ControlPc, dispatch.FunctionEntry,
                            &new_context, NULL, &frame, NULL );
                    rec->ExceptionFlags |= EH_COLLIDED_UNWIND;
                    goto unwind_done;
                }
                teb_frame = __wine_pop_frame( teb_frame );
            }
            if ((ULONG64)teb_frame == (ULONG64)end_frame && (ULONG64)end_frame < new_context.Rsp) break;
            dispatch.EstablisherFrame = backup_frame;
        }

        if (dispatch.EstablisherFrame == (ULONG64)end_frame) break;
        *context = new_context;
    }

    context->Rax = (ULONG64)retval;
    context->Rip = (ULONG64)target_ip;
    RtlRestoreContext(context, rec);
}


/*******************************************************************
 *		RtlUnwind (NTDLL.@)
 */
void WINAPI RtlUnwind( void *frame, void *target_ip, EXCEPTION_RECORD *rec, void *retval )
{
    CONTEXT context;
    RtlUnwindEx( frame, target_ip, rec, retval, &context, NULL );
}


/*******************************************************************
 *		_local_unwind (NTDLL.@)
 */
void WINAPI _local_unwind( void *frame, void *target_ip )
{
    CONTEXT context;
    RtlUnwindEx( frame, target_ip, NULL, NULL, &context, NULL );
}

/*******************************************************************
 *		__C_specific_handler (NTDLL.@)
 */
EXCEPTION_DISPOSITION WINAPI __C_specific_handler( EXCEPTION_RECORD *rec,
                                                   void *frame,
                                                   CONTEXT *context,
                                                   struct _DISPATCHER_CONTEXT *dispatch )
{
    SCOPE_TABLE *table = dispatch->HandlerData;
    ULONG i;

    TRACE( "%p %p %p %p\n", rec, frame, context, dispatch );
    if (TRACE_ON(seh)) dump_scope_table( dispatch->ImageBase, table );

    if (rec->ExceptionFlags & (EH_UNWINDING | EH_EXIT_UNWIND))
    {
        for (i = dispatch->ScopeIndex; i < table->Count; i++)
        {
            if (dispatch->ControlPc >= dispatch->ImageBase + table->ScopeRecord[i].BeginAddress &&
                dispatch->ControlPc < dispatch->ImageBase + table->ScopeRecord[i].EndAddress)
            {
                PTERMINATION_HANDLER handler;

                if (table->ScopeRecord[i].JumpTarget) continue;

                if (rec->ExceptionFlags & EH_TARGET_UNWIND &&
                    dispatch->TargetIp >= dispatch->ImageBase + table->ScopeRecord[i].BeginAddress &&
                    dispatch->TargetIp < dispatch->ImageBase + table->ScopeRecord[i].EndAddress)
                {
                    break;
                }

                handler = (PTERMINATION_HANDLER)(dispatch->ImageBase + table->ScopeRecord[i].HandlerAddress);
                dispatch->ScopeIndex = i+1;

                TRACE( "calling __finally %p frame %p\n", handler, frame );
                handler( TRUE, frame );
            }
        }
        return ExceptionContinueSearch;
    }

    for (i = dispatch->ScopeIndex; i < table->Count; i++)
    {
        if (dispatch->ControlPc >= dispatch->ImageBase + table->ScopeRecord[i].BeginAddress &&
            dispatch->ControlPc < dispatch->ImageBase + table->ScopeRecord[i].EndAddress)
        {
            if (!table->ScopeRecord[i].JumpTarget) continue;
            if (table->ScopeRecord[i].HandlerAddress != EXCEPTION_EXECUTE_HANDLER)
            {
                EXCEPTION_POINTERS ptrs;
                PEXCEPTION_FILTER filter;

                filter = (PEXCEPTION_FILTER)(dispatch->ImageBase + table->ScopeRecord[i].HandlerAddress);
                ptrs.ExceptionRecord = rec;
                ptrs.ContextRecord = context;
                TRACE( "calling filter %p ptrs %p frame %p\n", filter, &ptrs, frame );
                switch (filter( &ptrs, frame ))
                {
                case EXCEPTION_EXECUTE_HANDLER:
                    break;
                case EXCEPTION_CONTINUE_SEARCH:
                    continue;
                case EXCEPTION_CONTINUE_EXECUTION:
                    return ExceptionContinueExecution;
                }
            }
            TRACE( "unwinding to target %p\n", (char *)dispatch->ImageBase + table->ScopeRecord[i].JumpTarget );
            RtlUnwindEx( frame, (char *)dispatch->ImageBase + table->ScopeRecord[i].JumpTarget,
                         rec, 0, dispatch->ContextRecord, dispatch->HistoryTable );
        }
    }
    return ExceptionContinueSearch;
}


/***********************************************************************
 *		RtlRaiseException (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( RtlRaiseException,
                   "sub $0x4f8,%rsp\n\t"
                   __ASM_SEH(".seh_stackalloc 0x4f8\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")
                   __ASM_CFI(".cfi_adjust_cfa_offset 0x4f8\n\t")
                   "movq %rcx,0x500(%rsp)\n\t"
                   "leaq 0x20(%rsp),%rcx\n\t"
                   "call " __ASM_NAME("RtlCaptureContext") "\n\t"
                   "leaq 0x20(%rsp),%rdx\n\t"   /* context pointer */
                   "leaq 0x500(%rsp),%rax\n\t"  /* orig stack pointer */
                   "movq %rax,0x98(%rdx)\n\t"   /* context->Rsp */
                   "movq (%rax),%rcx\n\t"       /* original first parameter */
                   "movq %rcx,0x80(%rdx)\n\t"   /* context->Rcx */
                   "movq 0x4f8(%rsp),%rax\n\t"  /* return address */
                   "movq %rax,0xf8(%rdx)\n\t"   /* context->Rip */
                   "movq %rax,0x10(%rcx)\n\t"   /* rec->ExceptionAddress */
                   "movl $1,%r8d\n\t"
                   "movq %gs:(0x30),%rax\n\t"   /* Teb */
                   "movq 0x60(%rax),%rax\n\t"   /* Peb */
                   "cmpb $0,0x02(%rax)\n\t"     /* BeingDebugged */
                   "jne 1f\n\t"
                   "call " __ASM_NAME("dispatch_exception") "\n"
                   "1:\tcall " __ASM_NAME("NtRaiseException") "\n\t"
                   "movq %rax,%rcx\n\t"
                   "call " __ASM_NAME("RtlRaiseStatus") /* does not return */ );


static inline ULONG hash_pointers( void **ptrs, ULONG count )
{
    /* Based on MurmurHash2, which is in the public domain */
    static const ULONG m = 0x5bd1e995;
    static const ULONG r = 24;
    ULONG hash = count * sizeof(void*);
    for (; count > 0; ptrs++, count--)
    {
        ULONG_PTR data = (ULONG_PTR)*ptrs;
        ULONG k1 = (ULONG)(data & 0xffffffff), k2 = (ULONG)(data >> 32);
        k1 *= m;
        k1 = (k1 ^ (k1 >> r)) * m;
        k2 *= m;
        k2 = (k2 ^ (k2 >> r)) * m;
        hash = (((hash * m) ^ k1) * m) ^ k2;
    }
    hash = (hash ^ (hash >> 13)) * m;
    return hash ^ (hash >> 15);
}


/*************************************************************************
 *		RtlCaptureStackBackTrace (NTDLL.@)
 */
USHORT WINAPI RtlCaptureStackBackTrace( ULONG skip, ULONG count, PVOID *buffer, ULONG *hash )
{
    UNWIND_HISTORY_TABLE table;
    DISPATCHER_CONTEXT dispatch;
    CONTEXT context;
    NTSTATUS status;
    ULONG i;
    USHORT num_entries = 0;

    TRACE( "(%u, %u, %p, %p)\n", skip, count, buffer, hash );

    RtlCaptureContext( &context );
    dispatch.TargetIp      = 0;
    dispatch.ContextRecord = &context;
    dispatch.HistoryTable  = &table;
    if (hash) *hash = 0;
    for (i = 0; i < skip + count; i++)
    {
        status = virtual_unwind( UNW_FLAG_NHANDLER, &dispatch, &context );
        if (status != STATUS_SUCCESS) return i;

        if (!dispatch.EstablisherFrame) break;

        if ((dispatch.EstablisherFrame & 7) ||
            dispatch.EstablisherFrame < (ULONG64)NtCurrentTeb()->Tib.StackLimit ||
            dispatch.EstablisherFrame > (ULONG64)NtCurrentTeb()->Tib.StackBase)
        {
            ERR( "invalid frame %p (%p-%p)\n", (void *)dispatch.EstablisherFrame,
                 NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
            break;
        }

        if (context.Rsp == (ULONG64)NtCurrentTeb()->Tib.StackBase) break;

        if (i >= skip) buffer[num_entries++] = (void *)context.Rip;
    }
    if (hash && num_entries > 0) *hash = hash_pointers( buffer, num_entries );
    TRACE( "captured %hu frames\n", num_entries );
    return num_entries;
}


/***********************************************************************
 *           signal_start_thread
 */
__ASM_GLOBAL_FUNC( signal_start_thread,
                   "movq %rcx,%rbx\n\t"        /* context */
                   /* clear the thread stack */
                   "andq $~0xfff,%rcx\n\t"     /* round down to page size */
                   "movq %gs:0x30,%rax\n\t"
                   "movq 0x10(%rax),%rdi\n\t"  /* NtCurrentTeb()->Tib.StackLimit */
                   "addq $0x2000,%rdi\n\t"
                   "movq %rdi,%rsp\n\t"
                   "subq %rdi,%rcx\n\t"
                   "xorl %eax,%eax\n\t"
                   "shrq $3,%rcx\n\t"
                   "rep; stosq\n\t"
                   /* switch to the initial context */
                   "leaq -32(%rbx),%rsp\n\t"
                   "movq %rbx,%rcx\n\t"
                   "movl $1,%edx\n\t"
                   "call " __ASM_NAME("NtContinue") )


/**********************************************************************
 *		DbgBreakPoint   (NTDLL.@)
 */
__ASM_STDCALL_FUNC( DbgBreakPoint, 0, "int $3; ret"
                    "\n\tnop; nop; nop; nop; nop; nop; nop; nop"
                    "\n\tnop; nop; nop; nop; nop; nop" );

/**********************************************************************
 *		DbgUserBreakPoint   (NTDLL.@)
 */
__ASM_STDCALL_FUNC( DbgUserBreakPoint, 0, "int $3; ret"
                    "\n\tnop; nop; nop; nop; nop; nop; nop; nop"
                    "\n\tnop; nop; nop; nop; nop; nop" );

#endif  /* __x86_64__ */
