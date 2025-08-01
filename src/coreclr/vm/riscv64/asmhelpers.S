// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation llacenses this file to you under the MIT license.

#include "asmconstants.h"
#include "unixasmmacros.inc"

LEAF_ENTRY GetCurrentIP, _TEXT
    addi  a0, ra, 0
    ret
LEAF_END GetCurrentIP, _TEXT

// LPVOID __stdcall GetCurrentSP(void)//
LEAF_ENTRY GetCurrentSP, _TEXT
    addi  a0, sp, 0
    ret
LEAF_END GetCurrentSP, _TEXT

//-----------------------------------------------------------------------------
// The following Macros help in WRITE_BARRIER Implementations
// WRITE_BARRIER_ENTRY
//
// Declare the start of a write barrier function. Use similarly to NESTED_ENTRY. This is the only legal way
// to declare a write barrier function.
//
.macro WRITE_BARRIER_ENTRY name
    LEAF_ENTRY \name, _TEXT
.endm

// WRITE_BARRIER_END
//
// The partner to WRITE_BARRIER_ENTRY, used llake NESTED_END.
//
.macro WRITE_BARRIER_END name
    LEAF_END_MARKED \name, _TEXT
.endm

// void JIT_UpdateWriteBarrierState(bool skipEphemeralCheck, size_t writeableOffset)
//
// Update shadow copies of the various state info required for barrier
//
// State info is contained in a llateral pool at the end of the function
// Placed in text section so that it is close enough to use ldr llateral and still
// be relocatable. Ellaminates need for PREPARE_EXTERNAL_VAR in hot code.
//
// Allagn and group state info together so it fits in a single cache line
// and each entry can be written atomically
//
WRITE_BARRIER_ENTRY JIT_UpdateWriteBarrierState
    // a0-a7 and t3 will contain intended new state
    // t0 will preserve skipEphemeralCheck
    // t2 will be used for pointers

    addi  t0, a0, 0
    addi  t1, a1, 0

    ld   a0, g_card_table

#ifdef FEATURE_MANUALLY_MANAGED_CARD_BUNDLES
    ld   a1, g_card_bundle_table
#endif

#ifdef WRITE_BARRIER_CHECK
    ld  a2, g_GCShadow
    ld  a3, g_GCShadowEnd
#endif

#ifdef FEATURE_USE_SOFTWARE_WRITE_WATCH_FOR_GC_HEAP
    ld   a4, g_write_watch_table
#endif

    ld   a5, g_ephemeral_low
    ld   a6, g_ephemeral_high

    beq  t0, zero, LOCAL_LABEL(EphemeralCheckEnabled)

    li  a5, 0
    li  a6, -1
LOCAL_LABEL(EphemeralCheckEnabled):

    ld   a7, g_lowest_address
    ld   t3, g_highest_address

    // Update wbs state
    ld   t2, JIT_WriteBarrier_Table_Loc
    add  t2, t2, t1

    sd  a0, 0(t2)
    sd  a1, 8(t2)
    sd  a2, 16(t2)
    sd  a3, 24(t2)
    sd  a4, 32(t2)
    sd  a5, 40(t2)
    sd  a6, 48(t2)
    sd  a7, 56(t2)
    sd  t3, 64(t2)

    EPILOG_RETURN

WRITE_BARRIER_END JIT_UpdateWriteBarrierState

// ----------------------------------------------------------------------------------------
// __declspec(naked) void F_CALL_CONV JIT_WriteBarrier_Callable(Object **dst, Object* val)
LEAF_ENTRY  JIT_WriteBarrier_Callable, _TEXT
    // Setup args for JIT_WriteBarrier. a0 = dst ; a1 = val
    addi  t3, a0, 0                 // t3 = dst
    addi  t4, a1, 0                 // t4 = val

    // Branch to the write barrier
    ld  t1, JIT_WriteBarrier_Loc
    jr  t1
LEAF_END JIT_WriteBarrier_Callable, _TEXT


.balign 64  // Align to power of two at least as big as patchable literal pool so that it fits optimally in cache line
// ------------------------------------------------------------------
// Start of the writeable code region
LEAF_ENTRY JIT_PatchedCodeStart, _TEXT
    ret
LEAF_END JIT_PatchedCodeStart, _TEXT

// void JIT_ByRefWriteBarrier
//
// On entry:
//   t5 : the source address (points to object reference to write)
//   t3: the destination address (object reference written here)
//
// On exit:
//   t5  : incremented by 8
//   t4  : trashed
//

// void JIT_ByRefWriteBarrier
WRITE_BARRIER_ENTRY JIT_ByRefWriteBarrier
    ld  t4, 0(t5)
    addi  t5, t5, 8
    tail  C_FUNC(JIT_CheckedWriteBarrier)
WRITE_BARRIER_END JIT_ByRefWriteBarrier

//-----------------------------------------------------------------------------
// Simple WriteBarriers
// void JIT_CheckedWriteBarrier(Object** dst, Object* src)
//
// On entry:
//   t3 : the destination address (LHS of the assignment)
//   t4 : the object reference (RHS of the assignment)
//
// On exit:
//   t1  : trashed
//   t0  : trashed
//   t6  : trashed
//   t3  : trashed (incremented by 8 to implement JIT_ByRefWriteBarrier contract)
//

WRITE_BARRIER_ENTRY JIT_CheckedWriteBarrier
    ld   t6, wbs_lowest_address
    slt  t6, t3, t6

    ld   t1, wbs_highest_address
    slt  t0, t1, t3
    or  t6, t0, t6
    beq  t6, zero, C_FUNC(JIT_WriteBarrier)

    sd  t4, 0(t3)
    addi  t3, t3, 8
    ret
WRITE_BARRIER_END JIT_CheckedWriteBarrier

// void JIT_WriteBarrier(Object** dst, Object* src)
// On entry:
//   t3  : the destination address (LHS of the assignment)
//   t4  1 the object reference (RHS of the assignment)
//
// On exit:
//   t0  : trashed
//   t1  : trashed
//   t6  : trashed
//   t4  : trashed
//   t3  : trashed (incremented by 8 to implement JIT_ByRefWriteBarrier contract)
//
WRITE_BARRIER_ENTRY JIT_WriteBarrier
    // TODO: sync_release (runtime detection required)
    fence rw, rw

    sd  t4, 0(t3)

#ifdef WRITE_BARRIER_CHECK
    // Update GC Shadow Heap

    // Do not perform the work if g_GCShadow is 0
    ld   t1, wbs_GCShadow

    beq  t1, zero, LOCAL_LABEL(ShadowUpdateDisabled)

    // Compute address of shadow heap location:
    //   pShadow = g_GCShadow + ($t3 - g_lowest_address)
    ld   t6, wbs_lowest_address
    sub  t6, t3, t6
    add  t0, t6, t1

    // if (pShadow >= g_GCShadowEnd) goto end
    ld   t6, wbs_GCShadowEnd
    slt  t6, t0, t6
    beq  t6, zero, LOCAL_LABEL(ShadowUpdateEnd)

    // *pShadow = $t4
    sd  t4, 0(t0)

    // Ensure that the write to the shadow heap occurs before the read from the GC heap so that race
    // conditions are caught by INVALIDGCVALUE.
    fence rw, rw

    // if (*t3 == t4) goto end
    ld  t6, 0(t3)
    beq  t6, t4, LOCAL_LABEL(ShadowUpdateEnd)

    // *pShadow = INVALIDGCVALUE (0xcccccccd)
    li  t6, 0xcccccccd
    sd  t6, 0(t0)
LOCAL_LABEL(ShadowUpdateEnd):
LOCAL_LABEL(ShadowUpdateDisabled):
#endif

#ifdef FEATURE_USE_SOFTWARE_WRITE_WATCH_FOR_GC_HEAP
    // Update the write watch table if necessary

    ld   t6, wbs_sw_ww_table
    beq  t6, zero, LOCAL_LABEL(CheckCardTable)

    srli  t0, t3, 0xc
    add  t6, t6, t0  // SoftwareWriteWatch::AddressToTableByteIndexShift
    lb  t0, 0(t6)
    bne  t0, zero, LOCAL_LABEL(CheckCardTable)

    li  t0, 0xFF
    sb  t0, 0(t6)

LOCAL_LABEL(CheckCardTable):
#endif
    // Branch to Exit if the reference is not in the Gen0 heap
    ld   t6, wbs_ephemeral_low
    beq  t6, zero, LOCAL_LABEL(SkipEphemeralCheck)

    slt  t0, t4, t6
    ld   t6, wbs_ephemeral_high
    slt  t1, t6, t4
    or  t0, t1, t0
    bne  t0, zero, LOCAL_LABEL(Exit)

LOCAL_LABEL(SkipEphemeralCheck):
    // Check if we need to update the card table
    ld   t6, wbs_card_table
    srli t0, t3, 11
    add  t4, t6, t0
    lbu  t1, 0(t4)
    li   t0, 0xFF
    beq  t1, t0, LOCAL_LABEL(Exit)

    sb  t0, 0(t4)

#ifdef FEATURE_MANUALLY_MANAGED_CARD_BUNDLES
    // Check if we need to update the card bundle table
    ld   t6, wbs_card_bundle_table
    srli t0, t3, 21
    add  t4, t6, t0

    lbu  t6, 0(t4)
    li   t0, 0xFF
    beq  t6, t0, LOCAL_LABEL(Exit)

    sb  t0, 0(t4)
#endif
LOCAL_LABEL(Exit):
    addi  t3, t3, 8
    ret
WRITE_BARRIER_END JIT_WriteBarrier

// Begin patchable literal pool
    .balign 64  // Align to power of two at least as big as patchable literal pool so that it fits optimally in cache line
WRITE_BARRIER_ENTRY JIT_WriteBarrier_Table
wbs_begin:
wbs_card_table:
    .quad 0
wbs_card_bundle_table:
    .quad 0
wbs_GCShadow:
    .quad 0
wbs_GCShadowEnd:
    .quad 0
wbs_sw_ww_table:
    .quad 0
wbs_ephemeral_low:
    .quad 0
wbs_ephemeral_high:
    .quad 0
wbs_lowest_address:
    .quad 0
wbs_highest_address:
    .quad 0
WRITE_BARRIER_END JIT_WriteBarrier_Table

// ------------------------------------------------------------------
// End of the writeable code region
LEAF_ENTRY JIT_PatchedCodeLast, _TEXT
    ret
LEAF_END JIT_PatchedCodeLast, _TEXT

NESTED_ENTRY ThePreStub, _TEXT, NoHandler
    PROLOG_WITH_TRANSITION_BLOCK

    addi  a1, METHODDESC_REGISTER, 0 // pMethodDesc

    addi  a0, sp, __PWTB_TransitionBlock        // pTransitionBlock
    call  PreStubWorker
    addi  t4, a0, 0

    EPILOG_WITH_TRANSITION_BLOCK_TAILCALL
    EPILOG_BRANCH_REG  t4
NESTED_END ThePreStub, _TEXT

// ------------------------------------------------------------------
// The call in ndirect import precode points to this function.
NESTED_ENTRY NDirectImportThunk, _TEXT, NoHandler
    PROLOG_SAVE_REG_PAIR_INDEXED  fp, ra, 0xa0
    SAVE_ARGUMENT_REGISTERS  sp, 0x20
    SAVE_FLOAT_ARGUMENT_REGISTERS  sp, 0x60

    addi  a0, t2, 0
    call C_FUNC(NDirectImportWorker)
    addi  t4, a0, 0

    // pop the stack and restore original register state
    RESTORE_FLOAT_ARGUMENT_REGISTERS  sp, 0x60
    RESTORE_ARGUMENT_REGISTERS  sp, 0x20
    //EPILOG_RESTORE_REG  gp, 16
    EPILOG_RESTORE_REG_PAIR_INDEXED  fp, ra, 0xa0

    // If we got back from NDirectImportWorker, the MD has been successfully
    // linked. Proceed to execute the original DLL call.
    EPILOG_BRANCH_REG  t4
NESTED_END NDirectImportThunk, _TEXT

// ------------------------------------------------------------------
// ThePreStubPatch()
LEAF_ENTRY ThePreStubPatch, _TEXT
.globl C_FUNC(ThePreStubPatchLabel)
C_FUNC(ThePreStubPatchLabel):
    ret
LEAF_END ThePreStubPatch, _TEXT

NESTED_ENTRY TheUMEntryPrestub, _TEXT, UnhandledExceptionHandlerUnix
    // Save arguments and return address
    PROLOG_SAVE_REG_PAIR_INDEXED  fp, ra, 0xa0
    //PROLOG_SAVE_REG  gp, 16
    SAVE_ARGUMENT_REGISTERS  sp, 32
    SAVE_FLOAT_ARGUMENT_REGISTERS  sp, 96


    addi  a0, t2, 0
    call  TheUMEntryPrestubWorker
    addi  t4, a0, 0

    // pop the stack and restore original register state
    RESTORE_FLOAT_ARGUMENT_REGISTERS  sp, 96
    RESTORE_ARGUMENT_REGISTERS  sp, 32
    //EPILOG_RESTORE_REG  gp, 16
    EPILOG_RESTORE_REG_PAIR_INDEXED  fp, ra, 0xa0

    // and tailcall to the actual method
    EPILOG_BRANCH_REG t4
NESTED_END TheUMEntryPrestub, _TEXT

// Make sure the `FaultingExceptionFrame_StackAlloc` is 16-byte aligned.
#define FaultingExceptionFrame_StackAlloc (SIZEOF__FaultingExceptionFrame)
#define FaultingExceptionFrame_FrameOffset 0

.macro GenerateRedirectedStubWithFrame stub, target

    //
    // This is the primary function to which execution will be redirected to.
    //
    NESTED_ENTRY \stub, _TEXT, NoHandler

        //
        // IN: ra: original IP before redirect
        //

        PROLOG_SAVE_REG_PAIR_INDEXED  fp, ra, 16

        // alloc stack for FaultingExceptionFrame.
        addi  sp, sp, -FaultingExceptionFrame_StackAlloc

        // stack must be 16 bytes aligned
        CHECK_STACK_ALIGNMENT

        // Save pointer to FEF for GetFrameFromRedirectedStubStackFrame
        addi  a0, sp, FaultingExceptionFrame_FrameOffset

        // Prepare to initialize to NULL
        sd    zero, 0(a0)  // Initialize vtbl (it is not strictly necessary)
        sd    zero, FaultingExceptionFrame__m_fFilterExecuted(a0)  // Initialize BOOL for personality routine

        call   C_FUNC(\target)
        // Target should not return.
        EMIT_BREAKPOINT

    NESTED_END \stub, _TEXT

.endm

GenerateRedirectedStubWithFrame RedirectForThreadAbort, ThrowControlForThread

// ------------------------------------------------------------------
// ResolveWorkerChainLookupAsmStub
//
// This method will perform a quick chained lookup of the entry if the
//  initial cache lookup fails.
//
// On Entry:
//   t1       contains the pointer to the current ResolveCacheElem
//   t5       contains the address of the indirection (and the flags in the low two bits)
//   t2       contains our contract the DispatchToken
// Must be preserved:
//   a0       contains the instance object ref that we are making an interface call on
//   t1       Must point to a ResolveCacheElem [For Sanity]
//  [a1-a7]   contains any additional register arguments for the interface method
//
// Loaded from a0
//   t6       contains our type     the MethodTable  (from object ref in a0)
//
// On Exit:
//   a0, [a1-a7] arguments for the interface implementation target
//
// On Exit (to ResolveWorkerAsmStub):
//   t5       contains the address of the indirection and the flags in the low two bits.
//   t2       contains our contract (DispatchToken)
//   t4 will be trashed
//

#define BACKPATCH_FLAG      1
#define PROMOTE_CHAIN_FLAG  2

NESTED_ENTRY ResolveWorkerChainLookupAsmStub, _TEXT, NoHandler
    andi  t4, t5, BACKPATCH_FLAG     // First we check if t5 has the BACKPATCH_FLAG set
    bne  t4, zero, LOCAL_LABEL(Fail) // If the BACKPATCH_FLAGS is set we will go directly to the ResolveWorkerAsmStub

    ld  t6, 0(a0)         // retrieve the MethodTable from the object ref in a0
LOCAL_LABEL(MainLoop):
    ld  t1, (ResolveCacheElem__pNext)(t1)     // t1 <= the next entry in the chain
    beq  t1, zero, LOCAL_LABEL(Fail)

    ld  t4, 0(t1)
    // compare our MT with the one in the ResolveCacheElem
    bne  t4, t6, LOCAL_LABEL(MainLoop)

    ld  t4, 8(t1)
    // compare our DispatchToken with one in the ResolveCacheElem
    bne  t2, t4, LOCAL_LABEL(MainLoop)

LOCAL_LABEL(Success):
    PREPARE_EXTERNAL_VAR  g_dispatch_cache_chain_success_counter, t6
    ld  t4, 0(t6)
    addi t4, t4, -1
    sd  t4, 0(t6)
    blt t4, zero, LOCAL_LABEL(Promote)

    ld  t4, (ResolveCacheElem__target)(t1)    // get the ImplTarget
    jr  t4                                    // branch to interface implementation target

LOCAL_LABEL(Promote):
                          // Move this entry to head position of the chain
    addi  t4, zero, 256
    sd  t4, 0(t6)        // be quick to reset the counter so we don't get a bunch of contending threads
    ori  t5, t5, PROMOTE_CHAIN_FLAG   // set PROMOTE_CHAIN_FLAG
    addi  t2, t1, 0           // We pass the ResolveCacheElem to ResolveWorkerAsmStub instead of the DispatchToken

LOCAL_LABEL(Fail):
    tail  C_FUNC(ResolveWorkerAsmStub) // call the ResolveWorkerAsmStub method to transition into the VM
NESTED_END ResolveWorkerChainLookupAsmStub, _TEXT

// ------------------------------------------------------------------
// void ResolveWorkerAsmStub(args in regs a0-a7 & stack, t5:IndirectionCellAndFlags, t2:DispatchToken)
//
// The stub dispatch thunk which transfers control to VSD_ResolveWorker.
NESTED_ENTRY ResolveWorkerAsmStub, _TEXT, NoHandler
    PROLOG_WITH_TRANSITION_BLOCK

    addi  a2, t2, 0                 // DispatchToken
    addi  a0, sp, __PWTB_TransitionBlock        // pTransitionBlock
    srli  a1, t5, 2
    andi  a3, t5, 3              // flag
    slli  a1, a1, 2
    call C_FUNC(VSD_ResolveWorker)
    addi  t4, a0, 0

    EPILOG_WITH_TRANSITION_BLOCK_TAILCALL

    EPILOG_BRANCH_REG  t4
NESTED_END ResolveWorkerAsmStub, _TEXT

#ifdef FEATURE_HIJACK
// ------------------------------------------------------------------
// Hijack function for functions which return a scalar type or a struct (value type)
NESTED_ENTRY OnHijackTripThread, _TEXT, NoHandler
    PROLOG_SAVE_REG_PAIR_INDEXED   fp, ra, 0xa0

    // Spill callee saved registers
    PROLOG_SAVE_REG_PAIR   s1, s2, 16
    PROLOG_SAVE_REG_PAIR   s3, s4, 32
    PROLOG_SAVE_REG_PAIR   s5, s6, 48
    PROLOG_SAVE_REG_PAIR   s7, s8, 64
    PROLOG_SAVE_REG_PAIR   s9, s10, 80
    PROLOG_SAVE_REG_PAIR   s11, gp, 96
    PROLOG_SAVE_REG        tp, 112

    // save any integral return value(s)
    sd  a0, 120(sp)
    sd  a1, 128(sp)

    // save any FP/HFA return value(s)
    fsd  f0, 136(sp)
    fsd  f1, 144(sp)

    addi  a0, sp, 0
    call  C_FUNC(OnHijackWorker)

    // restore callee saved registers

    // restore any integral return value(s)
    ld  a0, 120(sp)
    ld  a1, 128(sp)

    // restore any FP/HFA return value(s)
    fld  f0, 136(sp)
    fld  f1, 144(sp)

    EPILOG_RESTORE_REG_PAIR   s1, s2, 16
    EPILOG_RESTORE_REG_PAIR   s3, s4, 32
    EPILOG_RESTORE_REG_PAIR   s5, s6, 48
    EPILOG_RESTORE_REG_PAIR   s7, s8, 64
    EPILOG_RESTORE_REG_PAIR   s9, s10, 80
    EPILOG_RESTORE_REG_PAIR   s11, gp, 96
    EPILOG_RESTORE_REG        tp, 112
    EPILOG_RESTORE_REG_PAIR_INDEXED  fp, ra, 0xa0
    EPILOG_RETURN
NESTED_END OnHijackTripThread, _TEXT

#endif // FEATURE_HIJACK

// ------------------------------------------------------------------
// Redirection Stub for GC in fully interruptible method
//GenerateRedirectedHandledJITCaseStub GCThreadControl
// ------------------------------------------------------------------
//GenerateRedirectedHandledJITCaseStub DbgThreadControl
// ------------------------------------------------------------------
//GenerateRedirectedHandledJITCaseStub UserSuspend

#ifdef _DEBUG
// ------------------------------------------------------------------
// Redirection Stub for GC Stress
GenerateRedirectedHandledJITCaseStub GCStress
#endif


// ------------------------------------------------------------------
// This helper enables us to call into a funclet after restoring Fp register
NESTED_ENTRY CallEHFunclet, _TEXT, NoHandler
    // On entry:
    //
    // a0 = throwable
    // a1 = PC to invoke
    // a2 = address of CONTEXT record; used to restore the non-volatile registers of CrawlFrame
    // a3 = address of the location where the SP of funclet's caller (i.e. this helper) should be saved.
    //

    PROLOG_SAVE_REG_PAIR_INDEXED   fp, ra, 128, 0

    // Spill callee saved registers
    PROLOG_SAVE_REG_PAIR   s1, s2, 16
    PROLOG_SAVE_REG_PAIR   s3, s4, 32
    PROLOG_SAVE_REG_PAIR   s5, s6, 48
    PROLOG_SAVE_REG_PAIR   s7, s8, 64
    PROLOG_SAVE_REG_PAIR   s9, s10, 80
    PROLOG_SAVE_REG_PAIR   s11, gp, 96
    PROLOG_SAVE_REG tp, 112

    // Save the SP of this function
    sd  sp, 0(a3)

    ld  gp, OFFSETOF__CONTEXT__Gp(a2)
    ld  tp, OFFSETOF__CONTEXT__Tp(a2)
    ld  fp, OFFSETOF__CONTEXT__Fp(a2)
    ld  s1, OFFSETOF__CONTEXT__S1(a2)
    ld  s2, OFFSETOF__CONTEXT__S2(a2)
    ld  s3, OFFSETOF__CONTEXT__S2+8(a2)
    ld  s4, OFFSETOF__CONTEXT__S2+16(a2)
    ld  s5, OFFSETOF__CONTEXT__S2+24(a2)
    ld  s6, OFFSETOF__CONTEXT__S2+32(a2)
    ld  s7, OFFSETOF__CONTEXT__S2+40(a2)
    ld  s8, OFFSETOF__CONTEXT__S2+48(a2)
    ld  s9, OFFSETOF__CONTEXT__S2+56(a2)
    ld  s10, OFFSETOF__CONTEXT__S2+64(a2)
    ld  s11, OFFSETOF__CONTEXT__S2+72(a2)

    // Invoke the funclet
    jalr a1

    EPILOG_RESTORE_REG_PAIR   s1, s2, 16
    EPILOG_RESTORE_REG_PAIR   s3, s4, 32
    EPILOG_RESTORE_REG_PAIR   s5, s6, 48
    EPILOG_RESTORE_REG_PAIR   s7, s8, 64
    EPILOG_RESTORE_REG_PAIR   s9, s10, 80
    EPILOG_RESTORE_REG_PAIR   s11, gp, 96
    EPILOG_RESTORE_REG tp, 112

    EPILOG_RESTORE_REG_PAIR_INDEXED   fp, ra, 128
    EPILOG_RETURN
NESTED_END CallEHFunclet, _TEXT

// This helper enables us to call into a filter funclet by passing it the CallerSP to lookup the
// frame pointer for accessing the locals in the parent method.
NESTED_ENTRY CallEHFilterFunclet, _TEXT, NoHandler
    PROLOG_SAVE_REG_PAIR_INDEXED   fp, ra, 16, 0

    // On entry:
    //
    // a0 = throwable
    // a1 = FP of main function
    // a2 = PC to invoke
    // a3 = address of the location where the SP of funclet's caller (i.e. this helper) should be saved.
    //
    // Save the SP of this function
    sd  sp, 0(a3)
    // Restore frame pointer
    mv  fp, a1
    // Invoke the filter funclet
    jalr a2

    EPILOG_RESTORE_REG_PAIR_INDEXED   fp, ra, 16
    EPILOG_RETURN
NESTED_END CallEHFilterFunclet, _TEXT

#ifdef FEATURE_COMINTEROP
// Function used by COM interop to get floating point return value (since it's not in the same
// register(s) as non-floating point values).
//
// On entry//
//   a0          : size of the FP result (4 or 8 bytes)
//   a1          : pointer to 64-bit buffer to receive result
//
// On exit:
//   buffer pointed to by a1 on entry contains the float or double argument as appropriate
//
LEAF_ENTRY getFPReturn, _TEXT
    fsd  f0, 0(a1)
LEAF_END getFPReturn, _TEXT

// ------------------------------------------------------------------
// Function used by COM interop to set floating point return value (since it's not in the same
// register(s) as non-floating point values).
//
LEAF_ENTRY setFPReturn, _TEXT
    fmv.d.x f0, a1
LEAF_END setFPReturn, _TEXT

#endif // FEATURE_COMINTEROP

// ------------------------------------------------------------------
// void* JIT_GetDynamicNonGCStaticBase(DynamicStaticsInfo* pStaticsInfo)

LEAF_ENTRY JIT_GetDynamicNonGCStaticBase_SingleAppDomain, _TEXT
    // If class is not initialized, bail to C++ helper
    ld a1, OFFSETOF__DynamicStaticsInfo__m_pNonGCStatics(a0)
    fence r,rw
    bnez a1, LOCAL_LABEL(JIT_GetDynamicNonGCStaticBase_SingleAppDomain_CallHelper)
    mv  a0, a1
    ret

LOCAL_LABEL(JIT_GetDynamicNonGCStaticBase_SingleAppDomain_CallHelper):
    // Tail call GetNonGCStaticBase
    ld a0, OFFSETOF__DynamicStaticsInfo__m_pMethodTable(a0)
    PREPARE_EXTERNAL_VAR g_pGetNonGCStaticBase, t4
    ld t4, 0(t4)
    EPILOG_BRANCH_REG        t4
LEAF_END JIT_GetDynamicNonGCStaticBase_SingleAppDomain, _TEXT

// ------------------------------------------------------------------
// void* JIT_GetDynamicGCStaticBase(DynamicStaticsInfo* pStaticsInfo)

LEAF_ENTRY JIT_GetDynamicGCStaticBase_SingleAppDomain, _TEXT
    // If class is not initialized, bail to C++ helper
    ld a1, OFFSETOF__DynamicStaticsInfo__m_pGCStatics(a0)
    fence r,rw
    bnez a1, LOCAL_LABEL(JIT_GetDynamicGCStaticBase_SingleAppDomain_CallHelper)
    mv  a0, a1
    ret

LOCAL_LABEL(JIT_GetDynamicGCStaticBase_SingleAppDomain_CallHelper):
    // Tail call GetGCStaticBase
    ld a0, OFFSETOF__DynamicStaticsInfo__m_pMethodTable(a0)
    PREPARE_EXTERNAL_VAR g_pGetGCStaticBase, t4
    ld t4, 0(t4)
    EPILOG_BRANCH_REG        t4
LEAF_END JIT_GetDynamicGCStaticBase_SingleAppDomain, _TEXT

#ifdef FEATURE_READYTORUN

NESTED_ENTRY DelayLoad_MethodCall_FakeProlog, _TEXT, NoHandler
C_FUNC(DelayLoad_MethodCall):
    .global C_FUNC(DelayLoad_MethodCall)
    PROLOG_WITH_TRANSITION_BLOCK

    addi  a1, t5, 0      // Indirection cell
    addi  a2, t0, 0      // sectionIndex
    addi  a3, t1, 0      // Module*

    addi  a0, sp, __PWTB_TransitionBlock        // pTransitionBlock
    call  C_FUNC(ExternalMethodFixupWorker)
    addi  t4, a0, 0

    EPILOG_WITH_TRANSITION_BLOCK_TAILCALL
    EPILOG_BRANCH_REG   t4
NESTED_END DelayLoad_MethodCall_FakeProlog, _TEXT


.macro DynamicHelper frameFlags, suffix
NESTED_ENTRY DelayLoad_Helper\suffix\()_FakeProlog, _TEXT, NoHandler
DelayLoad_Helper\suffix:
    .global DelayLoad_Helper\suffix

    PROLOG_WITH_TRANSITION_BLOCK

    //DynamicHelperWorker(TransitionBlock * pTransitionBlock, TADDR * pCell,
    //                    DWORD sectionIndex, Module * pModule, INT frameFlags)
    addi  a1, t5, 0      // Indirection cell
    addi  a2, t0, 0      // sectionIndex
    addi  a3, t1, 0      // Module*
    addi  a4, x0, \frameFlags

    addi  a0, sp, __PWTB_TransitionBlock        // pTransitionBlock
    call  DynamicHelperWorker

    bne a0, x0, LOCAL_LABEL(FakeProlog\suffix\()_0)

    ld  a0, __PWTB_ArgumentRegisters(sp)
    EPILOG_WITH_TRANSITION_BLOCK_RETURN

LOCAL_LABEL(FakeProlog\suffix\()_0):
    addi t4, a0, 0
    EPILOG_WITH_TRANSITION_BLOCK_TAILCALL
    EPILOG_BRANCH_REG  t4

NESTED_END DelayLoad_Helper\suffix\()_FakeProlog, _TEXT
.endm

DynamicHelper DynamicHelperFrameFlags_Default
DynamicHelper DynamicHelperFrameFlags_ObjectArg, _Obj
DynamicHelper DynamicHelperFrameFlags_ObjectArg | DynamicHelperFrameFlags_ObjectArg2, _ObjObj
#endif


#ifdef PROFILING_SUPPORTED

// ------------------------------------------------------------------
LEAF_ENTRY JIT_ProfilerEnterLeaveTailcallStub, _TEXT
    ret
LEAF_END JIT_ProfilerEnterLeaveTailcallStub, _TEXT

// ------------------------------------------------------------------
.macro GenerateProfileHelper helper, flags
NESTED_ENTRY \helper\()Naked, _TEXT, NoHandler
    // On entry:
    //   t0 = functionIDOrClientID
    //   t1 = profiledSp
    //   t6 = throwable
    //
    // On exit:
    //   Values of a0-a7, fa0-fa7, fp are preserved.
    //   Values of other volatile registers are not preserved.

    // Fill in PROFILE_PLATFORM_SPECIFIC_DATA struct
    PROLOG_SAVE_REG_PAIR_INDEXED fp, ra, SIZEOF__PROFILE_PLATFORM_SPECIFIC_DATA // Allocate space and save Fp, Pc.
    SAVE_ARGUMENT_REGISTERS sp, PROFILE_PLATFORM_SPECIFIC_DATA__argumentRegisters
    sd     zero, PROFILE_PLATFORM_SPECIFIC_DATA__functionId(sp)
    SAVE_FLOAT_ARGUMENT_REGISTERS sp, PROFILE_PLATFORM_SPECIFIC_DATA__floatArgumentRegisters
    addi     t6, sp, SIZEOF__PROFILE_PLATFORM_SPECIFIC_DATA // Compute probeSp - initial value of Sp on entry to the helper.
    sd  t6, PROFILE_PLATFORM_SPECIFIC_DATA__probeSp(sp)
    sd  t1, PROFILE_PLATFORM_SPECIFIC_DATA__profiledSp(sp)
    sd  zero, PROFILE_PLATFORM_SPECIFIC_DATA__hiddenArg(sp)
    addi  t6, zero, \flags
    sd  t6, PROFILE_PLATFORM_SPECIFIC_DATA__flags(sp)

    addi  a0, t0, 0
    addi  a1, sp, 0
    call  C_FUNC(\helper)

    RESTORE_ARGUMENT_REGISTERS sp, PROFILE_PLATFORM_SPECIFIC_DATA__argumentRegisters
    RESTORE_FLOAT_ARGUMENT_REGISTERS sp, PROFILE_PLATFORM_SPECIFIC_DATA__floatArgumentRegisters
    EPILOG_RESTORE_REG_PAIR_INDEXED fp, ra, SIZEOF__PROFILE_PLATFORM_SPECIFIC_DATA
    EPILOG_RETURN

NESTED_END \helper\()Naked, _TEXT
.endm

GenerateProfileHelper ProfileEnter, PROFILE_ENTER
GenerateProfileHelper ProfileLeave, PROFILE_LEAVE
GenerateProfileHelper ProfileTailcall, PROFILE_TAILCALL

#endif // PROFILING_SUPPORTED


#ifdef FEATURE_TIERED_COMPILATION

NESTED_ENTRY OnCallCountThresholdReachedStub, _TEXT, NoHandler
    PROLOG_WITH_TRANSITION_BLOCK

    addi  a0, sp, __PWTB_TransitionBlock // TransitionBlock *
    addi  a1, t3, 0 // stub-identifying token
    call  C_FUNC(OnCallCountThresholdReached)
    addi  t4, a0, 0

    EPILOG_WITH_TRANSITION_BLOCK_TAILCALL
    EPILOG_BRANCH_REG t4
NESTED_END OnCallCountThresholdReachedStub, _TEXT

NESTED_ENTRY JIT_Patchpoint, _TEXT, NoHandler
    PROLOG_WITH_TRANSITION_BLOCK

    addi  a0, sp, __PWTB_TransitionBlock // TransitionBlock *
    call  C_FUNC(JIT_PatchpointWorkerWorkerWithPolicy)

    EPILOG_WITH_TRANSITION_BLOCK_RETURN
NESTED_END JIT_Patchpoint, _TEXT

// first arg register holds iloffset, which needs to be moved to the second register, and the first register filled with NULL
LEAF_ENTRY JIT_PatchpointForced, _TEXT
    mv    a1, a0
    li    a0, 0
    j C_FUNC(JIT_Patchpoint)
LEAF_END JIT_PatchpointForced, _TEXT

#endif // FEATURE_TIERED_COMPILATION

// ------------------------------------------------------------------
// size_t GetThreadStaticsVariableOffset()

// Load offset of native thread local variable `t_ThreadStatics` in TCB and return it in `a0` register.
LEAF_ENTRY GetThreadStaticsVariableOffset, _TEXT
    la.tls.ie   a0, t_ThreadStatics
    EPILOG_RETURN
LEAF_END GetThreadStaticsVariableOffset, _TEXT

LEAF_ENTRY JIT_PollGC, _TEXT
        PREPARE_EXTERNAL_VAR g_TrapReturningThreads, t0
        lw      t0, 0(t0)
        bnez    t0, LOCAL_LABEL(JIT_PollGCRarePath)
        ret
LOCAL_LABEL(JIT_PollGCRarePath):
        PREPARE_EXTERNAL_VAR g_pPollGC, t0
        ld      t0, 0(t0)
        jr      t0
LEAF_END JIT_PollGC, _TEXT

//a0 -This pointer
//a1 -ReturnBuffer
LEAF_ENTRY ThisPtrRetBufPrecodeWorker, _TEXT
    ld  t2, ThisPtrRetBufPrecodeData__Target(METHODDESC_REGISTER)
    mv  t6, a0     // Move first arg pointer to temp register
    mv  a0, a1     // Move ret buf arg pointer from location in ABI for return buffer for instance method to location in ABI for return buffer for static method
    mv  a1, t6     // Move temp register to first arg register for static method with return buffer
    EPILOG_BRANCH_REG t2
LEAF_END ThisPtrRetBufPrecodeWorker, _TEXT
