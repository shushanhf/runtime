// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers.Binary;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Versioning;
using System.Threading;

namespace System.Runtime.CompilerServices
{
    public static partial class RuntimeHelpers
    {
        [Intrinsic]
        public static unsafe void InitializeArray(Array array, RuntimeFieldHandle fldHandle)
        {
            if (array is null)
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.array);

            if (fldHandle.IsNullHandle())
                throw new ArgumentException(SR.Argument_InvalidHandle);

            IRuntimeFieldInfo fldInfo = fldHandle.GetRuntimeFieldInfo();

            if (!RuntimeFieldHandle.GetRVAFieldInfo(fldInfo.Value, out void* address, out uint size))
                throw new ArgumentException(SR.Argument_BadFieldForInitializeArray);

            // Note that we do not check that the field is actually in the PE file that is initializing
            // the array. Basically, the data being published can be accessed by anyone with the proper
            // permissions (C# marks these as assembly visibility, and thus are protected from outside
            // snooping)

            MethodTable* pMT = GetMethodTable(array);
            TypeHandle elementTH = pMT->GetArrayElementTypeHandle();

            if (elementTH.IsTypeDesc || !elementTH.AsMethodTable()->IsPrimitive) // Enum is included
                throw new ArgumentException(SR.Argument_BadArrayForInitializeArray);

            nuint totalSize = pMT->ComponentSize * array.NativeLength;

            // make certain you don't go off the end of the rva static
            if (totalSize > size)
                throw new ArgumentException(SR.Argument_BadFieldForInitializeArray);

            ref byte src = ref *(byte*)address; // Ref is extending the lifetime of the static field.
            GC.KeepAlive(fldInfo);

            ref byte dst = ref MemoryMarshal.GetArrayDataReference(array);

            Debug.Assert(!elementTH.AsMethodTable()->ContainsGCPointers);

            if (BitConverter.IsLittleEndian)
            {
                SpanHelpers.Memmove(ref dst, ref src, totalSize);
            }
            else
            {
                switch (pMT->ComponentSize)
                {
                    case sizeof(byte):
                        SpanHelpers.Memmove(ref dst, ref src, totalSize);
                        break;
                    case sizeof(ushort):
                        BinaryPrimitives.ReverseEndianness(
                            new ReadOnlySpan<ushort>(ref Unsafe.As<byte, ushort>(ref src), array.Length),
                            new Span<ushort>(ref Unsafe.As<byte, ushort>(ref dst), array.Length));
                        break;
                    case sizeof(uint):
                        BinaryPrimitives.ReverseEndianness(
                            new ReadOnlySpan<uint>(ref Unsafe.As<byte, uint>(ref src), array.Length),
                            new Span<uint>(ref Unsafe.As<byte, uint>(ref dst), array.Length));
                        break;
                    case sizeof(ulong):
                        BinaryPrimitives.ReverseEndianness(
                            new ReadOnlySpan<ulong>(ref Unsafe.As<byte, ulong>(ref src), array.Length),
                            new Span<ulong>(ref Unsafe.As<byte, ulong>(ref dst), array.Length));
                        break;
                    default:
                        Debug.Fail("Incorrect primitive type size!");
                        break;
                }
            }
        }

        private static unsafe ref byte GetSpanDataFrom(
            RuntimeFieldHandle fldHandle,
            RuntimeTypeHandle targetTypeHandle,
            out int count)
        {
            if (fldHandle.IsNullHandle())
                throw new ArgumentException(SR.Argument_InvalidHandle);

            IRuntimeFieldInfo fldInfo = fldHandle.GetRuntimeFieldInfo();

            if (!RuntimeFieldHandle.GetRVAFieldInfo(fldInfo.Value, out void* data, out uint totalSize))
                throw new ArgumentException(SR.Argument_BadFieldForInitializeArray);

            TypeHandle th = targetTypeHandle.GetRuntimeType().GetNativeTypeHandle();
            Debug.Assert(!th.IsTypeDesc); // TypeDesc can't be used as generic parameter
            MethodTable* targetMT = th.AsMethodTable();

            if (!targetMT->IsPrimitive) // Enum is included
                throw new ArgumentException(SR.Argument_BadArrayForInitializeArray);

            uint targetTypeSize = targetMT->GetNumInstanceFieldBytes();
            Debug.Assert(uint.IsPow2(targetTypeSize));

            if (((nuint)data & (targetTypeSize - 1)) != 0)
                throw new ArgumentException(SR.Argument_BadFieldForInitializeArray);

            if (!BitConverter.IsLittleEndian)
            {
                throw new PlatformNotSupportedException();
            }

            count = (int)(totalSize / targetTypeSize);
            ref byte dataRef = ref *(byte*)data; // Ref is extending the lifetime of the static field.
            GC.KeepAlive(fldInfo);

            return ref dataRef;
        }

        // GetObjectValue is intended to allow value classes to be manipulated as 'Object'
        // but have aliasing behavior of a value class.  The intent is that you would use
        // this function just before an assignment to a variable of type 'Object'.  If the
        // value being assigned is a mutable value class, then a shallow copy is returned
        // (because value classes have copy semantics), but otherwise the object itself
        // is returned.
        //
        // Note: VB calls this method when they're about to assign to an Object
        // or pass it as a parameter.  The goal is to make sure that boxed
        // value types work identical to unboxed value types - ie, they get
        // cloned when you pass them around, and are always passed by value.
        // Of course, reference types are not cloned.
        //
        [return: NotNullIfNotNull(nameof(obj))]
        public static unsafe object? GetObjectValue(object? obj)
        {
            if (obj == null)
                return null;

            MethodTable* pMT = GetMethodTable(obj);

            if (!pMT->IsValueType || pMT->IsPrimitive)
                return obj;

            // Technically we could return boxed DateTimes and Decimals without
            // copying them here, but VB realized that this would be a breaking change
            // for their customers.  So copy them.

            return obj.MemberwiseClone();
        }

        // RunClassConstructor causes the class constructor for the given type to be triggered
        // in the current domain.  After this call returns, the class constructor is guaranteed to
        // have at least been started by some thread.  In the absence of class constructor
        // deadlock conditions, the call is further guaranteed to have completed.
        //
        // This call will generate an exception if the specified class constructor threw an
        // exception when it ran.

        [LibraryImport(QCall, EntryPoint = "ReflectionInvocation_RunClassConstructor")]
        private static partial void RunClassConstructor(QCallTypeHandle type);

        [RequiresUnreferencedCode("Trimmer can't guarantee existence of class constructor")]
        public static void RunClassConstructor(RuntimeTypeHandle type)
        {
            RuntimeType rt = type.GetRuntimeType() ??
                throw new ArgumentException(SR.InvalidOperation_HandleIsNotInitialized, nameof(type));

            RunClassConstructor(new QCallTypeHandle(ref rt));
        }

        // RunModuleConstructor causes the module constructor for the given type to be triggered
        // in the current domain.  After this call returns, the module constructor is guaranteed to
        // have at least been started by some thread.  In the absence of module constructor
        // deadlock conditions, the call is further guaranteed to have completed.
        //
        // This call will generate an exception if the specified module constructor threw an
        // exception when it ran.

        [LibraryImport(QCall, EntryPoint = "ReflectionInvocation_RunModuleConstructor")]
        private static partial void RunModuleConstructor(QCallModule module);

        public static void RunModuleConstructor(ModuleHandle module)
        {
            RuntimeModule rm = module.GetRuntimeModule() ??
                throw new ArgumentException(SR.InvalidOperation_HandleIsNotInitialized, nameof(module));

            RunModuleConstructor(new QCallModule(ref rm));
        }

        [LibraryImport(QCall, EntryPoint = "ReflectionInvocation_CompileMethod")]
        internal static partial void CompileMethod(RuntimeMethodHandleInternal method);

        [LibraryImport(QCall, EntryPoint = "ReflectionInvocation_PrepareMethod")]
        private static unsafe partial void PrepareMethod(RuntimeMethodHandleInternal method, IntPtr* pInstantiation, int cInstantiation);

        public static void PrepareMethod(RuntimeMethodHandle method) => PrepareMethod(method, null);

        public static unsafe void PrepareMethod(RuntimeMethodHandle method, RuntimeTypeHandle[]? instantiation)
        {
            IRuntimeMethodInfo methodInfo = method.GetMethodInfo() ??
                throw new ArgumentException(SR.InvalidOperation_HandleIsNotInitialized, nameof(method));

            // defensive copy of user-provided array, per CopyRuntimeTypeHandles contract
            instantiation = (RuntimeTypeHandle[]?)instantiation?.Clone();

            ReadOnlySpan<IntPtr> instantiationHandles = RuntimeTypeHandle.CopyRuntimeTypeHandles(instantiation, stackScratch: stackalloc IntPtr[8]);
            fixed (IntPtr* pInstantiation = instantiationHandles)
            {
                PrepareMethod(methodInfo.Value, pInstantiation, instantiationHandles.Length);
                GC.KeepAlive(instantiation);
                GC.KeepAlive(methodInfo);
            }
        }

        [LibraryImport(QCall, EntryPoint = "ReflectionInvocation_PrepareDelegate")]
        private static partial void PrepareDelegate(ObjectHandleOnStack d);

        public static void PrepareDelegate(Delegate d)
        {
            if (d is null)
            {
                return;
            }

            PrepareDelegate(ObjectHandleOnStack.Create(ref d));
        }

        /// <summary>
        /// If a hash code has been assigned to the object, it is returned. Otherwise zero is
        /// returned.
        /// </summary>
        [MethodImpl(MethodImplOptions.InternalCall)]
        internal static extern int TryGetHashCode(object? o);

        [LibraryImport(QCall, EntryPoint = "ObjectNative_GetHashCodeSlow")]
        private static partial int GetHashCodeSlow(ObjectHandleOnStack o);

        public static int GetHashCode(object? o)
        {
            int hashCode = TryGetHashCode(o);
            if (hashCode == 0)
            {
                return GetHashCodeWorker(o);
            }
            return hashCode;

            [MethodImpl(MethodImplOptions.NoInlining)]
            static int GetHashCodeWorker(object? o)
            {
                if (o is null)
                {
                    return 0;
                }
                return GetHashCodeSlow(ObjectHandleOnStack.Create(ref o));
            }
        }

        public static new unsafe bool Equals(object? o1, object? o2)
        {
            // Compare by ref for normal classes, by value for value types.

            if (ReferenceEquals(o1, o2))
                return true;

            if (o1 is null || o2 is null)
                return false;

            MethodTable* pMT = GetMethodTable(o1);

            // If it's not a value class, don't compare by value
            if (!pMT->IsValueType)
                return false;

            // Make sure they are the same type.
            if (pMT != GetMethodTable(o2))
                return false;

            // Compare the contents
            return ContentEquals(o1, o2);
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        private static extern bool ContentEquals(object o1, object o2);

        [Obsolete("OffsetToStringData has been deprecated. Use string.GetPinnableReference() instead.")]
        public static int OffsetToStringData
        {
            // This offset is baked in by string indexer intrinsic, so there is no harm
            // in getting it baked in here as well.
            [NonVersionable]
            get =>
                // Number of bytes from the address pointed to by a reference to
                // a String to the first 16-bit character in the String.  Skip
                // over the MethodTable pointer, & String
                // length.  Of course, the String reference points to the memory
                // after the sync block, so don't count that.
                // This property allows C#'s fixed statement to work on Strings.
                // On 64 bit platforms, this should be 12 (8+4) and on 32 bit 8 (4+4).
#if TARGET_64BIT
                12;
#else // 32
                8;
#endif // TARGET_64BIT

        }

        // This method ensures that there is sufficient stack to execute the average Framework function.
        // If there is not enough stack, then it throws System.InsufficientExecutionStackException.
        // Note: this method is not to be confused with ProbeForSufficientStack.
        public static void EnsureSufficientExecutionStack()
        {
            if (!TryEnsureSufficientExecutionStack())
            {
                throw new InsufficientExecutionStackException();
            }
        }

        // This method ensures that there is sufficient stack to execute the average Framework function.
        // If there is not enough stack, then it return false.
        // Note: this method is not to be confused with ProbeForSufficientStack.
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern bool TryEnsureSufficientExecutionStack();

        public static object GetUninitializedObject(
            // This API doesn't call any constructors, but the type needs to be seen as constructed.
            // A type is seen as constructed if a constructor is kept.
            // This obviously won't cover a type with no constructor. Reference types with no
            // constructor are an academic problem. Valuetypes with no constructors are a problem,
            // but IL Linker currently treats them as always implicitly boxed.
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors | DynamicallyAccessedMemberTypes.NonPublicConstructors)]
            Type type)
        {
            if (type is not RuntimeType rt)
            {
                ArgumentNullException.ThrowIfNull(type);
                throw new SerializationException(SR.Format(SR.Serialization_InvalidType, type));
            }

            return rt.GetUninitializedObject();
        }

        [LibraryImport(QCall, EntryPoint = "ObjectNative_AllocateUninitializedClone")]
        internal static partial void AllocateUninitializedClone(ObjectHandleOnStack objHandle);

        /// <returns>true if given type is bitwise equatable (memcmp can be used for equality checking)</returns>
        /// <remarks>
        /// Only use the result of this for Equals() comparison, not for CompareTo() comparison.
        /// </remarks>
        [Intrinsic]
        internal static bool IsBitwiseEquatable<T>()
        {
            // The body of this function will be replaced by the EE.
            // See getILIntrinsicImplementationForRuntimeHelpers for how this happens.
            throw new InvalidOperationException();
        }

        [Intrinsic]
        internal static bool EnumEquals<T>(T x, T y) where T : struct, Enum
        {
            // The body of this function will be replaced by the EE.
            // See getILIntrinsicImplementationForRuntimeHelpers for how this happens.
            return x.Equals(y);
        }

        [Intrinsic]
        internal static int EnumCompareTo<T>(T x, T y) where T : struct, Enum
        {
            // The body of this function will be replaced by the EE.
            // See getILIntrinsicImplementationForRuntimeHelpers for how this happens.
            return x.CompareTo(y);
        }

#if FEATURE_IJW
        [Intrinsic]
        internal static unsafe void CopyConstruct<T>(T* dest, T* src) where T : unmanaged
        {
            // The body of this function will be replaced by the EE.
            // See getILIntrinsicImplementationForRuntimeHelpers for how this happens.
            throw new InvalidOperationException();
        }
#endif
        [DebuggerHidden]
        [DebuggerStepThrough]
        internal static ref byte GetRawData(this object obj) =>
            ref Unsafe.As<RawData>(obj).Data;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe nuint GetRawObjectDataSize(object obj)
        {
            MethodTable* pMT = GetMethodTable(obj);

            // See comment on RawArrayData for details
            nuint rawSize = pMT->BaseSize - (nuint)(2 * sizeof(IntPtr));
            if (pMT->HasComponentSize)
                rawSize += (uint)Unsafe.As<RawArrayData>(obj).Length * (nuint)pMT->ComponentSize;

            GC.KeepAlive(obj); // Keep MethodTable alive

            return rawSize;
        }

        // Returns array element size.
        // Callers are required to keep obj alive
        internal static unsafe ushort GetElementSize(this Array array)
        {
            Debug.Assert(ObjectHasComponentSize(array));
            return GetMethodTable(array)->ComponentSize;
        }

        // Returns pointer to the multi-dimensional array bounds.
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ref int GetMultiDimensionalArrayBounds(this Array array)
        {
            Debug.Assert(GetMultiDimensionalArrayRank(array) > 0);
            // See comment on RawArrayData for details
            return ref Unsafe.As<byte, int>(ref Unsafe.As<RawArrayData>(array).Data);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe int GetMultiDimensionalArrayRank(this Array array)
        {
            int rank = GetMethodTable(array)->MultiDimensionalArrayRank;
            GC.KeepAlive(array); // Keep MethodTable alive
            return rank;
        }

        // Returns true iff the object has a component size;
        // i.e., is variable length like System.String or Array.
        // Callers are required to keep obj alive
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static unsafe bool ObjectHasComponentSize(object obj)
        {
            return GetMethodTable(obj)->HasComponentSize;
        }

        /// <summary>
        /// Boxes a given value using an input <see cref="MethodTable"/> to determine its type.
        /// </summary>
        /// <param name="methodTable">The <see cref="MethodTable"/> pointer to use to create the boxed instance.</param>
        /// <param name="data">A reference to the data to box.</param>
        /// <returns>A boxed instance of the value at <paramref name="data"/>.</returns>
        /// <remarks>This method includes proper handling for nullable value types as well.</remarks>
        internal static unsafe object? Box(MethodTable* methodTable, ref byte data) =>
            methodTable->IsNullable ? CastHelpers.Box_Nullable(methodTable, ref data) : CastHelpers.Box(methodTable, ref data);

        // Given an object reference, returns its MethodTable*.
        //
        // WARNING: The caller has to ensure that MethodTable* does not get unloaded. The most robust way
        // to achieve this is by using GC.KeepAlive on the object that the MethodTable* was fetched from, e.g.:
        //
        // MethodTable* pMT = GetMethodTable(o);
        //
        // ... work with pMT ...
        //
        // GC.KeepAlive(o);
        //
        [Intrinsic]
        internal static unsafe MethodTable* GetMethodTable(object obj) => GetMethodTable(obj);

        [LibraryImport(QCall, EntryPoint = "MethodTable_AreTypesEquivalent")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool AreTypesEquivalent(MethodTable* pMTa, MethodTable* pMTb);

        /// <summary>
        /// Allocate memory that is associated with the <paramref name="type"/> and
        /// will be freed if and when the <see cref="Type"/> is unloaded.
        /// </summary>
        /// <param name="type">Type associated with the allocated memory.</param>
        /// <param name="size">Amount of memory in bytes to allocate.</param>
        /// <returns>The allocated memory</returns>
        public static IntPtr AllocateTypeAssociatedMemory(Type type, int size)
        {
            if (type is not RuntimeType rt)
                throw new ArgumentException(SR.Arg_MustBeType, nameof(type));

            ArgumentOutOfRangeException.ThrowIfNegative(size);

            return AllocateTypeAssociatedMemory(new QCallTypeHandle(ref rt), (uint)size);
        }

        [LibraryImport(QCall, EntryPoint = "RuntimeTypeHandle_AllocateTypeAssociatedMemory")]
        private static partial IntPtr AllocateTypeAssociatedMemory(QCallTypeHandle type, uint size);

        [MethodImpl(MethodImplOptions.InternalCall)]
        private static extern IntPtr AllocTailCallArgBufferWorker(int size, IntPtr gcDesc);

        private static IntPtr AllocTailCallArgBuffer(int size, IntPtr gcDesc)
        {
            IntPtr buffer = AllocTailCallArgBufferWorker(size, gcDesc);
            if (buffer == IntPtr.Zero)
            {
                throw new OutOfMemoryException();
            }
            return buffer;
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        private static extern unsafe TailCallTls* GetTailCallInfo(IntPtr retAddrSlot, IntPtr* retAddr);

        [StackTraceHidden]
        private static unsafe void DispatchTailCalls(
            IntPtr callersRetAddrSlot,
            delegate*<IntPtr, ref byte, PortableTailCallFrame*, void> callTarget,
            ref byte retVal)
        {
            IntPtr callersRetAddr;
            TailCallTls* tls = GetTailCallInfo(callersRetAddrSlot, &callersRetAddr);
            PortableTailCallFrame* prevFrame = tls->Frame;
            if (callersRetAddr == prevFrame->TailCallAwareReturnAddress)
            {
                prevFrame->NextCall = callTarget;
                return;
            }

            PortableTailCallFrame newFrame;
            // GC uses NextCall to keep LoaderAllocator alive after we link it below,
            // so we must null it out before that.
            newFrame.NextCall = null;

            try
            {
                tls->Frame = &newFrame;

                do
                {
                    callTarget(tls->ArgBuffer, ref retVal, &newFrame);
                    callTarget = newFrame.NextCall;
                } while (callTarget != null);
            }
            finally
            {
                tls->Frame = prevFrame;

                // If the arg buffer is reporting inst argument, it is safe to abandon it now
                if (tls->ArgBuffer != IntPtr.Zero && *(int*)tls->ArgBuffer == 1 /* TAILCALLARGBUFFER_INSTARG_ONLY */)
                {
                    *(int*)tls->ArgBuffer = 2 /* TAILCALLARGBUFFER_ABANDONED */;
                }
            }
        }

        /// <summary>
        /// Create a boxed object of the specified type from the data located at the target reference.
        /// </summary>
        /// <param name="target">The target data</param>
        /// <param name="type">The type of box to create.</param>
        /// <returns>A boxed object containing the specified data.</returns>
        /// <exception cref="ArgumentNullException">The specified type handle is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">The specified type cannot have a boxed instance of itself created.</exception>
        /// <exception cref="NotSupportedException">The passed in type is a by-ref-like type.</exception>
        public static object? Box(ref byte target, RuntimeTypeHandle type)
        {
            if (type.IsNullHandle())
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.type);

            return type.GetRuntimeType().Box(ref target);
        }

        [LibraryImport(QCall, EntryPoint = "ReflectionInvocation_SizeOf")]
        [SuppressGCTransition]
        private static partial int SizeOf(QCallTypeHandle handle);

        /// <summary>
        /// Get the size of an object of the given type.
        /// </summary>
        /// <param name="type">The type to get the size of.</param>
        /// <returns>The size of instances of the type.</returns>
        /// <exception cref="ArgumentException">The passed-in type is not a valid type to get the size of.</exception>
        /// <remarks>
        /// This API returns the same value as <see cref="Unsafe.SizeOf{T}"/> for the type that <paramref name="type"/> represents.
        /// </remarks>
        public static int SizeOf(RuntimeTypeHandle type)
        {
            if (type.IsNullHandle())
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.type);

            int result = SizeOf(new QCallTypeHandle(ref type));

            if (result <= 0)
                throw new ArgumentException(SR.Arg_TypeNotSupported);

            return result;
        }
    }
    // Helper class to assist with unsafe pinning of arbitrary objects.
    // It's used by VM code.
    [NonVersionable] // This only applies to field layout
    internal sealed class RawData
    {
        public byte Data;
    }

    // CLR arrays are laid out in memory as follows (multidimensional array bounds are optional):
    // [ sync block || pMethodTable || num components || MD array bounds || array data .. ]
    //                 ^               ^                 ^                  ^ returned reference
    //                 |               |                 \-- ref Unsafe.As<RawArrayData>(array).Data
    //                 \-- array       \-- ref Unsafe.As<RawData>(array).Data
    // The BaseSize of an array includes all the fields before the array data,
    // including the sync block and method table. The reference to RawData.Data
    // points at the number of components, skipping over these two pointer-sized fields.
    [NonVersionable] // This only applies to field layout
    internal sealed class RawArrayData
    {
        public uint Length; // Array._numComponents padded to IntPtr
#if TARGET_64BIT
        public uint Padding;
#endif
        public byte Data;
    }

    // Subset of src\vm\methoddesc.hpp
    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct MethodDesc
    {
        public ushort Flags3AndTokenRemainder;
        public byte ChunkIndex;
        public byte Flags4; // Used to hold more flags
        public ushort SlotNumber; // The slot number of this MethodDesc in the vtable array.
        public ushort Flags; // See MethodDescFlags
        public IntPtr CodeData;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [DebuggerHidden]
        [DebuggerStepThrough]
        private MethodDescChunk* GetMethodDescChunk() => (MethodDescChunk*)(((byte*)Unsafe.AsPointer<MethodDesc>(ref this)) - (sizeof(MethodDescChunk) + ChunkIndex * sizeof(IntPtr)));

        public MethodTable* MethodTable => GetMethodDescChunk()->MethodTable;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct MethodDescChunk
    {
        public MethodTable* MethodTable;
        public MethodDescChunk*  Next;
        public byte Size;        // The size of this chunk minus 1 (in multiples of MethodDesc::ALIGNMENT)
        public byte Count;       // The number of MethodDescs in this chunk minus 1
        public ushort FlagsAndTokenRange;
    }

    // Subset of src\vm\methodtable.h
    [StructLayout(LayoutKind.Explicit)]
    internal unsafe struct MethodTable
    {
        /// <summary>
        /// The low WORD of the first field is the component size for array and string types.
        /// </summary>
        [FieldOffset(0)]
        public ushort ComponentSize;

        /// <summary>
        /// The flags for the current method table (only for not array or string types).
        /// </summary>
        [FieldOffset(0)]
        private uint Flags;

        /// <summary>
        /// The base size of the type (used when allocating an instance on the heap).
        /// </summary>
        [FieldOffset(4)]
        public uint BaseSize;

        // See additional native members in methodtable.h, not needed here yet.
        // 0x8: m_dwFlags2 (additional flags and token in upper 24 bits)
        // 0xC: m_wNumVirtuals

        /// <summary>
        /// The number of interfaces implemented by the current type.
        /// </summary>
        [FieldOffset(0x0E)]
        public ushort InterfaceCount;

        // For DEBUG builds, there is a conditional field here (see methodtable.h again).
        // 0x10: debug_m_szClassName (display name of the class, for the debugger)

        /// <summary>
        /// A pointer to the parent method table for the current one.
        /// </summary>
        [FieldOffset(ParentMethodTableOffset)]
        public MethodTable* ParentMethodTable;

        // Additional conditional fields (see methodtable.h).
        // m_pModule

        /// <summary>
        /// A pointer to auxiliary data that is cold for method table.
        /// </summary>
        [FieldOffset(AuxiliaryDataOffset)]
        public MethodTableAuxiliaryData* AuxiliaryData;

        // union {
        //   m_pEEClass (pointer to the EE class)
        //   m_pCanonMT (pointer to the canonical method table)
        // }

        /// <summary>
        /// This element type handle is in a union with additional info or a pointer to the interface map.
        /// Which one is used is based on the specific method table being in used (so this field is not
        /// always guaranteed to actually be a pointer to a type handle for the element type of this type).
        /// </summary>
        [FieldOffset(ElementTypeOffset)]
        public void* ElementType;

        /// <summary>
        /// The PerInstInfo is used to describe the generic arguments and dictionary of this type.
        /// It points at a structure defined as PerInstInfo in C++, which is an array of pointers to generic
        /// dictionaries, which then point to the actual type arguments + the contents of the generic dictionary.
        /// The size of the PerInstInfo is defined in the negative space of that structure, and the size of the
        /// generic dictionary is described in the DictionaryLayout of the associated canonical MethodTable.
        /// </summary>
        [FieldOffset(ElementTypeOffset)]
        public MethodTable*** PerInstInfo;

        /// <summary>
        /// This interface map used to list out the set of interfaces. Only meaningful if InterfaceCount is non-zero.
        /// </summary>
        [FieldOffset(InterfaceMapOffset)]
        public MethodTable** InterfaceMap;

        /// <summary>
        /// This is used to hold the nullable unbox data for nullable value types.
        /// </summary>
        [FieldOffset(InterfaceMapOffset)]
#if TARGET_64BIT
        public uint NullableValueAddrOffset;
#else
        public byte NullableValueAddrOffset;
#endif

#if TARGET_64BIT
        [FieldOffset(InterfaceMapOffset + 4)]
        public uint NullableValueSize;
#else
        [FieldOffset(InterfaceMapOffset)]
        private uint NullableValueSizeEncoded;
        public uint NullableValueSize => NullableValueSizeEncoded >> 8;
#endif

        // WFLAGS_LOW_ENUM
        private const uint enum_flag_GenericsMask = 0x00000030;
        private const uint enum_flag_GenericsMask_NonGeneric = 0x00000000; // no instantiation
        private const uint enum_flag_GenericsMask_GenericInst = 0x00000010; // regular instantiation, e.g. List<String>
        private const uint enum_flag_GenericsMask_SharedInst = 0x00000020; // shared instantiation, e.g. List<__Canon> or List<MyValueType<__Canon>>
        private const uint enum_flag_GenericsMask_TypicalInst = 0x00000030; // the type instantiated at its formal parameters, e.g. List<T>
        private const uint enum_flag_HasDefaultCtor = 0x00000200;
        private const uint enum_flag_IsByRefLike = 0x00001000;

        // WFLAGS_HIGH_ENUM
        private const uint enum_flag_ContainsGCPointers = 0x01000000;
        private const uint enum_flag_ContainsGenericVariables = 0x20000000;
        private const uint enum_flag_HasComponentSize = 0x80000000;
#if FEATURE_TYPEEQUIVALENCE
        private const uint enum_flag_HasTypeEquivalence = 0x02000000;
#endif // FEATURE_TYPEEQUIVALENCE
        private const uint enum_flag_HasFinalizer = 0x00100000;
        private const uint enum_flag_Category_Mask = 0x000F0000;
        private const uint enum_flag_Category_ValueType = 0x00040000;
        private const uint enum_flag_Category_Nullable = 0x00050000;
        private const uint enum_flag_Category_IsPrimitiveMask = 0x000E0000;
        private const uint enum_flag_Category_PrimitiveValueType = 0x00060000; // sub-category of ValueType, Enum or primitive value type
        private const uint enum_flag_Category_TruePrimitive = 0x00070000; // sub-category of ValueType, Primitive (ELEMENT_TYPE_I, etc.)
        private const uint enum_flag_Category_Array = 0x00080000;
        private const uint enum_flag_Category_Array_Mask = 0x000C0000;
        private const uint enum_flag_Category_ValueType_Mask = 0x000C0000;
        private const uint enum_flag_Category_Interface = 0x000C0000;
        // Types that require non-trivial interface cast have this bit set in the category
        private const uint enum_flag_NonTrivialInterfaceCast = 0x00080000 // enum_flag_Category_Array
                                                             | 0x40000000 // enum_flag_ComObject
                                                             | 0x10000000 // enum_flag_IDynamicInterfaceCastable;
                                                             | 0x00040000; // enum_flag_Category_ValueType

        private const int DebugClassNamePtr = // adjust for debug_m_szClassName
#if DEBUG
#if TARGET_64BIT
            8
#else
            4
#endif
#else
            0
#endif
            ;

        private const int ParentMethodTableOffset = 0x10 + DebugClassNamePtr;

#if TARGET_64BIT
        private const int AuxiliaryDataOffset = 0x20 + DebugClassNamePtr;
#else
        private const int AuxiliaryDataOffset = 0x18 + DebugClassNamePtr;
#endif

#if TARGET_64BIT
        private const int ElementTypeOffset = 0x30 + DebugClassNamePtr;
#else
        private const int ElementTypeOffset = 0x20 + DebugClassNamePtr;
#endif

#if TARGET_64BIT
        private const int InterfaceMapOffset = 0x38 + DebugClassNamePtr;
#else
        private const int InterfaceMapOffset = 0x24 + DebugClassNamePtr;
#endif

        public bool HasComponentSize => (Flags & enum_flag_HasComponentSize) != 0;

        public bool ContainsGCPointers => (Flags & enum_flag_ContainsGCPointers) != 0;

        public bool NonTrivialInterfaceCast => (Flags & enum_flag_NonTrivialInterfaceCast) != 0;

#if FEATURE_TYPEEQUIVALENCE
        public bool HasTypeEquivalence => (Flags & enum_flag_HasTypeEquivalence) != 0;
#endif // FEATURE_TYPEEQUIVALENCE

        public bool HasFinalizer => (Flags & enum_flag_HasFinalizer) != 0;

        internal static bool AreSameType(MethodTable* mt1, MethodTable* mt2) => mt1 == mt2;

        public bool HasDefaultConstructor => (Flags & (enum_flag_HasComponentSize | enum_flag_HasDefaultCtor)) == enum_flag_HasDefaultCtor;

        public bool IsSzArray
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get
            {
                Debug.Assert(IsArray);
                return BaseSize == (uint)(3 * sizeof(IntPtr));
            }
        }

        public bool IsMultiDimensionalArray
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get
            {
                Debug.Assert(HasComponentSize);
                // See comment on RawArrayData for details
                return BaseSize > (uint)(3 * sizeof(IntPtr));
            }
        }

        // Returns rank of multi-dimensional array rank, 0 for sz arrays
        public int MultiDimensionalArrayRank
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get
            {
                Debug.Assert(HasComponentSize);
                // See comment on RawArrayData for details
                return (int)((BaseSize - (uint)(3 * sizeof(IntPtr))) / (uint)(2 * sizeof(int)));
            }
        }

        public bool IsInterface => (Flags & enum_flag_Category_Mask) == enum_flag_Category_Interface;

        public bool IsValueType => (Flags & enum_flag_Category_ValueType_Mask) == enum_flag_Category_ValueType;


        public bool IsNullable { [MethodImpl(MethodImplOptions.AggressiveInlining)] get { return (Flags & enum_flag_Category_Mask) == enum_flag_Category_Nullable; } }

        public bool IsByRefLike => (Flags & (enum_flag_HasComponentSize | enum_flag_IsByRefLike)) == enum_flag_IsByRefLike;

        // Warning! UNLIKE the similarly named Reflection api, this method also returns "true" for Enums.
        public bool IsPrimitive => (Flags & enum_flag_Category_IsPrimitiveMask) == enum_flag_Category_PrimitiveValueType;

        public bool IsTruePrimitive => (Flags & enum_flag_Category_Mask) is enum_flag_Category_TruePrimitive;

        public bool IsArray => (Flags & enum_flag_Category_Array_Mask) == enum_flag_Category_Array;

        public bool HasInstantiation => (Flags & enum_flag_HasComponentSize) == 0 && (Flags & enum_flag_GenericsMask) != enum_flag_GenericsMask_NonGeneric;

        public bool IsGenericTypeDefinition => (Flags & (enum_flag_HasComponentSize | enum_flag_GenericsMask)) == enum_flag_GenericsMask_TypicalInst;

        public bool IsConstructedGenericType
        {
            get
            {
                uint genericsFlags = Flags & (enum_flag_HasComponentSize | enum_flag_GenericsMask);
                return genericsFlags == enum_flag_GenericsMask_GenericInst || genericsFlags == enum_flag_GenericsMask_SharedInst;
            }
        }

        public bool IsSharedByGenericInstantiations
        {
            get
            {
                uint genericsFlags = Flags & (enum_flag_HasComponentSize | enum_flag_GenericsMask);
                return genericsFlags == enum_flag_GenericsMask_SharedInst;
            }
        }

        public bool ContainsGenericVariables => (Flags & enum_flag_ContainsGenericVariables) != 0;

        /// <summary>
        /// Gets a <see cref="TypeHandle"/> for the element type of the current type.
        /// </summary>
        /// <remarks>This method should only be called when the current <see cref="MethodTable"/> instance represents an array or string type.</remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public TypeHandle GetArrayElementTypeHandle()
        {
            Debug.Assert(HasComponentSize);

            return new(ElementType);
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        public extern uint GetNumInstanceFieldBytes();

        /// <summary>
        /// Get the <see cref="CorElementType"/> representing primitive-like type. Enums are represented by underlying type.
        /// </summary>
        /// <remarks>This method should only be called when <see cref="IsPrimitive"/> returns <see langword="true"/>.</remarks>
        [MethodImpl(MethodImplOptions.InternalCall)]
        public extern CorElementType GetPrimitiveCorElementType();

        /// <summary>
        /// Get the MethodTable in the type hierarchy of this MethodTable that has the same TypeDef/Module as parent.
        /// </summary>
        [MethodImpl(MethodImplOptions.InternalCall)]
        public extern MethodTable* GetMethodTableMatchingParentClass(MethodTable* parent);

        [MethodImpl(MethodImplOptions.InternalCall)]
        public extern MethodTable* InstantiationArg0();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public uint GetNullableNumInstanceFieldBytes()
        {
            Debug.Assert(IsNullable);
            Debug.Assert((NullableValueAddrOffset + NullableValueSize) == GetNumInstanceFieldBytes());
            return NullableValueAddrOffset + NullableValueSize;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public uint GetNumInstanceFieldBytesIfContainsGCPointers()
        {
            // If the type ContainsGCPointers, we can compute the size without resorting to loading the BaseSizePadding field from the EEClass

            Debug.Assert(ContainsGCPointers);
            Debug.Assert((BaseSize - (nuint)(2 * sizeof(IntPtr)) == GetNumInstanceFieldBytes()));
            return BaseSize - (uint)(2 * sizeof(IntPtr));
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        public extern IntPtr GetLoaderAllocatorHandle();
    }

    // Subset of src\vm\typedesc.h
    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct TypeDesc
    {
        private uint _typeAndFlags;
        private nint _exposedClassObject;

        public RuntimeType? ExposedClassObject
        {
            get
            {
                return *(RuntimeType*)Unsafe.AsPointer(ref _exposedClassObject);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe ref struct DynamicStaticsInfo
    {
        internal const int ISCLASSNOTINITED = 1;
        internal IntPtr _pGCStatics; // The ISCLASSNOTINITED bit is set when the class is NOT initialized
        internal IntPtr _pNonGCStatics; // The ISCLASSNOTINITED bit is set when the class is NOT initialized

        /// <summary>
        /// Given a statics pointer in the DynamicStaticsInfo, get the actual statics pointer.
        /// If the class it initialized, this mask is not necessary
        /// </summary>
        [DebuggerHidden]
        [DebuggerStepThrough]
        internal static ref byte MaskStaticsPointer(ref byte staticsPtr)
        {
            fixed (byte* p = &staticsPtr)
            {
                return ref Unsafe.AsRef<byte>((byte*)((nuint)p & ~(nuint)DynamicStaticsInfo.ISCLASSNOTINITED));
            }
        }

        internal MethodTable* _methodTable;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal ref struct GenericsStaticsInfo
    {
        // Pointer to field descs for statics
        internal IntPtr _pFieldDescs;
        internal DynamicStaticsInfo _dynamicStatics;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal ref struct ThreadStaticsInfo
    {
        internal int _nonGCTlsIndex;
        internal int _gcTlsIndex;
        internal GenericsStaticsInfo _genericStatics;
    }


    // Subset of src\vm\methodtable.h
    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct MethodTableAuxiliaryData
    {
        private uint Flags;
        private void* LoaderModule;
        private nint ExposedClassObjectRaw;

        private const uint enum_flag_HasCheckedCanCompareBitsOrUseFastGetHashCode = 0x0002;  // Whether we have checked the overridden Equals or GetHashCode
        private const uint enum_flag_CanCompareBitsOrUseFastGetHashCode = 0x0004;     // Is any field type or sub field type overridden Equals or GetHashCode

        private const uint enum_flag_Initialized                = 0x0001;
        private const uint enum_flag_HasCheckedStreamOverride   = 0x0400;
        private const uint enum_flag_StreamOverriddenRead       = 0x0800;
        private const uint enum_flag_StreamOverriddenWrite      = 0x1000;
        private const uint enum_flag_EnsuredInstanceActive      = 0x2000;


        public bool HasCheckedCanCompareBitsOrUseFastGetHashCode => (Flags & enum_flag_HasCheckedCanCompareBitsOrUseFastGetHashCode) != 0;

        public bool CanCompareBitsOrUseFastGetHashCode
        {
            get
            {
                Debug.Assert(HasCheckedCanCompareBitsOrUseFastGetHashCode);
                return (Flags & enum_flag_CanCompareBitsOrUseFastGetHashCode) != 0;
            }
        }

        public bool HasCheckedStreamOverride => (Flags & enum_flag_HasCheckedStreamOverride) != 0;

        public bool IsStreamOverriddenRead
        {
            get
            {
                Debug.Assert(HasCheckedStreamOverride);
                return (Flags & enum_flag_StreamOverriddenRead) != 0;
            }
        }

        public bool IsStreamOverriddenWrite
        {
            get
            {
                Debug.Assert(HasCheckedStreamOverride);
                return (Flags & enum_flag_StreamOverriddenWrite) != 0;
            }
        }

        public RuntimeType? ExposedClassObject
        {
            get
            {
                return *(RuntimeType*)Unsafe.AsPointer(ref ExposedClassObjectRaw);
            }
        }

        public bool IsClassInited => (Volatile.Read(ref Flags) & enum_flag_Initialized) != 0;

        public bool IsClassInitedAndActive => (Volatile.Read(ref Flags) & (enum_flag_Initialized | enum_flag_EnsuredInstanceActive)) == (enum_flag_Initialized | enum_flag_EnsuredInstanceActive);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [DebuggerHidden]
        [DebuggerStepThrough]
        public ref DynamicStaticsInfo GetDynamicStaticsInfo()
        {
            return ref Unsafe.Subtract(ref Unsafe.As<MethodTableAuxiliaryData, DynamicStaticsInfo>(ref this), 1);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [DebuggerHidden]
        [DebuggerStepThrough]
        public ref ThreadStaticsInfo GetThreadStaticsInfo()
        {
            return ref Unsafe.Subtract(ref Unsafe.As<MethodTableAuxiliaryData, ThreadStaticsInfo>(ref this), 1);
        }
    }

    /// <summary>
    /// A type handle, which can wrap either a pointer to a <c>TypeDesc</c> or to a <see cref="MethodTable"/>.
    /// </summary>
    internal readonly unsafe partial struct TypeHandle
    {
        // Subset of src\vm\typehandle.h

        /// <summary>
        /// The address of the current type handle object.
        /// </summary>
        private readonly void* m_asTAddr;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public TypeHandle(void* tAddr)
        {
            m_asTAddr = tAddr;
        }

        /// <summary>
        /// Gets whether the current instance wraps a <see langword="null"/> pointer.
        /// </summary>
        public bool IsNull => m_asTAddr is null;

        /// <summary>
        /// Gets whether or not this <see cref="TypeHandle"/> wraps a <c>TypeDesc</c> pointer.
        /// Only if this returns <see langword="false"/> it is safe to call <see cref="AsMethodTable"/>.
        /// </summary>
        public bool IsTypeDesc
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => ((nint)m_asTAddr & 2) != 0;
        }

        /// <summary>
        /// Gets the <see cref="MethodTable"/> pointer wrapped by the current instance.
        /// </summary>
        /// <remarks>This is only safe to call if <see cref="IsTypeDesc"/> returned <see langword="false"/>.</remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public MethodTable* AsMethodTable()
        {
            Debug.Assert(!IsTypeDesc);

            return (MethodTable*)m_asTAddr;
        }

        /// <summary>
        /// Gets the <see cref="TypeDesc"/> pointer wrapped by the current instance.
        /// </summary>
        /// <remarks>This is only safe to call if <see cref="IsTypeDesc"/> returned <see langword="true"/>.</remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public TypeDesc* AsTypeDesc()
        {
            Debug.Assert(IsTypeDesc);

            return (TypeDesc*)((nint)m_asTAddr & ~2); // Drop the second lowest bit.
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TypeHandle TypeHandleOf<T>()
        {
            return new TypeHandle((void*)RuntimeTypeHandle.ToIntPtr(typeof(T).TypeHandle));
        }

        public static bool AreSameType(TypeHandle left, TypeHandle right) => left.m_asTAddr == right.m_asTAddr;

        public int GetCorElementType() => GetCorElementType(m_asTAddr);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool CanCastTo(TypeHandle destTH)
        {
            return TryCanCastTo(this, destTH) switch
            {
                CastResult.CanCast => true,
                CastResult.CannotCast => false,

                // Regular casting does not allow T to be cast to Nullable<T>.
                // See TypeHandle::CanCastTo()
                _ => CanCastToWorker(this, destTH, nullableCast: false)
            };
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool CanCastToForReflection(TypeHandle srcTH, TypeHandle destTH)
        {
            return TryCanCastTo(srcTH, destTH) switch
            {
                CastResult.CanCast => true,
                CastResult.CannotCast => false,

                // Reflection allows T to be cast to Nullable<T>.
                // See ObjIsInstanceOfCore()
                _ => CanCastToWorker(srcTH, destTH, nullableCast: true)
            };
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static CastResult TryCanCastTo(TypeHandle srcTH, TypeHandle destTH)
        {
            // See TypeHandle::CanCastToCached() for duplicate quick checks.
            if (srcTH.m_asTAddr == destTH.m_asTAddr)
                return CastResult.CanCast;

            if (!srcTH.IsTypeDesc && destTH.IsTypeDesc)
                return CastResult.CannotCast;

            return CastCache.TryGet(CastHelpers.s_table!, (nuint)srcTH.m_asTAddr, (nuint)destTH.m_asTAddr);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static bool CanCastToWorker(TypeHandle srcTH, TypeHandle destTH, bool nullableCast)
        {
            if (!srcTH.IsTypeDesc
                && !destTH.IsTypeDesc
                && CastHelpers.IsNullableForType(destTH.AsMethodTable(), srcTH.AsMethodTable()))
            {
                return nullableCast;
            }

            return CanCastTo_NoCacheLookup(srcTH.m_asTAddr, destTH.m_asTAddr) != Interop.BOOL.FALSE;
        }

        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "TypeHandle_CanCastTo_NoCacheLookup")]
        private static partial Interop.BOOL CanCastTo_NoCacheLookup(void* fromTypeHnd, void* toTypeHnd);

        [SuppressGCTransition]
        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "TypeHandle_GetCorElementType")]
        private static partial int GetCorElementType(void* typeHnd);
    }

    // Helper structs used for tail calls via helper.
    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct PortableTailCallFrame
    {
        public IntPtr TailCallAwareReturnAddress;
        public delegate*<IntPtr, ref byte, PortableTailCallFrame*, void> NextCall;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct TailCallTls
    {
        public PortableTailCallFrame* Frame;
        public IntPtr ArgBuffer;
    }
}
