// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;

using Internal.TypeSystem;
using Internal.Runtime;

namespace ILCompiler.DependencyAnalysis
{
    /// <summary>
    /// Canonical type instantiations are emitted, not because they are used directly by the user code, but because
    /// they are used by the dynamic type loader when dynamically instantiating types at runtime.
    /// The data that we emit on canonical type instantiations should just be the minimum that is needed by the template
    /// type loader.
    /// Similarly, the dependencies that we track for canonical type instantiations are minimal, and are just the ones used
    /// by the dynamic type loader
    /// </summary>
    public sealed class CanonicalEETypeNode : EETypeNode
    {
        public CanonicalEETypeNode(NodeFactory factory, TypeDesc type) : base(factory, type)
        {
            Debug.Assert(!type.IsCanonicalDefinitionType(CanonicalFormKind.Any));
            Debug.Assert(type.IsCanonicalSubtype(CanonicalFormKind.Any));
            Debug.Assert(type == type.ConvertToCanonForm(CanonicalFormKind.Specific));
            Debug.Assert(!type.IsMdArray);
        }

        public override bool StaticDependenciesAreComputed => true;
        public override bool IsShareable => IsTypeNodeShareable(_type);
        protected override bool EmitVirtualSlots => true;
        public override bool ShouldSkipEmittingObjectNode(NodeFactory factory) => false;

        protected override DependencyList ComputeNonRelocationBasedDependencies(NodeFactory factory)
        {
            DependencyList dependencyList = base.ComputeNonRelocationBasedDependencies(factory);

            // Ensure that we track the necessary type symbol if we are working with a constructed type symbol.
            // The emitter will ensure we don't emit both, but this allows us assert that we only generate
            // relocs to nodes we emit.
            dependencyList.Add(factory.NecessaryTypeSymbol(_type), "Necessary type symbol related to CanonicalEETypeNode");

            DefType closestDefType = _type.GetClosestDefType();

            dependencyList.Add(factory.VTable(closestDefType), "VTable");

            // Track generic virtual methods that will get added to the GVM tables
            if ((_virtualMethodAnalysisFlags & VirtualMethodAnalysisFlags.NeedsGvmEntries) != 0)
            {
                dependencyList.Add(new DependencyListEntry(factory.TypeGVMEntries(_type.GetTypeDefinition()), "Type with generic virtual methods"));
            }

            return dependencyList;
        }

        protected override ISymbolNode GetBaseTypeNode(NodeFactory factory)
        {
            return _type.BaseType != null ? factory.NecessaryTypeSymbol(_type.BaseType.NormalizeInstantiation()) : null;
        }

        protected override FrozenRuntimeTypeNode GetFrozenRuntimeTypeNode(NodeFactory factory) => throw new NotSupportedException();

        protected override ISymbolNode GetNonNullableValueTypeArrayElementTypeNode(NodeFactory factory)
        {
            return factory.ConstructedTypeSymbol(((ArrayType)_type).ElementType);
        }

        protected override int GCDescSize
        {
            get
            {
                return GCDescEncoder.GetGCDescSize(_type);
            }
        }

        protected override void OutputGCDesc(ref ObjectDataBuilder builder)
        {
            GCDescEncoder.EncodeGCDesc(ref builder, _type);
        }

        protected override void OutputInterfaceMap(NodeFactory factory, ref ObjectDataBuilder objData)
        {
            foreach (DefType intface in _type.RuntimeInterfaces)
            {
                // If the interface was optimized away, skip it
                if (!factory.InterfaceUse(intface.GetTypeDefinition()).Marked)
                    continue;

                // Interface omitted for canonical instantiations (constructed at runtime for dynamic types from the native layout info)
                objData.EmitZeroPointer();
            }
        }

        public override int ClassCode => -1798018602;
    }
}
