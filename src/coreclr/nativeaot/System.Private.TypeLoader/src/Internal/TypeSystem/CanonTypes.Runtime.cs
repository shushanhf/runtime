// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.


using System;

using Internal.Runtime;
using Internal.Runtime.Augments;

namespace Internal.TypeSystem
{
    public partial class CanonBaseType : DefType { }

    internal partial class CanonType
    {
        partial void Initialize()
        {
            SetRuntimeTypeHandleUnsafe(RuntimeAugments.GetCanonType());
        }
    }
}
