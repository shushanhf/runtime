// Copyright (c) .NET Foundation and contributors. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Threading.Tasks;
using ILLink.Shared;
using Microsoft.CodeAnalysis.Testing;
using Xunit;
using VerifyCS = ILLink.RoslynAnalyzer.Tests.CSharpCodeFixVerifier<
    ILLink.RoslynAnalyzer.DynamicallyAccessedMembersAnalyzer,
    ILLink.CodeFix.DynamicallyAccessedMembersCodeFixProvider>;

namespace ILLink.RoslynAnalyzer.Tests
{
    public class DynamicallyAccessedMembersAnalyzerTests
    {
        static Task VerifyDynamicallyAccessedMembersAnalyzer(
            string source,
            bool consoleApplication,
            params DiagnosticResult[] expected)
        {
            return VerifyCS.VerifyAnalyzerAsync(
                source,
                consoleApplication,
                TestCaseUtils.UseMSBuildProperties(MSBuildPropertyOptionNames.EnableTrimAnalyzer),
                expected: expected);
        }

        [Fact]
        public Task NoWarningsIfAnalyzerIsNotEnabled()
        {
            var TargetParameterWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            public class Foo
            {
            }

            class C
            {
                public static void Main()
                {
                    M(typeof(Foo));
                }

                private static void NeedsPublicMethodsOnParameter(
                    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)] Type parameter)
                {
                }

                private static void M(Type type)
                {
                    NeedsPublicMethodsOnParameter(type);
                }
            }
            """;
            return VerifyCS.VerifyAnalyzerAsync(TargetParameterWithAnnotations, consoleApplication: false);
        }

        #region SourceParameter
        [Fact]
        public Task SourceParameterDoesNotMatchTargetParameterAnnotations()
        {
            var TargetParameterWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            public class Foo
            {
            }

            class C
            {
                public static void Main()
                {
                    M(typeof(Foo));
                }
                private static void NeedsPublicMethodsOnParameter(
                    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)] Type parameter)
                {
                }

                private static void M(Type type)
                {
                    NeedsPublicMethodsOnParameter(type);
                }
            }
            """;
            // (21,3): warning IL2067: 'parameter' argument does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' in call to 'C.NeedsPublicMethodsOnParameter(Type)'.
            // The parameter 'type' of method 'C.M(Type)' does not have matching annotations.
            // The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetParameterWithAnnotations, consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchParameterTargetsParameter)
                .WithSpan(21, 9, 21, 44)
                .WithSpan(19, 27, 19, 36)
                .WithArguments("parameter",
                    "C.NeedsPublicMethodsOnParameter(Type)",
                    "type",
                    "C.M(Type)",
                    "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task SourceParameterDoesNotMatchTargetMethodReturnTypeAnnotations()
        {
            var TargetMethodReturnTypeWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            public class Foo
            {
            }

            class C
            {
                public static void Main()
                {
                    M(typeof(Foo));
                }

                [return: DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)]
                private static Type M(Type type)
                {
                    return type;
                }
            }
            """;

            // (18,10): warning IL2068: 'C.M(Type)' method return value does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' requirements.
            // The parameter 'type' of method 'C.M(Type)' does not have matching annotations.
            // The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetMethodReturnTypeWithAnnotations, consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchParameterTargetsMethodReturnType)
                .WithSpan(18, 16, 18, 20)
                .WithSpan(16, 27, 16, 36)
                .WithArguments("C.M(Type)",
                    "type",
                    "C.M(Type)",
                    "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task SourceParameterDoesNotMatchTargetFieldAnnotations()
        {
            var TargetFieldWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            public class Foo
            {
            }

            class C
            {
                public static void Main()
                {
                    M(typeof(Foo));
                }

                private static void M(Type type)
                {
                    f = type;
                }

                [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)]
                private static Type f = typeof(Foo);
            }
            """;

            // (17,3): warning IL2069: value stored in field 'C.f' does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' requirements.
            // The parameter 'type' of method 'C.M(Type)' does not have matching annotations.
            // The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetFieldWithAnnotations, consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchParameterTargetsField)
                .WithSpan(17, 9, 17, 17)
                .WithSpan(15, 27, 15, 36)
                .WithArguments("C.f",
                    "type",
                    "C.M(Type)",
                    "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task SourceParameterDoesNotMatchTargetMethodAnnotations()
        {
            var TargetMethodWithAnnotations = $$"""
            using System;

            public class Foo
            {
            }

            class C
            {
                public static void Main()
                {
                    M(typeof(Foo));
                }

                private static void M(Type type)
                {
                    type.GetMethod("Bar");
                }
            }
            """;
            // The warning will be generated once dataflow is able to handle GetMethod intrinsic

            // (16,3): warning IL2070: 'this' argument does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' in call to 'System.Type.GetMethod(String)'.
            // The parameter 'type' of method 'C.M(Type)' does not have matching annotations.
            // The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetMethodWithAnnotations, consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchParameterTargetsThisParameter)
                .WithSpan(16, 9, 16, 30)
                .WithSpan(14, 27, 14, 36)
                .WithArguments("System.Type.GetMethod(String)",
                    "type",
                    "C.M(Type)",
                    "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }
        #endregion

        #region SourceMethodReturnType
        [Fact]
        public Task SourceMethodReturnTypeDoesNotMatchTargetParameterAnnotations()
        {
            var TargetParameterWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            public class T
            {
            }

            class C
            {
                public static void Main()
                {
                    NeedsPublicMethodsOnParameter(GetT());
                }

                private static void NeedsPublicMethodsOnParameter(
                [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)] Type type)
                {
                }

                private static Type GetT()
                {
                    return typeof(T);
                }
            }
            """;

            // (12,9): warning IL2072: 'type' argument does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' in call to 'C.NeedsPublicMethodsOnParameter(Type)'. The return value of method 'C.GetT()' does not have matching annotations. The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetParameterWithAnnotations, consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchMethodReturnTypeTargetsParameter)
                .WithSpan(12, 9, 12, 46)
                .WithSpan(20, 5, 23, 6)
                .WithArguments("type", "C.NeedsPublicMethodsOnParameter(Type)", "C.GetT()", "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task SourceMethodReturnTypeDoesNotMatchTargetMethodReturnTypeAnnotations()
        {
            var TargetMethodReturnTypeWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            public class Foo
            {
            }

            class C
            {
                public static void Main()
                {
                    M();
                }

                [return: DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)]
                private static Type M()
                {
                    return GetFoo();
                }

                private static Type GetFoo()
                {
                    return typeof(Foo);
                }
            }
            """;

            // (18,16): warning IL2073: 'C.M()' method return value does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' requirements. The return value of method 'C.GetT()' does not have matching annotations. The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetMethodReturnTypeWithAnnotations, consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchMethodReturnTypeTargetsMethodReturnType)
                .WithSpan(18, 16, 18, 24)
                .WithSpan(21, 5, 24, 6)
                .WithArguments("C.M()", "C.GetFoo()", "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task SourceMethodReturnTypeDoesNotMatchTargetFieldAnnotations()
        {
            var TargetFieldWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            public class Foo
            {
            }

            class C
            {
                public static void Main()
                {
                    f = M();
                }

                private static Type M()
                {
                    return typeof(Foo);
                }

                [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)]
                private static Type f;
            }
            """;

            // (12,9): warning IL2074: value stored in field 'C.f' does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' requirements. The return value of method 'C.M()' does not have matching annotations. The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetFieldWithAnnotations, consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchMethodReturnTypeTargetsField)
                .WithSpan(12, 9, 12, 16)
                .WithSpan(15, 5, 18, 6)
                .WithArguments("C.f",
                    "C.M()",
                    "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task SourceMethodReturnTypeDoesNotMatchTargetMethod()
        {
            var TargetMethodWithAnnotations = $$"""
            using System;

            public class Foo
            {
            }

            class C
            {
                public static void Main()
                {
                    GetFoo().GetMethod("Bar");

                }

                private static Type GetFoo()
                {
                    return typeof(Foo);
                }
            }
            """;
            // The warning will be generated once dataflow is able to handle GetMethod intrinsic

            // (11,9): warning IL2075: 'this' argument does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' in call to 'System.Type.GetMethod(String)'. The return value of method 'C.GetT()' does not have matching annotations. The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetMethodWithAnnotations, consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchMethodReturnTypeTargetsThisParameter)
                .WithSpan(11, 9, 11, 34)
                .WithSpan(15, 5, 18, 6)
                .WithArguments("System.Type.GetMethod(String)", "C.GetFoo()", "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        #endregion

        #region SourceField
        [Fact]
        public Task SourceFieldDoesNotMatchTargetParameterAnnotations()
        {
            var TargetParameterWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            public class Foo
            {
            }

            class C
            {
                private static Type f = typeof(Foo);

                public static void Main()
                {
                    NeedsPublicMethods(f);
                }

                private static void NeedsPublicMethods(
                    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)] Type type)
                {
                }
            }
            """;

            // (14,3): warning IL2077: 'type' argument does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' in call to 'C.NeedsPublicMethods(Type)'.
            // The field 'C.f' does not have matching annotations.
            // The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetParameterWithAnnotations, consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchFieldTargetsParameter)
                .WithSpan(14, 9, 14, 30)
                .WithSpan(10, 25, 10, 40)
                .WithArguments("type",
                    "C.NeedsPublicMethods(Type)",
                    "C.f",
                    "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task SourceFieldDoesNotMatchTargetMethodReturnTypeAnnotations()
        {
            var TargetMethodReturnTypeWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            public class Foo
            {
            }

            class C
            {
                private static Type f = typeof(Foo);

                public static void Main()
                {
                    M();
                }

                [return: DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)]
                private static Type M()
                {
                    return f;
                }
            }
            """;

            // (20,10): warning IL2078: 'C.M()' method return value does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' requirements.
            // The field 'C.f' does not have matching annotations.
            // The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetMethodReturnTypeWithAnnotations, consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchFieldTargetsMethodReturnType)
                .WithSpan(20, 16, 20, 17)
                .WithSpan(10, 25, 10, 40)
                .WithArguments("C.M()", "C.f",
                    "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task SourceFieldDoesNotMatchTargetFieldAnnotations()
        {
            var TargetFieldWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            public class Foo
            {
            }

            class C
            {
                private static Type f1 = typeof(Foo);

                [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)]
                private static Type f2 = typeof(Foo);

                public static void Main()
                {
                    f2 = f1;
                }
            }
            """;
            // (17,3): warning IL2079: value stored in field 'C.f2' does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' requirements.
            // The field 'C.f1' does not have matching annotations.
            // The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetFieldWithAnnotations, consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchFieldTargetsField)
                .WithSpan(17, 9, 17, 16)
                .WithSpan(10, 25, 10, 41)
                .WithArguments("C.f2",
                    "C.f1",
                    "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task SourceFieldDoesNotMatchTargetMethodAnnotations()
        {
            var TargetMethodWithAnnotations = $$"""
            using System;

            public class Foo
            {
            }

            class C
            {
                private static Type f = typeof(Foo);

                public static void Main()
                {
                    f.GetMethod("Bar");
                }
            }
            """;
            // The warning will be generated once dataflow is able to handle GetMethod intrinsic

            // (13,3): warning IL2080: 'this' argument does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' in call to 'System.Type.GetMethod(String)'.
            // The field 'C.f' does not have matching annotations.
            // The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetMethodWithAnnotations, consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchFieldTargetsThisParameter)
                .WithSpan(13, 9, 13, 27)
                .WithSpan(9, 25, 9, 40)
                .WithArguments("System.Type.GetMethod(String)",
                    "C.f",
                    "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }
        #endregion

        #region SourceMethod

        public static string GetSystemTypeBase()
        {
            return $$"""
// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Globalization;
using System.Reflection;
using System.Diagnostics.CodeAnalysis;

namespace System
{
    public class TestSystemTypeBase : Type
    {
        public override Assembly Assembly => throw new NotImplementedException();

        public override string AssemblyQualifiedName => throw new NotImplementedException();

        public override Type BaseType => throw new NotImplementedException();

        public override string FullName => throw new NotImplementedException();

        public override Guid GUID => throw new NotImplementedException();

        public override Module Module => throw new NotImplementedException();

        public override string Namespace => throw new NotImplementedException();

        public override Type UnderlyingSystemType => throw new NotImplementedException();

        public override string Name => throw new NotImplementedException();

        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors
            | DynamicallyAccessedMemberTypes.NonPublicConstructors)]
        public override ConstructorInfo[] GetConstructors(BindingFlags bindingAttr)
        {
            throw new NotImplementedException();
        }

        public override object[] GetCustomAttributes(bool inherit)
        {
            throw new NotImplementedException();
        }

        public override object[] GetCustomAttributes(Type attributeType, bool inherit)
        {
            throw new NotImplementedException();
        }

        public override Type GetElementType()
        {
            throw new NotImplementedException();
        }

        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicEvents
        | DynamicallyAccessedMemberTypes.NonPublicEvents)]
        public override EventInfo GetEvent(string name, BindingFlags bindingAttr)
        {
            throw new NotImplementedException();
        }

        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicEvents | DynamicallyAccessedMemberTypes.NonPublicEvents)]
        public override EventInfo[] GetEvents(BindingFlags bindingAttr)
        {
            throw new NotImplementedException();
        }

        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.NonPublicFields)]
        public override FieldInfo GetField(string name, BindingFlags bindingAttr)
        {
            throw new NotImplementedException();
        }

        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields
            | DynamicallyAccessedMemberTypes.NonPublicFields)]
        public override FieldInfo[] GetFields(BindingFlags bindingAttr)
        {
            throw new NotImplementedException();
        }

        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.Interfaces)]
        [return: DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.Interfaces)]
        public override Type GetInterface(string name, bool ignoreCase)
        {
            throw new NotImplementedException();
        }

        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.Interfaces)]
        public override Type[] GetInterfaces()
        {
            throw new NotImplementedException();
        }

        [DynamicallyAccessedMembers((DynamicallyAccessedMemberTypes)0x1FFF)]
        public override MemberInfo[] GetMembers(BindingFlags bindingAttr)
        {
            throw new NotImplementedException();
        }

        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.NonPublicMethods)]
        public override MethodInfo[] GetMethods(BindingFlags bindingAttr)
        {
            throw new NotImplementedException();
        }

        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicNestedTypes | DynamicallyAccessedMemberTypes.NonPublicNestedTypes)]
        public override Type GetNestedType(string name, BindingFlags bindingAttr)
        {
            throw new NotImplementedException();
        }

        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicNestedTypes | DynamicallyAccessedMemberTypes.NonPublicNestedTypes)]
        public override Type[] GetNestedTypes(BindingFlags bindingAttr)
        {
            throw new NotImplementedException();
        }

        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.NonPublicProperties)]
        public override PropertyInfo[] GetProperties(BindingFlags bindingAttr)
        {
            throw new NotImplementedException();
        }

        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors | DynamicallyAccessedMemberTypes.NonPublicConstructors | DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.NonPublicMethods | DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.NonPublicFields | DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.NonPublicProperties)]
        public override object InvokeMember(string name, BindingFlags invokeAttr, Binder binder, object target, object[] args, ParameterModifier[] modifiers, CultureInfo culture, string[] namedParameters)
        {
            throw new NotImplementedException();
        }

        public override bool IsDefined(Type attributeType, bool inherit)
        {
            throw new NotImplementedException();
        }

        protected override TypeAttributes GetAttributeFlagsImpl()
        {
            throw new NotImplementedException();
        }

        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors
        | DynamicallyAccessedMemberTypes.NonPublicConstructors)]
        protected override ConstructorInfo GetConstructorImpl(BindingFlags bindingAttr, Binder binder, CallingConventions callConvention, Type[] types, ParameterModifier[] modifiers)
        {
            throw new NotImplementedException();
        }

        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.NonPublicMethods)]
        protected override MethodInfo GetMethodImpl(string name, BindingFlags bindingAttr, Binder binder, CallingConventions callConvention, Type[] types, ParameterModifier[] modifiers)
        {
            throw new NotImplementedException();
        }

        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.NonPublicProperties)]
        protected override PropertyInfo GetPropertyImpl(string name, BindingFlags bindingAttr, Binder binder, Type returnType, Type[] types, ParameterModifier[] modifiers)
        {
            throw new NotImplementedException();
        }

        protected override bool HasElementTypeImpl()
        {
            throw new NotImplementedException();
        }

        protected override bool IsArrayImpl()
        {
            throw new NotImplementedException();
        }

        protected override bool IsByRefImpl()
        {
            throw new NotImplementedException();
        }

        protected override bool IsCOMObjectImpl()
        {
            throw new NotImplementedException();
        }

        protected override bool IsPointerImpl()
        {
            throw new NotImplementedException();
        }

        protected override bool IsPrimitiveImpl()
        {
            throw new NotImplementedException();
        }
    }
}
""";
        }

        [Fact]
        public Task SourceMethodDoesNotMatchTargetParameterAnnotations()
        {
            var TargetParameterWithAnnotations = $$"""
            namespace System
            {
                class C : TestSystemTypeBase
                {
                    public static void Main()
                    {
                        new C().M1();
                    }

                    private void M1()
                    {
                        M2(this);
                    }

                    private static void M2(
                        [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(
                            System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicMethods)] Type type)
                    {
                    }
                }
            }
            """;

            // (198,13): warning IL2082: 'type' argument does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' in call to 'System.C.M2(Type)'.
            // The implicit 'this' argument of method 'System.C.M1()' does not have matching annotations.
            // The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(string.Concat(GetSystemTypeBase(), TargetParameterWithAnnotations), consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchThisParameterTargetsParameter)
                .WithSpan(198, 13, 198, 21)
                .WithSpan(196, 9, 199, 10)
                .WithArguments("type", "System.C.M2(Type)", "System.C.M1()", "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task ConversionOperation()
        {
            var ConversionOperation = $$"""
            namespace System
            {
                class ConvertsToType
                {
                    public static implicit operator Type(ConvertsToType value) => typeof(ConvertsToType);
                }

                class C : TestSystemTypeBase
                {
                    public static void Main()
                    {
                        new C().M1();
                    }

                    private void M1()
                    {
                        M2(new ConvertsToType());
                    }

                    private static void M2(
                        [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(
                            System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicMethods)] Type type)
                    {
                    }
                }
            }
            """;

            return VerifyDynamicallyAccessedMembersAnalyzer(string.Concat(GetSystemTypeBase(), ConversionOperation), consoleApplication: false,
                // (203,13): warning IL2072: 'type' argument does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' in call to 'System.C.M2(Type)'. The return value of method 'System.ConvertsToType.implicit operator Type(ConvertsToType)' does not have matching annotations. The source value must declare at least the same requirements as those declared on the target location it is assigned to.
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchMethodReturnTypeTargetsParameter)
                .WithSpan(203, 13, 203, 37)
                .WithSpan(191, 9, 191, 94)
                .WithArguments("type", "System.C.M2(Type)", "System.ConvertsToType.implicit operator Type(ConvertsToType)", "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task ConversionOperationAnnotationDoesNotMatch()
        {
            var AnnotatedConversionOperation = $$"""
            namespace System
            {
                class ConvertsToType
                {
                    [return: System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(
                        System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicFields)]
                    public static implicit operator Type(ConvertsToType value) => null;
                }

                class C : TestSystemTypeBase
                {
                    public static void Main()
                    {
                        new C().M1();
                    }

                    private void M1()
                    {
                        M2(new ConvertsToType());
                    }

                    private static void M2(
                        [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(
                            System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicMethods)] Type type)
                    {
                    }
                }
            }
            """;

            return VerifyDynamicallyAccessedMembersAnalyzer(string.Concat(GetSystemTypeBase(), AnnotatedConversionOperation), consoleApplication: false,
                // (205,13): warning IL2072: 'type' argument does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' in call to 'System.C.M2(Type)'. The return value of method 'System.ConvertsToType.implicit operator Type(ConvertsToType)' does not have matching annotations. The source value must declare at least the same requirements as those declared on the target location it is assigned to.
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchMethodReturnTypeTargetsParameter)
                .WithSpan(205, 13, 205, 37)
                .WithArguments("type", "System.C.M2(Type)", "System.ConvertsToType.implicit operator Type(ConvertsToType)", "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task ConversionOperationAnnotationMatches()
        {
            var AnnotatedConversionOperation = $$"""
            namespace System
            {
                class ConvertsToType
                {
                    [return: System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(
                        System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicMethods)]
                    public static implicit operator Type(ConvertsToType value) => null;
                }

                class C : TestSystemTypeBase
                {
                    public static void Main()
                    {
                        new C().M1();
                    }

                    private void M1()
                    {
                        M2(new ConvertsToType());
                    }

                    private static void M2(
                        [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(
                            System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicMethods)] Type type)
                    {
                    }
                }
            }
            """;

            return VerifyDynamicallyAccessedMembersAnalyzer(string.Concat(GetSystemTypeBase(), AnnotatedConversionOperation), consoleApplication: false);
        }


        [Fact]
        public Task SourceMethodDoesNotMatchTargetMethodReturnTypeAnnotations()
        {
            var TargetMethodReturnTypeWithAnnotations = $$"""
            namespace System
            {
                class C : TestSystemTypeBase
                {
                    public static void Main()
                    {
                        new C().M();
                    }

                    [return: System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(
                            System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicMethods)]
                    private Type M()
                    {
                        return this;
                    }
                }
            }
            """;

            // (200,20): warning IL2083: 'System.C.M()' method return value does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' requirements.
            // The implicit 'this' argument of method 'System.C.M()' does not have matching annotations.
            // The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(string.Concat(GetSystemTypeBase(), TargetMethodReturnTypeWithAnnotations), consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchThisParameterTargetsMethodReturnType)
                .WithSpan(200, 20, 200, 24)
                .WithSpan(196, 9, 201, 10)
                .WithArguments("System.C.M()", "System.C.M()", "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task SourceMethodDoesNotMatchTargetFieldAnnotations()
        {
            var TargetFieldWithAnnotations = $$"""
            namespace System
            {
                class C : TestSystemTypeBase
                {
                    public static void Main()
                    {
                        new C().M();
                    }

                    private void M()
                    {
                        f = this;
                    }

                    [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(
                            System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicMethods)]
                    private static Type f;
                }
            }
            """;

            // (198,13): warning IL2084: value stored in field 'System.C.f' does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' requirements.
            // The implicit 'this' argument of method 'System.C.M()' does not have matching annotations.
            // The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(string.Concat(GetSystemTypeBase(), TargetFieldWithAnnotations), consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchThisParameterTargetsField)
                .WithSpan(198, 13, 198, 21)
                .WithSpan(196, 9, 199, 10)
                .WithArguments("System.C.f",
                    "System.C.M()",
                    "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task SourceMethodDoesNotMatchTargetMethodAnnotations()
        {
            var TargetMethodWithAnnotations = $$"""
            namespace System
            {
                class C : TestSystemTypeBase
                {
                    public static void Main()
                    {
                        new C().M();
                    }

                    private void M()
                    {
                        this.GetMethods();
                    }
                }
            }
            """;

            // (198,13): warning IL2085: 'this' argument does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' in call to 'System.Type.GetMethods()'.
            // The implicit 'this' argument of method 'System.C.M()' does not have matching annotations.
            // The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(string.Concat(GetSystemTypeBase(), TargetMethodWithAnnotations), consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchThisParameterTargetsThisParameter)
                .WithSpan(198, 13, 198, 30)
                .WithSpan(196, 9, 199, 10)
                .WithArguments("System.Type.GetMethods()", "System.C.M()", "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }
        #endregion

        [Fact]
        public Task SourceGenericParameterDoesNotMatchTargetParameterAnnotations()
        {
            var TargetParameterWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            class C
            {
                public static void Main()
                {
                    M2<int>();
                }

                private static void M1(
                    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)] Type type)
                {
                }

                private static void M2<T>()
                {
                    M1(typeof(T));
                }
            }
            """;

            // (18,3): warning IL2087: 'type' argument does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' in call to 'C.M1(Type)'.
            // The generic parameter 'T' of 'C.M2<T>()' does not have matching annotations.
            // The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetParameterWithAnnotations, consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchTypeArgumentTargetsParameter)
                .WithSpan(18, 9, 18, 22)
                .WithSpan(16, 28, 16, 29)
                .WithArguments("type", "C.M1(Type)", "T", "C.M2<T>()", "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task SourceGenericParameterDoesNotMatchTargetMethodReturnTypeAnnotations()
        {
            var TargetMethodReturnTypeWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            class C
            {
                public static void Main()
                {
                    M<int>();
                }

                [return: DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
                private static Type M<T>()
                {
                    return typeof(T);
                }
            }
            """;

            // (14,10): warning IL2088: 'C.M<T>()' method return value does not satisfy 'DynamicallyAccessedMemberTypes.PublicConstructors' requirements.
            // The generic parameter 'T' of 'C.M<T>()' does not have matching annotations.
            // The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetMethodReturnTypeWithAnnotations, consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchTypeArgumentTargetsMethodReturnType)
                .WithSpan(14, 16, 14, 25)
                .WithSpan(12, 27, 12, 28)
                .WithArguments("C.M<T>()", "T", "C.M<T>()", "'DynamicallyAccessedMemberTypes.PublicConstructors'"));
        }

        [Fact]
        public Task SourceGenericParameterDoesNotMatchTargetFieldAnnotations()
        {
            var TargetFieldWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            class C
            {
                public static void Main()
                {
                    M<int>();
                }

                [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)]
                private static Type f;

                private static void M<T>()
                {
                    f = typeof(T);
                }
            }
            """;

            // (16,3): warning IL2089: value stored in field 'C.f' does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' requirements.
            // The generic parameter 'T' of 'C.M<T>()' does not have matching annotations.
            // The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetFieldWithAnnotations, consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchTypeArgumentTargetsField)
                .WithSpan(16, 9, 16, 22)
                .WithSpan(14, 27, 14, 28)
                .WithArguments("C.f",
                    "T",
                    "C.M<T>()",
                    "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task SourceGenericParameterDoesNotMatchTargetGenericParameterAnnotations()
        {
            var TargetGenericParameterWithAnnotations = $$"""
            using System.Diagnostics.CodeAnalysis;

            class C
            {
                public static void Main()
                {
                    M2<int>();
                }

                private static void M1<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)] T>()
                {
                }

                private static void M2<S>()
                {
                    M1<S>();
                }
            }
            """;

            // (16,3): warning IL2091: 'T' generic argument does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods'
            // in 'C.M1<T>()'. The generic parameter 'S' of 'C.M2<S>()' does not have matching annotations.
            // The source value must declare at least the same requirements as those declared on the target location it is assigned to.
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetGenericParameterWithAnnotations, consoleApplication: false,
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchTypeArgumentTargetsGenericParameter)
                .WithSpan(16, 9, 16, 16)
                .WithSpan(14, 28, 14, 29)
                .WithArguments("T", "C.M1<T>()", "S", "C.M2<S>()", "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task SourceTypeofFlowsIntoTargetParameterAnnotations()
        {
            var TargetParameterWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            public class Foo
            {
            }

            class C
            {
                public static void Main()
                {
                    M(typeof(Foo));
                }

                private static void M([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)] Type type)
                {
                }
            }
            """;
            return VerifyDynamicallyAccessedMembersAnalyzer(TargetParameterWithAnnotations, consoleApplication: false);
        }

        [Fact]
        public Task SourceTypeofFlowsIntoTargetMethodReturnTypeAnnotation()
        {
            var TargetMethodReturnTypeWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            public class Foo
            {
            }

            class C
            {
                public static void Main()
                {
                    M();
                }

                [return: DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)]
                private static Type M()
                {
                    return typeof(Foo);
                }
            }
            """;

            return VerifyDynamicallyAccessedMembersAnalyzer(TargetMethodReturnTypeWithAnnotations, consoleApplication: false);
        }

        [Fact]
        public Task SourceParameterFlowsInfoTargetMethodReturnTypeAnnotations()
        {
            var TargetMethodReturnTypeWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            public class Foo
            {
            }

            class C
            {
                public static void Main()
                {
                    M(typeof(Foo));
                }

                [return: DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)]
                private static Type M([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)] Type type)
                {
                    return type;
                }
            }
            """;

            return VerifyDynamicallyAccessedMembersAnalyzer(TargetMethodReturnTypeWithAnnotations, consoleApplication: false);
        }

        [Fact]
        public Task SourceParameterFlowsIntoTargetFieldAnnotations()
        {
            var TargetFieldWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            public class Foo
            {
            }

            class C
            {
                public static void Main()
                {
                    M(typeof(Foo));
                }

                private static void M([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)] Type type)
                {
                    f = type;
                }

                [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)]
                private static Type f  = typeof(Foo);
            }
            """;

            return VerifyDynamicallyAccessedMembersAnalyzer(TargetFieldWithAnnotations, consoleApplication: false);
        }

        [Fact]
        public Task SourceParameterFlowsIntoTargetMethodAnnotations()
        {
            var TargetMethodWithAnnotations = $$"""
            using System;
            using System.Diagnostics.CodeAnalysis;

            public class Foo
            {
            }

            class C
            {
                public static void Main()
                {
                    M(typeof(Foo));
                }

                private static void M([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)] Type type)
                {
                    type.GetMethod("Bar");
                }
            }
            """;

            return VerifyDynamicallyAccessedMembersAnalyzer(TargetMethodWithAnnotations, consoleApplication: false);
        }

        [Fact]
        public Task MethodArgumentIsInvalidOperation()
        {
            var Source = """
            using System;
            using System.Diagnostics.CodeAnalysis;

            class C
            {
                public static void Main()
                {
                    RequireAll(type);
                }

                static void RequireAll([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] Type t) {}
            }
            """;

            return VerifyDynamicallyAccessedMembersAnalyzer(Source, consoleApplication: false,
                // (8,20): error CS0103: The name 'type' does not exist in the current context
                DiagnosticResult.CompilerError("CS0103").WithSpan(8, 20, 8, 24).WithArguments("type"));
        }

        [Fact]
        public Task MethodReturnIsInvalidOperation()
        {
            var Source = """
            using System;
            using System.Diagnostics.CodeAnalysis;

            class C
            {
                public static void Main()
                {
                    GetTypeWithAll();
                }

                [return: DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)]
                static Type GetTypeWithAll() => type;
            }
            """;

            return VerifyDynamicallyAccessedMembersAnalyzer(Source, consoleApplication: false,
                // (12,37): error CS0103: The name 'type' does not exist in the current context
                DiagnosticResult.CompilerError("CS0103").WithSpan(12, 37, 12, 41).WithArguments("type"),
                // (12,37): warning IL2063: Value returned from method 'C.GetTypeWithAll()' can not be statically determined and may not meet 'DynamicallyAccessedMembersAttribute' requirements.
                VerifyCS.Diagnostic(DiagnosticId.MethodReturnValueCannotBeStaticallyDetermined).WithSpan(12, 37, 12, 41).WithArguments("C.GetTypeWithAll()"));
        }

        [Fact]
        public Task AssignmentSourceIsInvalidOperation()
        {
            var Source = """
            using System;
            using System.Diagnostics.CodeAnalysis;

            class C
            {
                public static void Main()
                {
                    fieldRequiresAll = type;
                }

                [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)]
                static Type fieldRequiresAll;
            }
            """;

            return VerifyDynamicallyAccessedMembersAnalyzer(Source, consoleApplication: false,
                // (8,28): error CS0103: The name 'type' does not exist in the current context
                DiagnosticResult.CompilerError("CS0103").WithSpan(8, 28, 8, 32).WithArguments("type"),
                // (8,9): warning IL2064: Value assigned to C.fieldRequiresAll can not be statically determined and may not meet 'DynamicallyAccessedMembersAttribute' requirements.
                VerifyCS.Diagnostic(DiagnosticId.FieldValueCannotBeStaticallyDetermined).WithSpan(8, 9, 8, 32).WithArguments("C.fieldRequiresAll"));
        }

        [Fact]
        public Task AssignmentTargetIsInvalidOperation()
        {
            var Source = """
            using System;
            using System.Diagnostics.CodeAnalysis;

            class C
            {
                public static void Main()
                {
                    type = GetTypeWithAll();
                }

                [return: DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)]
                static Type GetTypeWithAll() => null;
            }
            """;

            return VerifyDynamicallyAccessedMembersAnalyzer(Source, consoleApplication: false,
                // (8,9): error CS0103: The name 'type' does not exist in the current context
                DiagnosticResult.CompilerError("CS0103").WithSpan(8, 9, 8, 13).WithArguments("type"));
        }

        [Fact]
        public Task AssignmentTargetIsCapturedInvalidOperation()
        {
            var Source = """
            using System;
            using System.Diagnostics.CodeAnalysis;

            class C
            {
                public static void Main()
                {
                    type ??= GetTypeWithAll();
                }

                [return: DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)]
                static Type GetTypeWithAll() => null;
            }
            """;

            return VerifyDynamicallyAccessedMembersAnalyzer(Source, consoleApplication: false,
                // (8,9): error CS0103: The name 'type' does not exist in the current context
                DiagnosticResult.CompilerError("CS0103").WithSpan(8, 9, 8, 13).WithArguments("type"));
        }

        [Fact]
        public Task AssignmentTargetHasNestedInvalidOperation()
        {
            // The assignment target is an IBinaryOperation whose right-hand side is an IInvalidOperation.
            var Source = $$"""
                int a, b = 0;
                a + = 3;
            """;

            return VerifyDynamicallyAccessedMembersAnalyzer(Source, consoleApplication: true,
                // (2,9): error CS1525: Invalid expression term '='
                DiagnosticResult.CompilerError("CS1525").WithSpan(2, 9, 2, 10).WithArguments("="),
                // (2,5): error CS0165: Use of unassigned local variable 'a'
                DiagnosticResult.CompilerError("CS0165").WithSpan(2, 5, 2, 6).WithArguments("a"),
                // (1,12): warning CS0219: The variable 'b' is assigned but its value is never used
                DiagnosticResult.CompilerWarning("CS0219").WithSpan(1, 12, 1, 13).WithArguments("b")
            );
        }

        [Fact]
        public Task CRefGenericParameterAnalysis()
        {
            var Source = """
            using System.Diagnostics.CodeAnalysis;

            class C<TOuter>
            {
                /// <summary>
                /// <remarks>
                /// <see cref="CRequires{TOuter}.IsIt"/>
                /// </remarks>
                /// </summary>
                static CRequires<TOuter> Value => new CRequires<TOuter>);
            }

            class CRequires<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)] TInner> { public static bool IsIt => false; }
            """;

            // The actual usage (ctor call) should warn, about missing annotation, but the cref should not.
            return VerifyDynamicallyAccessedMembersAnalyzer(Source, consoleApplication: false,
                // (10,60): error CS1526: A new expression requires an argument list or (), [], or {} after type
                DiagnosticResult.CompilerError("CS1526").WithSpan(10, 60, 10, 61),
                // (10,60): error CS1002: ; expected
                DiagnosticResult.CompilerError("CS1002").WithSpan(10, 60, 10, 61),
                // (10,60): error CS1519: Invalid token ')' in a member declaration
                DiagnosticResult.CompilerError("CS1519").WithSpan(10, 60, 10, 61).WithArguments(")"),
                // (10,39): warning IL2091: 'TInner' generic argument does not satisfy 'DynamicallyAccessedMemberTypes.PublicMethods' in 'CRequires<TInner>'. The generic parameter 'TOuter' of 'C<TOuter>' does not have matching annotations. The source value must declare at least the same requirements as those declared on the target location it is assigned to.
                VerifyCS.Diagnostic(DiagnosticId.DynamicallyAccessedMembersMismatchTypeArgumentTargetsGenericParameter).WithSpan(10, 39, 10, 60).WithSpan(3, 9, 3, 15).WithArguments("TInner", "CRequires<TInner>", "TOuter", "C<TOuter>", "'DynamicallyAccessedMemberTypes.PublicMethods'"));
        }

        [Fact]
        public Task MethodParameterWithoutLocationAnalysis()
        {
            // The implicit main method has parameters
            var Source = """
            using System;
            foreach (var arg in args)
                Console.WriteLine(arg);
            """;

            return VerifyDynamicallyAccessedMembersAnalyzer(Source, consoleApplication: true);
        }
    }
}
