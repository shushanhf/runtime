// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using Microsoft.DotNet.Cli.Build;
using Microsoft.DotNet.Cli.Build.Framework;
using Microsoft.DotNet.CoreSetup.Test;
using Microsoft.DotNet.TestUtils;
using Xunit;

namespace HostActivation.Tests
{
    public class SDKLookup : IClassFixture<SDKLookup.SharedTestState>
    {
        private SharedTestState SharedState { get; }

        private readonly DotNetCli ExecutableDotNet;
        private readonly DotNetBuilder ExecutableDotNetBuilder;

        public SDKLookup(SharedTestState sharedState)
        {
            SharedState = sharedState;

            string exeDotNetPath = sharedState.BaseArtifact.GetUniqueSubdirectory("exe");
            ExecutableDotNetBuilder = new DotNetBuilder(exeDotNetPath, TestContext.BuiltDotNet.BinPath, null);
            ExecutableDotNet = ExecutableDotNetBuilder
                .AddMicrosoftNETCoreAppFrameworkMockHostPolicy("9999.0.0")
                .Build();

            // Note: no need to delete the directory, it will be removed once the entire class is done
            //       since everything is under the BaseArtifact from the shared state
        }

        [Fact]
        public void GlobalJson_SingleDigitPatch()
        {
            // Set specified SDK version = 9999.3.4-global-dummy
            string requestedVersion = "9999.3.4-global-dummy";
            string globalJsonPath = GlobalJson.CreateWithVersion(SharedState.CurrentWorkingDir, requestedVersion);

            // Specified SDK version: 9999.3.4-global-dummy
            // Exe: empty
            // Expected: no compatible version, no SDKs found
            RunTest()
                .Should().Fail()
                .And.NotFindCompatibleSdk(globalJsonPath, requestedVersion)
                .And.FindAnySdk(false)
                .And.HaveStdErrContaining("aka.ms/dotnet/download")
                .And.NotHaveStdErrContaining("Checking if resolved SDK dir");

            // Add SDK versions
            AddAvailableSdkVersions("9999.4.1", "9999.3.4-dummy");

            // Specified SDK version: 9999.3.4-global-dummy
            // Exe: 9999.4.1, 9999.3.4-dummy
            // Expected: no compatible version
            RunTest()
                .Should().Fail()
                .And.NotFindCompatibleSdk(globalJsonPath, requestedVersion)
                .And.FindAnySdk(true);

            // Add SDK versions
            AddAvailableSdkVersions("9999.3.3");

            // Specified SDK version: 9999.3.4-global-dummy
            // Exe: 9999.4.1, 9999.3.4-dummy, 9999.3.3
            // Expected: no compatible version
            RunTest()
                .Should().Fail()
                .And.NotFindCompatibleSdk(globalJsonPath, requestedVersion)
                .And.FindAnySdk(true);

            // Add SDK versions
            AddAvailableSdkVersions("9999.3.4");

            // Specified SDK version: 9999.3.4-global-dummy
            // Exe: 9999.4.1, 9999.3.4-dummy, 9999.3.3, 9999.3.4
            // Expected: 9999.3.4 from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.3.4"));

            // Add SDK versions
            AddAvailableSdkVersions("9999.3.5-dummy");

            // Specified SDK version: 9999.3.4-global-dummy
            // Exe: 9999.4.1, 9999.3.4-dummy, 9999.3.3, 9999.3.4, 9999.3.5-dummy
            // Expected: 9999.3.5-dummy from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.3.5-dummy"));

            // Add SDK versions
            AddAvailableSdkVersions("9999.3.600");

            // Add empty SDK version that is an exact match - should not be used
            Directory.CreateDirectory(Path.Combine(ExecutableDotNet.BinPath, "sdk", "9999.3.4-global-dummy"));

            // Specified SDK version: 9999.3.4-global-dummy
            // Exe: 9999.4.1, 9999.3.4-dummy, 9999.3.3, 9999.3.4, 9999.3.5-dummy, 9999.3.600, 9999.3.4-global.dummy (empty)
            // Expected: 9999.3.5-dummy from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.3.5-dummy"))
                .And.HaveStdErrContaining("Ignoring version [9999.3.4-global-dummy] without dotnet.dll");

            // Add SDK versions
            AddAvailableSdkVersions("9999.3.4-global-dummy");

            // Specified SDK version: 9999.3.4-global-dummy
            // Exe: 9999.4.1, 9999.3.4-dummy, 9999.3.3, 9999.3.4, 9999.3.5-dummy, 9999.3.600, 9999.3.4-global-dummy
            // Expected: 9999.3.4-global-dummy from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.3.4-global-dummy"));

            // Verify we have the expected SDK versions
            RunTest("--list-sdks")
                .Should().Pass()
                .And.HaveStdOutContaining("9999.3.4-dummy")
                .And.HaveStdOutContaining("9999.3.4-global-dummy")
                .And.HaveStdOutContaining("9999.4.1")
                .And.HaveStdOutContaining("9999.3.3")
                .And.HaveStdOutContaining("9999.3.4")
                .And.HaveStdOutContaining("9999.3.600")
                .And.HaveStdOutContaining("9999.3.5-dummy");
        }

        [Fact]
        public void GlobalJson_TwoPartPatch()
        {
            // Set specified SDK version = 9999.3.304-global-dummy
            string requestedVersion = "9999.3.304-global-dummy";
            string globalJsonPath = GlobalJson.CreateWithVersion(SharedState.CurrentWorkingDir, requestedVersion);

            // Specified SDK version: 9999.3.304-global-dummy
            // Exe: empty
            // Expected: no compatible version, no SDKs found
            RunTest()
                .Should().Fail()
                .And.NotFindCompatibleSdk(globalJsonPath, requestedVersion)
                .And.FindAnySdk(false);

            // Add SDK versions
            AddAvailableSdkVersions("9999.3.57", "9999.3.4-dummy");

            // Specified SDK version: 9999.3.304-global-dummy
            // Exe: 9999.3.57, 9999.3.4-dummy
            // Expected: no compatible version
            RunTest()
                .Should().Fail()
                .And.NotFindCompatibleSdk(globalJsonPath, requestedVersion)
                .And.FindAnySdk(true);

            // Add SDK versions
            AddAvailableSdkVersions("9999.3.300", "9999.7.304-global-dummy");

            // Specified SDK version: 9999.3.304-global-dummy
            // Exe: 9999.3.57, 9999.3.4-dummy, 9999.3.300, 9999.7.304-global-dummy
            // Expected: no compatible version
            RunTest()
                .Should().Fail()
                .And.NotFindCompatibleSdk(globalJsonPath, requestedVersion)
                .And.FindAnySdk(true);

            // Add SDK versions
            AddAvailableSdkVersions("9999.3.304");

            // Specified SDK version: 9999.3.304-global-dummy
            // Exe: 99999.3.57, 9999.3.4-dummy, 9999.3.300, 9999.7.304-global-dummy, 9999.3.304
            // Expected: 9999.3.304 from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.3.304"));

            // Add SDK versions
            AddAvailableSdkVersions("9999.3.399", "9999.3.399-dummy", "9999.3.400");

            // Specified SDK version: 9999.3.304-global-dummy
            // Exe: 9999.3.57, 9999.3.4-dummy, 9999.3.300, 9999.7.304-global-dummy, 9999.3.304, 9999.3.399, 9999.3.399-dummy, 9999.3.400
            // Expected: 9999.3.399 from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.3.399"));

            // Add SDK versions
            AddAvailableSdkVersions("9999.3.2400", "9999.3.3004");

            // Specified SDK version: 9999.3.304-global-dummy
            // Exe: 9999.3.57, 9999.3.4-dummy, 9999.3.300, 9999.7.304-global-dummy, 9999.3.304, 9999.3.399, 9999.3.399-dummy, 9999.3.400, 9999.3.2400, 9999.3.3004
            // Expected: 9999.3.399 from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.3.399"));

            // Add SDK versions
            AddAvailableSdkVersions("9999.3.304-global-dummy");

            // Specified SDK version: 9999.3.304-global-dummy
            // Exe: 9999.3.57, 9999.3.4-dummy, 9999.3.300, 9999.7.304-global-dummy, 9999.3.304, 9999.3.399, 9999.3.399-dummy, 9999.3.400, 9999.3.2400, 9999.3.3004, 9999.3.304-global-dummy
            // Expected: 9999.3.304-global-dummy from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.3.304-global-dummy"));

            // Verify we have the expected SDK versions
            RunTest("--list-sdks")
                .Should().Pass()
                .And.HaveStdOutContaining("9999.3.57")
                .And.HaveStdOutContaining("9999.3.4-dummy")
                .And.HaveStdOutContaining("9999.3.300")
                .And.HaveStdOutContaining("9999.7.304-global-dummy")
                .And.HaveStdOutContaining("9999.3.399")
                .And.HaveStdOutContaining("9999.3.399-dummy")
                .And.HaveStdOutContaining("9999.3.400")
                .And.HaveStdOutContaining("9999.3.2400")
                .And.HaveStdOutContaining("9999.3.3004")
                .And.HaveStdOutContaining("9999.3.304")
                .And.HaveStdOutContaining("9999.3.304-global-dummy");
        }

        [Fact]
        public void NegativeVersion()
        {
            GlobalJson.CreateEmpty(SharedState.CurrentWorkingDir);

            // Add a negative SDK version
            AddAvailableSdkVersions("-1.-1.-1");

            // Specified SDK version: none
            // Exe: -1.-1.-1
            // Expected: no compatible version, no SDKs found
            RunTest()
                .Should().Fail()
                .And.FindAnySdk(false);

            // Add SDK versions
            AddAvailableSdkVersions("9999.0.4");

            // Specified SDK version: none
            // Exe: -1.-1.-1, 9999.0.4
            // Expected: 9999.0.4 from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.0.4"));

            // Verify we have the expected SDK versions
            RunTest("--list-sdks")
                .Should().Pass()
                .And.HaveStdOutContaining("9999.0.4");
        }

        [Fact]
        public void PickHighestSemanticVersion()
        {
            GlobalJson.CreateEmpty(SharedState.CurrentWorkingDir);

            // Add SDK versions
            AddAvailableSdkVersions("9999.0.0", "9999.0.3-dummy.9", "9999.0.3-dummy.10");

            // Specified SDK version: none
            // Cwd: 10000.0.0                 --> should not be picked
            // Exe: 9999.0.0, 9999.0.3-dummy.9, 9999.0.3-dummy.10
            // Expected: 9999.0.3-dummy.10 from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.0.3-dummy.10"));

            // Add SDK versions
            AddAvailableSdkVersions("9999.0.3");

            // Specified SDK version: none
            // Cwd: 10000.0.0                 --> should not be picked
            // Exe: 9999.0.0, 9999.0.3-dummy.9, 9999.0.3-dummy.10, 9999.0.3
            // Expected: 9999.0.3 from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.0.3"));

            // Add SDK versions
            AddAvailableSdkVersions("9999.0.100");

            // Specified SDK version: none
            // Cwd: 10000.0.0                 --> should not be picked
            // Exe: 9999.0.0, 9999.0.3-dummy.9, 9999.0.3-dummy.10, 9999.0.3, 9999.0.100
            // Expected: 9999.0.100 from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.0.100"));

            // Add SDK versions
            AddAvailableSdkVersions("9999.0.80");

            // Specified SDK version: none
            // Cwd: 10000.0.0                 --> should not be picked
            // Exe: 9999.0.0, 9999.0.3-dummy.9, 9999.0.3-dummy.10, 9999.0.3, 9999.0.100, 9999.0.80
            // Expected: 9999.0.100 from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.0.100"));

            // Add SDK versions
            AddAvailableSdkVersions("9999.0.5500000");

            // Specified SDK version: none
            // Cwd: 10000.0.0                 --> should not be picked
            // Exe: 9999.0.0, 9999.0.3-dummy.9, 9999.0.3-dummy.10, 9999.0.3, 9999.0.100, 9999.0.80, 9999.0.5500000
            // Expected: 9999.0.5500000 from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.0.5500000"));

            // Add SDK versions
            AddAvailableSdkVersions("9999.0.52000000");

            // Add empty SDK version that is higher than any available version - should not be used
            Directory.CreateDirectory(Path.Combine(ExecutableDotNet.BinPath, "sdk", "9999.1.0"));

            // Specified SDK version: none
            // Cwd: 10000.0.0                 --> should not be picked
            // Exe: 9999.0.0, 9999.0.3-dummy.9, 9999.0.3-dummy.10, 9999.0.3, 9999.0.100, 9999.0.80, 9999.0.5500000, 9999.0.52000000
            // Expected: 9999.0.52000000 from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.0.52000000"))
                .And.HaveStdErrContaining("Ignoring version [9999.1.0] without dotnet.dll");

            // Verify we have the expected SDK versions
            RunTest("--list-sdks")
                .Should().Pass()
                .And.HaveStdOutContaining("9999.0.0")
                .And.HaveStdOutContaining("9999.0.3-dummy.9")
                .And.HaveStdOutContaining("9999.0.3-dummy.10")
                .And.HaveStdOutContaining("9999.0.3")
                .And.HaveStdOutContaining("9999.0.100")
                .And.HaveStdOutContaining("9999.0.80")
                .And.HaveStdOutContaining("9999.0.5500000")
                .And.HaveStdOutContaining("9999.0.52000000")
                .And.NotHaveStdOutContaining("9999.1.0");
        }

        [Theory]
        [InlineData("diSABle")]
        [InlineData("PaTCh")]
        [InlineData("FeaturE")]
        [InlineData("MINOR")]
        [InlineData("maJor")]
        [InlineData("LatestPatch")]
        [InlineData("Latestfeature")]
        [InlineData("latestMINOR")]
        [InlineData("latESTMajor")]
        public void RollForwardPolicy_CaseInsensitive(string rollForward)
        {
            const string Requested = "9999.0.100";
            AddAvailableSdkVersions(Requested);

            GlobalJson.CreateWithVersionSettings(SharedState.CurrentWorkingDir, policy: rollForward, version: Requested);

            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput(Requested));
        }

        [Theory]
        [MemberData(nameof(InvalidGlobalJsonData))]
        public void InvalidGlobalJson_FallsBackToLatestSdk(string globalJsonContents, string[] messages)
        {
            AddAvailableSdkVersions("9999.0.100", "9999.0.300-dummy.9", "9999.1.402");

            GlobalJson.Write(SharedState.CurrentWorkingDir, globalJsonContents);

            var expectation = RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.1.402"));

            foreach (var message in messages)
            {
                expectation = expectation.And.HaveStdErrContaining(message);
            }
        }

        [Theory]
        [MemberData(nameof(SdkRollForwardData))]
        public void RollForward(string policy, string requested, bool allowPrerelease, string expected, string[] installed)
        {
            AddAvailableSdkVersions(installed);

            string globalJson = GlobalJson.CreateWithVersionSettings(SharedState.CurrentWorkingDir, policy: policy, version: requested, allowPrerelease: allowPrerelease);

            var result = RunTest();
            if (expected == null)
            {
                result
                    .Should().Fail()
                    .And.NotFindCompatibleSdk(globalJson, requested);
            }
            else
            {
                result
                    .Should().Pass()
                    .And.HaveStdErrContaining($"SDK path resolved to [{Path.Combine(ExecutableDotNet.BinPath, "sdk", expected)}]");
            }
        }

        [Fact]
        public void AllowPrereleaseFalse_UseLatestRelease()
        {
            var installed = new string[] {
                    "9999.1.702",
                    "9999.2.101",
                    "9999.2.203",
                    "9999.2.204-preview1",
                    "10000.0.100-preview3",
                    "10000.0.100-preview7",
                    "10000.0.100",
                    "10000.1.102",
                    "10000.1.106",
                    "10000.0.200-preview5",
                    "10000.1.100-preview3",
                    "10001.0.100-preview3",
                };

            const string ExpectedVersion = "10000.1.106";

            AddAvailableSdkVersions(installed);

            GlobalJson.CreateWithVersionSettings(SharedState.CurrentWorkingDir, allowPrerelease: false);

            var result = RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining($"SDK path resolved to [{Path.Combine(ExecutableDotNet.BinPath, "sdk", ExpectedVersion)}]");
        }

        [Fact]
        public void GlobalJson_Paths()
        {
            GlobalJson.Sdk sdk = new() { Paths = [] };
            string globalJsonPath = GlobalJson.Write(SharedState.CurrentWorkingDir, sdk );

            // Add SDK versions
            AddAvailableSdkVersions("9999.0.4");

            // Paths: none
            // Exe: 9999.0.4
            // Expected: no SDKs found
            RunTest()
                .Should().Fail()
                .And.FindAnySdk(false)
                .And.HaveStdErrContaining($"Empty search paths specified in global.json file: {globalJsonPath}");

            sdk.Paths = [ GlobalJson.HostSdkPath ];
            globalJsonPath = GlobalJson.Write(SharedState.CurrentWorkingDir, sdk);

            // Paths: $host$
            // Exe: 9999.0.4
            // Expected: 9999.0.4 from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.0.4"));

            using TestArtifact custom = TestArtifact.Create("sdkPath");
            AddSdkToCustomPath(custom.Location, "9999.0.4");
            sdk.Paths = [ custom.Location ];
            globalJsonPath = GlobalJson.Write(SharedState.CurrentWorkingDir, sdk);

            // Paths: custom (absolute)
            // Custom: 9999.0.4
            // Exe: 9999.0.4
            // Expected: 9999.0.4 from custom dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.0.4", custom.Location));

            string relativePath = Path.GetRelativePath(SharedState.CurrentWorkingDir, custom.Location);
            sdk.Paths = [ relativePath ];
            GlobalJson.Write(SharedState.CurrentWorkingDir, sdk);

            // Paths: custom (relative, outside current directory)
            // Custom: 9999.0.4
            // Exe: 9999.0.4
            // Expected: 9999.0.4 from custom dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.0.4", custom.Location));

            string underCurrent = SharedState.CurrentWorkingDirArtifact.GetUniqueSubdirectory("sdkPath");
            AddSdkToCustomPath(underCurrent, "9999.0.4");

            relativePath = Path.GetRelativePath(SharedState.CurrentWorkingDir, underCurrent);
            sdk.Paths = [relativePath];
            GlobalJson.Write(SharedState.CurrentWorkingDir, sdk);

            // Paths: custom (relative, under current directory)
            // Custom: 9999.0.4
            // Exe: 9999.0.4
            // Expected: 9999.0.4 from custom dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.0.4", Path.Combine(SharedState.CurrentWorkingDir, relativePath)));
        }

        [Fact]
        public void GlobalJson_Paths_Multiple()
        {
            using TestArtifact custom = TestArtifact.Create("sdkPath");
            AddSdkToCustomPath(custom.Location, "9999.0.0");

            GlobalJson.Sdk sdk = new() { Paths = [ custom.Location, GlobalJson.HostSdkPath ] };
            GlobalJson.Write(SharedState.CurrentWorkingDir, sdk);

            // Add SDK versions
            AddAvailableSdkVersions("9999.0.4");

            // Specified SDK
            //   version: none
            //   paths: custom, $host$
            // Custom: 9999.0.0
            // Exe: 9999.0.4
            // Expected: 9999.0.0 from custom dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.0.0", custom.Location));

            sdk.Version = "9999.0.3";
            GlobalJson.Write(SharedState.CurrentWorkingDir, sdk);

            // Specified SDK
            //   version: 9999.0.3
            //   paths: custom, $host$
            // Custom: 9999.0.0
            // Exe: 9999.0.4
            // Expected: 9999.0.4 from exe dir
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.0.4"));

            sdk.Version = "9999.0.5";
            string globalJsonPath = GlobalJson.Write(SharedState.CurrentWorkingDir, sdk);

            // Specified SDK
            //   version: 9999.0.5
            //   paths: custom, $host$
            // Custom: 9999.0.0
            // Exe: 9999.0.4
            // Expected: no compatible version
            RunTest()
                .Should().Fail()
                .And.NotFindCompatibleSdk(globalJsonPath, sdk.Version)
                .And.FindAnySdk(true);

            // Verify we have the expected SDK versions
            RunTest("--list-sdks")
                .Should().Pass()
                .And.HaveStdOutContaining($"9999.0.0 [{custom.Location}")
                .And.HaveStdOutContaining($"9999.0.4 [{ExecutableDotNet.BinPath}");
        }

        [Fact]
        public void GlobalJson_Paths_FirstMatch()
        {
            using TestArtifact custom1 = TestArtifact.Create("sdkPath1");
            AddSdkToCustomPath(custom1.Location, "9999.0.0");
            using TestArtifact custom2 = TestArtifact.Create("sdkPath2");
            AddSdkToCustomPath(custom2.Location, "9999.0.2");
            AddAvailableSdkVersions("9999.0.1");

            GlobalJson.Sdk sdk = new() { Version = "9999.0.1", Paths = [ custom1.Location, custom2.Location, GlobalJson.HostSdkPath ] };
            GlobalJson.Write(SharedState.CurrentWorkingDir, sdk);

            // Specified SDK
            //   version: none
            //   paths: custom1, custom2, $host$
            // Custom1: 9999.0.0
            // Custom2: 9999.0.2
            // Exe: 9999.0.1
            // Expected: 9999.0.2 from custom2 - first match is used, not best match (which would be exe which is an exact match)
            RunTest()
                .Should().Pass()
                .And.HaveStdErrContaining(ExpectedResolvedSdkOutput("9999.0.2", custom2.Location));

            // Verify we have the expected SDK versions
            RunTest("--list-sdks")
                .Should().Pass()
                .And.HaveStdOutContaining($"9999.0.0 [{custom1.Location}")
                .And.HaveStdOutContaining($"9999.0.2 [{custom2.Location}")
                .And.HaveStdOutContaining($"9999.0.1 [{ExecutableDotNet.BinPath}");
        }

        [Fact]
        public void GlobalJson_ErrorMessage()
        {
            GlobalJson.Sdk sdk = new() { ErrorMessage = "Custom SDK resolution error" };
            GlobalJson.Write(SharedState.CurrentWorkingDir, sdk);

            RunTest()
                .Should().Fail()
                .And.HaveStdErrContaining(sdk.ErrorMessage);
        }

        [Fact]
        public void SdkResolutionError()
        {
            // Set specified SDK version to one that will not exist
            string requestedVersion = "9999.0.1";
            string globalJsonPath = GlobalJson.CreateWithVersion(SharedState.CurrentWorkingDir, requestedVersion);

            // When we fail to resolve SDK version, we print out all available SDKs
            // Versions should be in ascending order.
            string[] versions = ["5.0.2", "6.1.1", "9999.1.0"];
            AddAvailableSdkVersions(versions);

            string sdkPath = Path.Combine(ExecutableDotNet.BinPath, "sdk");
            string expectedOutput = string.Join(string.Empty, versions.Select(v => $"{v} [{sdkPath}]{Environment.NewLine}"));

            RunTest()
                .Should().Fail()
                .And.NotFindCompatibleSdk(globalJsonPath, requestedVersion)
                .And.HaveStdOutContaining(expectedOutput);
        }

        public static IEnumerable<object[]> InvalidGlobalJsonData
        {
            get
            {
                const string IgnoringSDKSettings = "Ignoring SDK settings in global.json: the latest installed .NET SDK (including prereleases) will be used";

                // Use invalid JSON
                yield return new object[] {
                    "{ sdk: { \"version\": \"9999.0.100\" } }",
                    new[] {
                        "A JSON parsing exception occurred",
                        IgnoringSDKSettings
                    }
                };

                // Use something other than a JSON object
                yield return new object[] {
                    "true",
                    new[] {
                        "Expected a JSON object",
                        IgnoringSDKSettings
                    }
                };

                // Use a non-string version
                yield return new object[] {
                    "{ \"sdk\": { \"version\": 1 } }",
                    new[] {
                        "Expected a string for the 'sdk/version' value",
                        IgnoringSDKSettings
                    }
                };

                // Use an invalid version value
                yield return new object[] {
                    GlobalJson.FormatSettings(new GlobalJson.Sdk() { Version = "invalid" }),
                    new[] {
                        "Version 'invalid' is not valid for the 'sdk/version' value",
                        IgnoringSDKSettings
                    }
                };

                // Use a non-string policy
                yield return new object[] {
                    "{ \"sdk\": { \"rollForward\": true } }",
                    new[] {
                        "Expected a string for the 'sdk/rollForward' value",
                        IgnoringSDKSettings
                    }
                };

                // Use a policy but no version
                yield return new object[] {
                    GlobalJson.FormatSettings(new GlobalJson.Sdk() { RollForward = "latestPatch" }),
                    new[] {
                        "The roll-forward policy 'latestPatch' requires a 'sdk/version' value",
                        IgnoringSDKSettings
                    }
                };

                // Use an invalid policy value
                yield return new object[] {
                    GlobalJson.FormatSettings(new GlobalJson.Sdk() { RollForward = "invalid" }),
                    new[] {
                        "The roll-forward policy 'invalid' is not supported for the 'sdk/rollForward' value",
                        IgnoringSDKSettings
                    }
                };

                // Use a non-boolean allow prerelease
                yield return new object[] {
                    "{ \"sdk\": { \"allowPrerelease\": \"true\" } }",
                    new[] {
                        "Expected a boolean for the 'sdk/allowPrerelease' value",
                        IgnoringSDKSettings
                    }
                };

                // Use a prerelease version and allowPrerelease = false
                yield return new object[] {
                    GlobalJson.FormatSettings(new GlobalJson.Sdk() { Version = "9999.1.402-preview1", AllowPrerelease = false }),
                    new[] { "Ignoring the 'sdk/allowPrerelease' value" }
                };
            }
        }

        public static IEnumerable<object[]> SdkRollForwardData
        {
            get
            {
                const string Requested = "9999.1.501";

                var installed = new string[] {
                    "9999.1.500",
                };

                // Array of (policy, expected) tuples
                var policies = new[] {
                    ((string)null,    (string)null),
                    ("patch",         (string)null),
                    ("feature",       (string)null),
                    ("minor",         (string)null),
                    ("major",         (string)null),
                    ("latestPatch",   (string)null),
                    ("latestFeature", (string)null),
                    ("latestMinor",   (string)null),
                    ("latestMajor",   (string)null),
                    ("disable",       (string)null),
                    ("invalid",       "9999.1.500"),
                };

                foreach (var policy in policies)
                {
                    yield return new object[] {
                        policy.Item1, // policy
                        Requested,    // requested
                        true,         // allow prerelease
                        policy.Item2, // expected
                        installed     // installed
                    };
                }

                installed = new string[] {
                    "9999.1.500",
                    "9999.2.100-preview1",
                };

                // Array of (policy, expected) tuples
                policies = new[] {
                    ((string)null,    (string)null),
                    ("patch",         (string)null),
                    ("feature",       (string)null),
                    ("minor",         (string)null),
                    ("major",         (string)null),
                    ("latestPatch",   (string)null),
                    ("latestFeature", (string)null),
                    ("latestMinor",   (string)null),
                    ("latestMajor",   (string)null),
                    ("disable",       (string)null),
                    ("invalid",       "9999.2.100-preview1"),
                };

                foreach (var policy in policies)
                {
                    yield return new object[] {
                        policy.Item1, // policy
                        Requested,    // requested
                        false,        // do not allow prerelease
                        policy.Item2, // expected
                        installed     // installed
                    };
                }

                installed = new string[] {
                    "9998.0.300",
                    "9999.1.500",
                    "9999.1.501",
                    "9999.1.503-preview5",
                    "9999.1.503",
                    "9999.1.504-preview1",
                    "9999.1.504-preview2",
                };

                // Array of (policy, expected) tuples
                policies = new[] {
                    ((string)null,    "9999.1.501"),
                    ("patch",         "9999.1.501"),
                    ("feature",       "9999.1.504-preview2"),
                    ("minor",         "9999.1.504-preview2"),
                    ("major",         "9999.1.504-preview2"),
                    ("latestPatch",   "9999.1.504-preview2"),
                    ("latestFeature", "9999.1.504-preview2"),
                    ("latestMinor",   "9999.1.504-preview2"),
                    ("latestMajor",   "9999.1.504-preview2"),
                    ("disable",       "9999.1.501"),
                    ("invalid",       "9999.1.504-preview2"),
                };

                foreach (var policy in policies)
                {
                    yield return new object[] {
                        policy.Item1, // policy
                        Requested,    // requested
                        true,         // allow prerelease
                        policy.Item2, // expected
                        installed     // installed
                    };
                }

                installed = new string[] {
                    "9998.0.300",
                    "9999.1.500",
                    "9999.1.501",
                    "9999.1.503-preview5",
                    "9999.1.503",
                    "9999.1.504-preview1",
                    "9999.1.504-preview2",
                };

                // Array of (policy, expected) tuples
                policies = new[] {
                    ((string)null,    "9999.1.501"),
                    ("patch",         "9999.1.501"),
                    ("feature",       "9999.1.503"),
                    ("minor",         "9999.1.503"),
                    ("major",         "9999.1.503"),
                    ("latestPatch",   "9999.1.503"),
                    ("latestFeature", "9999.1.503"),
                    ("latestMinor",   "9999.1.503"),
                    ("latestMajor",   "9999.1.503"),
                    ("disable",       "9999.1.501"),
                    ("invalid",       "9999.1.504-preview2"),
                };

                foreach (var policy in policies)
                {
                    yield return new object[] {
                        policy.Item1, // policy
                        Requested,    // requested
                        false,        // don't allow prerelease
                        policy.Item2, // expected
                        installed     // installed
                    };
                }

                installed = new string[] {
                    "9998.0.300",
                    "9999.1.500",
                    "9999.1.503",
                    "9999.1.505-preview2",
                    "9999.1.505",
                    "9999.1.506-preview1",
                    "9999.1.601",
                    "9999.1.608-preview3",
                    "9999.1.609",
                    "9999.2.101",
                    "9999.2.203-preview1",
                    "9999.2.203",
                    "10000.0.100",
                    "10000.1.100-preview1"
                };

                // Array of (policy, expected) tuples
                policies = new[] {
                    (null,            "9999.1.506-preview1"),
                    ("patch",         "9999.1.506-preview1"),
                    ("feature",       "9999.1.506-preview1"),
                    ("minor",         "9999.1.506-preview1"),
                    ("major",         "9999.1.506-preview1"),
                    ("latestPatch",   "9999.1.506-preview1"),
                    ("latestFeature", "9999.1.609"),
                    ("latestMinor",   "9999.2.203"),
                    ("latestMajor",   "10000.1.100-preview1"),
                    ("disable",       (string)null),
                    ("invalid",       "10000.1.100-preview1"),
                };

                foreach (var policy in policies)
                {
                    yield return new object[] {
                        policy.Item1, // policy
                        Requested,    // requested
                        true,         // allow prerelease
                        policy.Item2, // expected
                        installed     // installed
                    };
                }

                installed = new string[] {
                    "9998.0.300",
                    "9999.1.500",
                    "9999.1.503",
                    "9999.1.505-preview2",
                    "9999.1.505",
                    "9999.1.506-preview1",
                    "9999.1.601",
                    "9999.1.608-preview3",
                    "9999.1.609",
                    "9999.2.101",
                    "9999.2.203-preview1",
                    "9999.2.203",
                    "10000.0.100",
                    "10000.1.100-preview1"
                };

                // Array of (policy, expected) tuples
                policies = new[] {
                    (null,            "9999.1.505"),
                    ("patch",         "9999.1.505"),
                    ("feature",       "9999.1.505"),
                    ("minor",         "9999.1.505"),
                    ("major",         "9999.1.505"),
                    ("latestPatch",   "9999.1.505"),
                    ("latestFeature", "9999.1.609"),
                    ("latestMinor",   "9999.2.203"),
                    ("latestMajor",   "10000.0.100"),
                    ("disable",       (string)null),
                    ("invalid",       "10000.1.100-preview1"),
                };

                foreach (var policy in policies)
                {
                    yield return new object[] {
                        policy.Item1, // policy
                        Requested,    // requested
                        false,        // don't allow prerelease
                        policy.Item2, // expected
                        installed     // installed
                    };
                }

                installed = new string[] {
                    "9998.0.300",
                    "9999.1.500",
                    "9999.1.601",
                    "9999.1.604-preview3",
                    "9999.1.604",
                    "9999.1.605-preview4",
                    "9999.1.701",
                    "9999.1.702-preview1",
                    "9999.1.702",
                    "9999.2.101",
                    "9999.2.203",
                    "9999.2.204-preview1",
                    "10000.0.100-preview7",
                    "10000.0.100",
                };

                // Array of (policy, expected) tuples
                policies = new[] {
                    ((string)null,    (string)null),
                    ("patch",         (string)null),
                    ("feature",       "9999.1.605-preview4"),
                    ("minor",         "9999.1.605-preview4"),
                    ("major",         "9999.1.605-preview4"),
                    ("latestPatch",   (string)null),
                    ("latestFeature", "9999.1.702"),
                    ("latestMinor",   "9999.2.204-preview1"),
                    ("latestMajor",   "10000.0.100"),
                    ("disable",       (string)null),
                    ("invalid",       "10000.0.100"),
                };

                foreach (var policy in policies)
                {
                    yield return new object[] {
                        policy.Item1, // policy
                        Requested,    // requested
                        true,         // allow prerelease
                        policy.Item2, // expected
                        installed     // installed
                    };
                }

                installed = new string[] {
                    "9998.0.300",
                    "9999.1.500",
                    "9999.1.601",
                    "9999.1.604-preview3",
                    "9999.1.604",
                    "9999.1.605-preview4",
                    "9999.1.701",
                    "9999.1.702-preview1",
                    "9999.1.702",
                    "9999.2.101",
                    "9999.2.203",
                    "9999.2.204-preview1",
                    "10000.0.100-preview7",
                    "10000.0.100",
                };

                // Array of (policy, expected) tuples
                policies = new[] {
                    ((string)null,    (string)null),
                    ("patch",         (string)null),
                    ("feature",       "9999.1.604"),
                    ("minor",         "9999.1.604"),
                    ("major",         "9999.1.604"),
                    ("latestPatch",   (string)null),
                    ("latestFeature", "9999.1.702"),
                    ("latestMinor",   "9999.2.203"),
                    ("latestMajor",   "10000.0.100"),
                    ("disable",       (string)null),
                    ("invalid",       "10000.0.100"),
                };

                foreach (var policy in policies)
                {
                    yield return new object[] {
                        policy.Item1, // policy
                        Requested,    // requested
                        false,        // don't allow prerelease
                        policy.Item2, // expected
                        installed     // installed
                    };
                }

                installed = new string[] {
                    "9998.0.300",
                    "9999.1.500",
                    "9999.2.101-preview4",
                    "9999.2.101",
                    "9999.2.102-preview1",
                    "9999.2.203",
                    "9999.3.501",
                    "9999.4.205-preview3",
                    "10000.0.100",
                    "10000.1.100-preview1"
                };

                // Array of (policy, expected) tuples
                policies = new[] {
                    ((string)null,    (string)null),
                    ("patch",         (string)null),
                    ("feature",       (string)null),
                    ("minor",         "9999.2.102-preview1"),
                    ("major",         "9999.2.102-preview1"),
                    ("latestPatch",   (string)null),
                    ("latestFeature", (string)null),
                    ("latestMinor",   "9999.4.205-preview3"),
                    ("latestMajor",   "10000.1.100-preview1"),
                    ("disable",       (string)null),
                    ("invalid",       "10000.1.100-preview1"),
                };

                foreach (var policy in policies)
                {
                    yield return new object[] {
                        policy.Item1, // policy
                        Requested,    // requested
                        true,         // allow prerelease
                        policy.Item2, // expected
                        installed     // installed
                    };
                }

                installed = new string[] {
                    "9998.0.300",
                    "9999.1.500",
                    "9999.2.101-preview4",
                    "9999.2.101",
                    "9999.2.102-preview1",
                    "9999.2.203",
                    "9999.3.501",
                    "9999.4.205-preview3",
                    "10000.0.100",
                    "10000.1.100-preview1"
                };

                // Array of (policy, expected) tuples
                policies = new[] {
                    ((string)null,    (string)null),
                    ("patch",         (string)null),
                    ("feature",       (string)null),
                    ("minor",         "9999.2.101"),
                    ("major",         "9999.2.101"),
                    ("latestPatch",   (string)null),
                    ("latestFeature", (string)null),
                    ("latestMinor",   "9999.3.501"),
                    ("latestMajor",   "10000.0.100"),
                    ("disable",       (string)null),
                    ("invalid",       "10000.1.100-preview1"),
                };

                foreach (var policy in policies)
                {
                    yield return new object[] {
                        policy.Item1, // policy
                        Requested,    // requested
                        false,        // don't allow prerelease
                        policy.Item2, // expected
                        installed     // installed
                    };
                }

                installed = new string[] {
                    "9998.0.300",
                    "9999.1.500",
                    "10000.0.100",
                    "10000.0.105-preview1",
                    "10000.0.105",
                    "10000.0.106-preview1",
                    "10000.1.102",
                    "10000.1.107",
                    "10000.3.100",
                    "10000.3.102-preview3",
                };

                // Array of (policy, expected) tuples
                policies = new[] {
                    ((string)null,    (string)null),
                    ("patch",         (string)null),
                    ("feature",       (string)null),
                    ("minor",         (string)null),
                    ("major",         "10000.0.106-preview1"),
                    ("latestPatch",   (string)null),
                    ("latestFeature", (string)null),
                    ("latestMinor",   (string)null),
                    ("latestMajor",   "10000.3.102-preview3"),
                    ("disable",       (string)null),
                    ("invalid",       "10000.3.102-preview3"),
                };

                foreach (var policy in policies)
                {
                    yield return new object[] {
                        policy.Item1, // policy
                        Requested,    // requested
                        true,         // allow prerelease
                        policy.Item2, // expected
                        installed     // installed
                    };
                }

                installed = new string[] {
                    "9998.0.300",
                    "9999.1.500",
                    "10000.0.100",
                    "10000.0.105-preview1",
                    "10000.0.105",
                    "10000.0.106-preview1",
                    "10000.1.102",
                    "10000.1.107",
                    "10000.3.100",
                    "10000.3.102-preview3",
                };

                // Array of (policy, expected) tuples
                policies = new[] {
                    ((string)null,    (string)null),
                    ("patch",         (string)null),
                    ("feature",       (string)null),
                    ("minor",         (string)null),
                    ("major",         "10000.0.105"),
                    ("latestPatch",   (string)null),
                    ("latestFeature", (string)null),
                    ("latestMinor",   (string)null),
                    ("latestMajor",   "10000.3.100"),
                    ("disable",       (string)null),
                    ("invalid",       "10000.3.102-preview3"),
                };

                foreach (var policy in policies)
                {
                    yield return new object[] {
                        policy.Item1, // policy
                        Requested,    // requested
                        false,        // don't allow prerelease
                        policy.Item2, // expected
                        installed     // installed
                    };
                }
            }
        }

        private static void AddSdkToCustomPath(string sdkRoot, string version)
        {
            DotNetBuilder.AddMockSDK(sdkRoot, version, version);

            // Add a mock framework matching the runtime version for the mock SDK
            // This allows the host to successfully resolve frameworks for the SDK at the custom location
            DotNetBuilder.AddMicrosoftNETCoreAppFrameworkMockHostPolicy(sdkRoot, version);
        }

        // This method adds a list of new sdk version folders in the specified directory.
        // The actual contents are 'fake' and the minimum required for SDK discovery.
        // The dotnet.runtimeconfig.json created uses a dummy framework version (9999.0.0)
        private void AddAvailableSdkVersions(params string[] availableVersions)
        {
            foreach (string version in availableVersions)
            {
                ExecutableDotNetBuilder.AddMockSDK(version, "9999.0.0");
            }
        }

        private string ExpectedResolvedSdkOutput(string expectedVersion, string rootPath = null)
            => $"Using .NET SDK dll=[{Path.Combine(rootPath == null ? ExecutableDotNet.BinPath : rootPath, "sdk", expectedVersion, "dotnet.dll")}]";

        private CommandResult RunTest(string command = "help", [CallerMemberName] string caller = "")
        {
            return ExecutableDotNet.Exec(command)
                .WorkingDirectory(SharedState.CurrentWorkingDir)
                .EnableTracingAndCaptureOutputs()
                .MultilevelLookup(false)
                .Execute(caller);
        }

        public sealed class SharedTestState : IDisposable
        {
            public TestArtifact BaseArtifact { get; }

            public TestArtifact CurrentWorkingDirArtifact { get; }
            public string CurrentWorkingDir { get; }

            public SharedTestState()
            {
                BaseArtifact = TestArtifact.Create(nameof(SDKLookup));

                // The tested locations will be the cwd and the exe dir. cwd is no longer supported.
                // All dirs will be placed inside the base folder
                // Executable location is created per test as each test adds a different set of SDK versions

                var currentWorkingSdk = new DotNetBuilder(BaseArtifact.Location, TestContext.BuiltDotNet.BinPath, "current")
                    .AddMockSDK("10000.0.0", "9999.0.0")
                    .Build();
                CurrentWorkingDir = currentWorkingSdk.BinPath;
                CurrentWorkingDirArtifact = new TestArtifact(CurrentWorkingDir);
            }

            public void Dispose()
            {
                CurrentWorkingDirArtifact.Dispose();
                BaseArtifact.Dispose();
            }
        }
    }
}
