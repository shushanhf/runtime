// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;

namespace System.IO.Compression.Tests
{
    public class zip_ManualAndCompatibilityTests : ZipFileTestBase
    {
        public static bool IsUsingNewPathNormalization => !PathFeatures.IsUsingLegacyPathNormalization();

        public static IEnumerable<object[]> Get_CompatibilityTests_Data()
        {
            foreach (bool async in _bools)
            {
                yield return new object[] { "7zip.zip", "normal", true, true, async };
                yield return new object[] { "windows.zip", "normalWithoutEmptyDir", false, true, async };
                yield return new object[] { "dotnetzipstreaming.zip", "normal", false, false, async };
                yield return new object[] { "sharpziplib.zip", "normalWithoutEmptyDir", false, false, async };
                yield return new object[] { "xceedstreaming.zip", "normal", false, false, async };
            }
        }

        [Theory]
        [MemberData(nameof(Get_CompatibilityTests_Data))]
        public static async Task CompatibilityTests(string zipFile, string zipFolder, bool requireExplicit, bool checkTimes, bool async)
        {
            MemoryStream ms = await StreamHelpers.CreateTempCopyStream(compat(zipFile));
            await IsZipSameAsDir(ms, zfolder(zipFolder), ZipArchiveMode.Update, requireExplicit, checkTimes, async);
        }

        [Theory]
        [MemberData(nameof(Get_Booleans_Data))]
        public static async Task Deflate64Zip(bool async)
        {
            MemoryStream ms = await StreamHelpers.CreateTempCopyStream(compat("deflate64.zip"));
            await IsZipSameAsDir(ms, zfolder("normal"), ZipArchiveMode.Update, requireExplicit: true, checkTimes: true, async);
        }

        public static IEnumerable<object[]> Get_CompatibilityTestsMsFiles_Data()
        {
            foreach (bool async in _bools)
            {
                yield return new object[] { "excel.xlsx", "excel", false, false, async };
                yield return new object[] { "powerpoint.pptx", "powerpoint", false, false, async };
                yield return new object[] { "word.docx", "word", false, false, async };
                yield return new object[] { "silverlight.xap", "silverlight", false, false, async };
                yield return new object[] { "packaging.package", "packaging", false, false, async };
            }
        }

        [Theory]
        [MemberData(nameof(Get_CompatibilityTestsMsFiles_Data))]
        public static async Task CompatibilityTestsMsFiles(string withTrailing, string withoutTrailing, bool requireExplicit, bool checkTimes, bool async)
        {
            MemoryStream ms = await StreamHelpers.CreateTempCopyStream(compat(withTrailing));
            await IsZipSameAsDir(ms, compat(withoutTrailing), ZipArchiveMode.Update, requireExplicit, checkTimes, async);
        }

        /// <summary>
        /// This test ensures that a zipfile created on one platform with a file containing potentially invalid characters elsewhere
        /// will be interpreted based on the source OS path name validation rules.
        ///
        /// For example, the file "aa\bb\cc\dd" in a zip created on Unix should be one file "aa\bb\cc\dd" whereas the same file
        /// in a zip created on Windows should be interpreted as the file "dd" underneath three subdirectories.
        /// </summary>
        [ConditionalTheory(nameof(IsUsingNewPathNormalization))]
        [InlineData("backslashes_FromUnix.zip", "aa\\bb\\cc\\dd")]
        [InlineData("backslashes_FromWindows.zip", "dd")]
        [InlineData("WindowsInvalid_FromUnix.zip", "aa<b>d")]
        [InlineData("WindowsInvalid_FromWindows.zip", "aa<b>d")]
        [InlineData("NullCharFileName_FromWindows.zip", "a\06b6d")]
        [InlineData("NullCharFileName_FromUnix.zip", "a\06b6d")]
        public static async Task ZipWithInvalidFileNames_ParsedBasedOnSourceOS(string zipName, string fileName)
        {
            using (Stream stream = await StreamHelpers.CreateTempCopyStream(compat(zipName)))
            using (ZipArchive archive = new ZipArchive(stream))
            {
                Assert.Equal(1, archive.Entries.Count);
                ZipArchiveEntry entry = archive.Entries[0];
                Assert.Equal(fileName, entry.Name);
            }
        }

        public static IEnumerable<object[]> Get_ZipBinaryCompat_Data()
        {
            foreach (bool async in _bools)
            {
                yield return new object[] { "net45_unicode.zip", "unicode", async };
                yield return new object[] { "net46_unicode.zip", "unicode", async };
                yield return new object[] { "net45_normal.zip", "normal", async };
                yield return new object[] { "net46_normal.zip", "normal", async };
            }
        }

        /// <summary>
        /// This test compares binary content of a zip produced by the current version with a zip produced by
        /// other frameworks. It does this by searching the two zips for the header signature and then
        /// it compares the subsequent header values for equality.
        ///
        /// This test looks for the local file headers that each entry within a zip possesses and compares these
        /// values:
        /// local file header signature     4 bytes  (0x04034b50)
        /// version needed to extract       2 bytes
        /// general purpose bit flag        2 bytes
        /// compression method              2 bytes
        /// last mod file time              2 bytes
        /// last mod file date              2 bytes
        ///
        /// it does not compare these values:
        ///
        /// crc-32                          4 bytes
        /// compressed size                 4 bytes
        /// uncompressed size               4 bytes
        /// file name length                2 bytes
        /// extra field length              2 bytes
        /// file name(variable size)
        /// extra field(variable size)
        /// </summary>
        [Theory]
        [MemberData(nameof(Get_ZipBinaryCompat_Data))]
        public static async Task ZipBinaryCompat_LocalFileHeaders(string zipFile, string zipFolder, bool async)
        {
            using (MemoryStream actualArchiveStream = new MemoryStream())
            using (MemoryStream expectedArchiveStream = await StreamHelpers.CreateTempCopyStream(compat(zipFile)))
            {
                byte[] localFileHeaderSignature = new byte[] { 0x50, 0x4b, 0x03, 0x04 };

                // Produce a ZipFile
                await CreateFromDir(zfolder(zipFolder), actualArchiveStream, async, ZipArchiveMode.Create);

                // Read the streams to byte arrays
                byte[] actualBytes = actualArchiveStream.ToArray();
                byte[] expectedBytes = expectedArchiveStream.ToArray();

                // Search for the file headers
                int actualIndex = 0, expectedIndex = 0;
                while ((expectedIndex = FindIndexOfSequence(expectedBytes, expectedIndex, localFileHeaderSignature)) != -1)
                {
                    actualIndex = FindIndexOfSequence(actualBytes, actualIndex, localFileHeaderSignature);
                    Assert.NotEqual(-1, actualIndex);
                    for (int i = 0; i < 14; i++)
                    {
                        Assert.Equal(expectedBytes[expectedIndex], actualBytes[actualIndex]);
                    }
                    expectedIndex += 14;
                    actualIndex += 14;
                }
            }
        }

        /// <summary>
        /// This test compares binary content of a zip produced by the current version with a zip produced by
        /// other frameworks. It does this by searching the two zips for the header signature and then
        /// it compares the subsequent header values for equality.
        ///
        /// This test looks for the central directory headers that each entry within a zip possesses and compares these
        /// values:
        /// central file header signature   4 bytes  (0x02014b50)
        /// version made by                 2 bytes
        /// version needed to extract       2 bytes
        /// general purpose bit flag        2 bytes
        /// compression method              2 bytes
        /// last mod file time              2 bytes
        /// last mod file date              2 bytes
        /// uncompressed size               4 bytes
        /// file name length                2 bytes
        /// extra field length              2 bytes
        /// file comment length             2 bytes
        /// disk number start               2 bytes
        /// internal file attributes        2 bytes
        /// external file attributes        4 bytes
        ///
        /// it does not compare these values:
        /// crc-32                          4 bytes
        /// compressed size                 4 bytes
        /// relative offset of local header 4 bytes
        /// file name (variable size)
        /// extra field (variable size)
        /// file comment (variable size)
        /// </summary>
        [Theory]
        [MemberData(nameof(Get_ZipBinaryCompat_Data))]
        public static async Task ZipBinaryCompat_CentralDirectoryHeaders(string zipFile, string zipFolder, bool async)
        {
            using (MemoryStream actualArchiveStream = new MemoryStream())
            using (MemoryStream expectedArchiveStream = await StreamHelpers.CreateTempCopyStream(compat(zipFile)))
            {
                byte[] signature = new byte[] { 0x50, 0x4b, 0x03, 0x04 };

                // Produce a ZipFile
                await CreateFromDir(zfolder(zipFolder), actualArchiveStream, async, ZipArchiveMode.Create);

                // Read the streams to byte arrays
                byte[] actualBytes = actualArchiveStream.ToArray();
                byte[] expectedBytes = expectedArchiveStream.ToArray();

                // Search for the file headers
                int actualIndex = 0, expectedIndex = 0;
                while ((expectedIndex = FindIndexOfSequence(expectedBytes, expectedIndex, signature)) != -1)
                {
                    actualIndex = FindIndexOfSequence(actualBytes, actualIndex, signature);
                    Assert.NotEqual(-1, actualIndex);
                    for (int i = 0; i < 16; i++)
                    {
                        Assert.Equal(expectedBytes[expectedIndex], actualBytes[actualIndex]);
                    }
                    for (int i = 24; i < 42; i++)
                    {
                        Assert.Equal(expectedBytes[expectedIndex], actualBytes[actualIndex]);
                    }
                    expectedIndex += 38;
                    actualIndex += 38;
                }
            }
        }

        /// <summary>
        /// Simple helper method to search <paramref name="bytesToSearch"/> for the exact byte sequence specified by
        /// <paramref name="sequenceToFind"/>, starting at <paramref name="startIndex"/>.
        /// </summary>
        /// <returns>The first index of the first element in the matching sequence</returns>
        public static int FindIndexOfSequence(byte[] bytesToSearch, int startIndex, byte[] sequenceToFind)
        {
            for (int index = startIndex; index < bytesToSearch.Length - sequenceToFind.Length; index++)
            {
                bool equal = true;
                for (int i = 0; i < sequenceToFind.Length; i++)
                {
                    if (bytesToSearch[index + i] != sequenceToFind[i])
                    {
                        equal = false;
                        break;
                    }
                }
                if (equal)
                    return index;
            }
            return -1;
        }
    }
}
