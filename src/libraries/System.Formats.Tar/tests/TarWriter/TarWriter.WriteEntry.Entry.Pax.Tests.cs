﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Globalization;
using System.IO;
using Xunit;

namespace System.Formats.Tar.Tests
{
    // Tests specific to PAX format.
    public class TarWriter_WriteEntry_Pax_Tests : TarWriter_WriteEntry_Base
    {
        [Fact]
        public void WriteEntry_Null_Throws() =>
            WriteEntry_Null_Throws_Internal(TarEntryFormat.Pax);

        [Fact]
        public void WriteRegularFile()
        {
            using MemoryStream archiveStream = new MemoryStream();
            using (TarWriter writer = new TarWriter(archiveStream, TarEntryFormat.Pax, leaveOpen: true))
            {
                PaxTarEntry regularFile = new PaxTarEntry(TarEntryType.RegularFile, InitialEntryName);
                SetRegularFile(regularFile);
                VerifyRegularFile(regularFile, isWritable: true);
                writer.WriteEntry(regularFile);
            }

            archiveStream.Position = 0;
            using (TarReader reader = new TarReader(archiveStream))
            {
                PaxTarEntry regularFile = reader.GetNextEntry() as PaxTarEntry;
                VerifyRegularFile(regularFile, isWritable: false);
            }
        }

        [Fact]
        public void WriteHardLink()
        {
            using MemoryStream archiveStream = new MemoryStream();
            using (TarWriter writer = new TarWriter(archiveStream, TarEntryFormat.Pax, leaveOpen: true))
            {
                PaxTarEntry hardLink = new PaxTarEntry(TarEntryType.HardLink, InitialEntryName);
                SetHardLink(hardLink);
                VerifyHardLink(hardLink);
                writer.WriteEntry(hardLink);
            }

            archiveStream.Position = 0;
            using (TarReader reader = new TarReader(archiveStream))
            {
                PaxTarEntry hardLink = reader.GetNextEntry() as PaxTarEntry;
                VerifyHardLink(hardLink);
            }
        }

        [Fact]
        public void WriteSymbolicLink()
        {
            using MemoryStream archiveStream = new MemoryStream();
            using (TarWriter writer = new TarWriter(archiveStream, TarEntryFormat.Pax, leaveOpen: true))
            {
                PaxTarEntry symbolicLink = new PaxTarEntry(TarEntryType.SymbolicLink, InitialEntryName);
                SetSymbolicLink(symbolicLink);
                VerifySymbolicLink(symbolicLink);
                writer.WriteEntry(symbolicLink);
            }

            archiveStream.Position = 0;
            using (TarReader reader = new TarReader(archiveStream))
            {
                PaxTarEntry symbolicLink = reader.GetNextEntry() as PaxTarEntry;
                VerifySymbolicLink(symbolicLink);
            }
        }

        [Fact]
        public void WriteDirectory()
        {
            using MemoryStream archiveStream = new MemoryStream();
            using (TarWriter writer = new TarWriter(archiveStream, TarEntryFormat.Pax, leaveOpen: true))
            {
                PaxTarEntry directory = new PaxTarEntry(TarEntryType.Directory, InitialEntryName);
                SetDirectory(directory);
                VerifyDirectory(directory);
                writer.WriteEntry(directory);
            }

            archiveStream.Position = 0;
            using (TarReader reader = new TarReader(archiveStream))
            {
                PaxTarEntry directory = reader.GetNextEntry() as PaxTarEntry;
                VerifyDirectory(directory);
            }
        }

        [Fact]
        public void WriteCharacterDevice()
        {
            using MemoryStream archiveStream = new MemoryStream();
            using (TarWriter writer = new TarWriter(archiveStream, TarEntryFormat.Pax, leaveOpen: true))
            {
                PaxTarEntry charDevice = new PaxTarEntry(TarEntryType.CharacterDevice, InitialEntryName);
                SetCharacterDevice(charDevice);
                VerifyCharacterDevice(charDevice);
                writer.WriteEntry(charDevice);
            }

            archiveStream.Position = 0;
            using (TarReader reader = new TarReader(archiveStream))
            {
                PaxTarEntry charDevice = reader.GetNextEntry() as PaxTarEntry;
                VerifyCharacterDevice(charDevice);
            }
        }

        [Fact]
        public void WriteBlockDevice()
        {
            using MemoryStream archiveStream = new MemoryStream();
            using (TarWriter writer = new TarWriter(archiveStream, TarEntryFormat.Pax, leaveOpen: true))
            {
                PaxTarEntry blockDevice = new PaxTarEntry(TarEntryType.BlockDevice, InitialEntryName);
                SetBlockDevice(blockDevice);
                VerifyBlockDevice(blockDevice);
                writer.WriteEntry(blockDevice);
            }

            archiveStream.Position = 0;
            using (TarReader reader = new TarReader(archiveStream))
            {
                PaxTarEntry blockDevice = reader.GetNextEntry() as PaxTarEntry;
                VerifyBlockDevice(blockDevice);
            }
        }

        [Fact]
        public void WriteFifo()
        {
            using MemoryStream archiveStream = new MemoryStream();
            using (TarWriter writer = new TarWriter(archiveStream, TarEntryFormat.Pax, leaveOpen: true))
            {
                PaxTarEntry fifo = new PaxTarEntry(TarEntryType.Fifo, InitialEntryName);
                SetFifo(fifo);
                VerifyFifo(fifo);
                writer.WriteEntry(fifo);
            }

            archiveStream.Position = 0;
            using (TarReader reader = new TarReader(archiveStream))
            {
                PaxTarEntry fifo = reader.GetNextEntry() as PaxTarEntry;
                VerifyFifo(fifo);
            }
        }

        [Fact]
        public void WritePaxAttributes_CustomAttribute()
        {
            string expectedKey = "MyExtendedAttributeKey";
            string expectedValue = "MyExtendedAttributeValue";

            Dictionary<string, string> extendedAttributes = new();
            extendedAttributes.Add(expectedKey, expectedValue);

            using MemoryStream archiveStream = new MemoryStream();
            using (TarWriter writer = new TarWriter(archiveStream, TarEntryFormat.Pax, leaveOpen: true))
            {
                PaxTarEntry regularFile = new PaxTarEntry(TarEntryType.RegularFile, InitialEntryName, extendedAttributes);
                SetRegularFile(regularFile);
                VerifyRegularFile(regularFile, isWritable: true);
                writer.WriteEntry(regularFile);
            }

            archiveStream.Position = 0;
            using (TarReader reader = new TarReader(archiveStream))
            {
                PaxTarEntry regularFile = reader.GetNextEntry() as PaxTarEntry;
                VerifyRegularFile(regularFile, isWritable: false);

                Assert.NotNull(regularFile.ExtendedAttributes);

                // path, mtime, atime and ctime are always collected by default
                AssertExtensions.GreaterThanOrEqualTo(regularFile.ExtendedAttributes.Count, 3);

                Assert.Contains(PaxEaName, regularFile.ExtendedAttributes);
                Assert.Contains(PaxEaMTime, regularFile.ExtendedAttributes);

                Assert.Contains(expectedKey, regularFile.ExtendedAttributes);
                Assert.Equal(expectedValue, regularFile.ExtendedAttributes[expectedKey]);
            }
        }

        [Fact]
        public void WritePaxAttributes_Timestamps_AutomaticallyAdded()
        {
            DateTimeOffset minimumTime = DateTimeOffset.UtcNow - TimeSpan.FromHours(1);
            using MemoryStream archiveStream = new MemoryStream();
            using (TarWriter writer = new TarWriter(archiveStream, TarEntryFormat.Pax, leaveOpen: true))
            {
                PaxTarEntry regularFile = new PaxTarEntry(TarEntryType.RegularFile, InitialEntryName);
                writer.WriteEntry(regularFile);
            }

            archiveStream.Position = 0;
            using (TarReader reader = new TarReader(archiveStream))
            {
                PaxTarEntry regularFile = reader.GetNextEntry() as PaxTarEntry;

                AssertExtensions.GreaterThanOrEqualTo(regularFile.ExtendedAttributes.Count, 2);
                VerifyExtendedAttributeTimestamp(regularFile, PaxEaMTime, minimumTime);
            }
        }

        [Fact]
        public void WritePaxAttributes_Timestamps_UserProvided()
        {
            Dictionary<string, string> extendedAttributes = new();
            extendedAttributes.Add(PaxEaATime, GetTimestampStringFromDateTimeOffset(TestAccessTime));
            extendedAttributes.Add(PaxEaCTime, GetTimestampStringFromDateTimeOffset(TestChangeTime));

            using MemoryStream archiveStream = new MemoryStream();
            using (TarWriter writer = new TarWriter(archiveStream, TarEntryFormat.Pax, leaveOpen: true))
            {
                PaxTarEntry regularFile = new PaxTarEntry(TarEntryType.RegularFile, InitialEntryName, extendedAttributes);
                regularFile.ModificationTime = TestModificationTime;
                writer.WriteEntry(regularFile);
            }

            archiveStream.Position = 0;
            using (TarReader reader = new TarReader(archiveStream))
            {
                PaxTarEntry regularFile = reader.GetNextEntry() as PaxTarEntry;

                AssertExtensions.GreaterThanOrEqualTo(regularFile.ExtendedAttributes.Count, 4);
                VerifyExtendedAttributeTimestamp(regularFile, PaxEaMTime, TestModificationTime);
                VerifyExtendedAttributeTimestamp(regularFile, PaxEaATime, TestAccessTime);
                VerifyExtendedAttributeTimestamp(regularFile, PaxEaCTime, TestChangeTime);
            }
        }

        [Fact]
        public void WritePaxAttributes_LongGroupName_LongUserName()
        {
            string userName = "IAmAUserNameWhoseLengthIsWayBeyondTheThirtyTwoByteLimit";
            string groupName = "IAmAGroupNameWhoseLengthIsWayBeyondTheThirtyTwoByteLimit";

            using MemoryStream archiveStream = new MemoryStream();
            using (TarWriter writer = new TarWriter(archiveStream, TarEntryFormat.Pax, leaveOpen: true))
            {
                PaxTarEntry regularFile = new PaxTarEntry(TarEntryType.RegularFile, InitialEntryName);
                SetRegularFile(regularFile);
                VerifyRegularFile(regularFile, isWritable: true);
                regularFile.UserName = userName;
                regularFile.GroupName = groupName;
                writer.WriteEntry(regularFile);
            }

            archiveStream.Position = 0;
            using (TarReader reader = new TarReader(archiveStream))
            {
                PaxTarEntry regularFile = reader.GetNextEntry() as PaxTarEntry;
                VerifyRegularFile(regularFile, isWritable: false);

                Assert.NotNull(regularFile.ExtendedAttributes);

                // path, mtime are always collected by default
                AssertExtensions.GreaterThanOrEqualTo(regularFile.ExtendedAttributes.Count, 4);

                Assert.Contains(PaxEaName, regularFile.ExtendedAttributes);
                Assert.Contains(PaxEaMTime, regularFile.ExtendedAttributes);

                Assert.Contains(PaxEaUName, regularFile.ExtendedAttributes);
                Assert.Equal(userName, regularFile.ExtendedAttributes[PaxEaUName]);

                Assert.Contains(PaxEaGName, regularFile.ExtendedAttributes);
                Assert.Equal(groupName, regularFile.ExtendedAttributes[PaxEaGName]);

                // They should also get exposed via the regular properties
                Assert.Equal(groupName, regularFile.GroupName);
                Assert.Equal(userName, regularFile.UserName);
            }
        }

        [Fact]
        public void WritePaxAttributes_Name_AutomaticallyAdded()
        {
            using MemoryStream archiveStream = new MemoryStream();
            using (TarWriter writer = new TarWriter(archiveStream, TarEntryFormat.Pax, leaveOpen: true))
            {
                PaxTarEntry regularFile = new PaxTarEntry(TarEntryType.RegularFile, InitialEntryName);
                writer.WriteEntry(regularFile);
            }

            archiveStream.Position = 0;
            using (TarReader reader = new TarReader(archiveStream))
            {
                PaxTarEntry regularFile = reader.GetNextEntry() as PaxTarEntry;

                AssertExtensions.GreaterThanOrEqualTo(regularFile.ExtendedAttributes.Count, 2);
                Assert.Contains(PaxEaName, regularFile.ExtendedAttributes);
            }
        }

        [Fact]
        public void WritePaxAttributes_LongLinkName_AutomaticallyAdded()
        {
            using MemoryStream archiveStream = new MemoryStream();

            string longSymbolicLinkName = new string('a', 101);
            string longHardLinkName = new string('b', 101);
            using (TarWriter writer = new TarWriter(archiveStream, TarEntryFormat.Pax, leaveOpen: true))
            {
                PaxTarEntry symlink = new PaxTarEntry(TarEntryType.SymbolicLink, "symlink");
                symlink.LinkName = longSymbolicLinkName;
                writer.WriteEntry(symlink);

                PaxTarEntry hardlink = new PaxTarEntry(TarEntryType.HardLink, "hardlink");
                hardlink.LinkName = longHardLinkName;
                writer.WriteEntry(hardlink);
            }

            archiveStream.Position = 0;
            using (TarReader reader = new TarReader(archiveStream))
            {
                PaxTarEntry symlink = reader.GetNextEntry() as PaxTarEntry;

                AssertExtensions.GreaterThanOrEqualTo(symlink.ExtendedAttributes.Count, 3);

                Assert.Contains(PaxEaName, symlink.ExtendedAttributes);
                Assert.Equal("symlink", symlink.ExtendedAttributes[PaxEaName]);
                Assert.Contains(PaxEaLinkName, symlink.ExtendedAttributes);
                Assert.Equal(longSymbolicLinkName, symlink.ExtendedAttributes[PaxEaLinkName]);

                PaxTarEntry hardlink = reader.GetNextEntry() as PaxTarEntry;

                AssertExtensions.GreaterThanOrEqualTo(hardlink.ExtendedAttributes.Count, 3);

                Assert.Contains(PaxEaName, hardlink.ExtendedAttributes);
                Assert.Equal("hardlink", hardlink.ExtendedAttributes[PaxEaName]);
                Assert.Contains(PaxEaLinkName, hardlink.ExtendedAttributes);
                Assert.Equal(longHardLinkName, hardlink.ExtendedAttributes[PaxEaLinkName]);
            }
        }

        [Fact]
        public void Add_Empty_GlobalExtendedAttributes()
        {
            using MemoryStream archive = new MemoryStream();

            using (TarWriter writer = new TarWriter(archive, leaveOpen: true))
            {
                PaxGlobalExtendedAttributesTarEntry gea = new PaxGlobalExtendedAttributesTarEntry(new Dictionary<string, string>());
                writer.WriteEntry(gea);
            }

            archive.Seek(0, SeekOrigin.Begin);
            using (TarReader reader = new TarReader(archive))
            {
                PaxGlobalExtendedAttributesTarEntry gea = reader.GetNextEntry() as PaxGlobalExtendedAttributesTarEntry;
                Assert.NotNull(gea);
                Assert.Equal(TarEntryFormat.Pax, gea.Format);
                Assert.Equal(TarEntryType.GlobalExtendedAttributes, gea.EntryType);

                Assert.Equal(0, gea.GlobalExtendedAttributes.Count);

                Assert.Null(reader.GetNextEntry());
            }
        }

        [Theory]
        [MemberData(nameof(WriteTimeStamp_Pax_TheoryData))]
        public void WriteTimestampsInPax(DateTimeOffset timestamp)
        {
            string strTimestamp = GetTimestampStringFromDateTimeOffset(timestamp);

            Dictionary<string, string> ea = new Dictionary<string, string>()
            {
                { PaxEaATime, strTimestamp },
                { PaxEaCTime, strTimestamp }
            };

            PaxTarEntry entry = new PaxTarEntry(TarEntryType.Directory, "dir", ea);

            entry.ModificationTime = timestamp;
            Assert.Equal(timestamp, entry.ModificationTime);

            Assert.Contains(PaxEaATime, entry.ExtendedAttributes);
            DateTimeOffset atime = GetDateTimeOffsetFromTimestampString(entry.ExtendedAttributes, PaxEaATime);
            Assert.Equal(timestamp, atime);

            Assert.Contains(PaxEaCTime, entry.ExtendedAttributes);
            DateTimeOffset ctime = GetDateTimeOffsetFromTimestampString(entry.ExtendedAttributes, PaxEaCTime);
            Assert.Equal(timestamp, ctime);

            using MemoryStream archiveStream = new MemoryStream();
            using (TarWriter writer = new TarWriter(archiveStream, leaveOpen: true))
            {
                writer.WriteEntry(entry);
            }

            archiveStream.Position = 0;
            using (TarReader reader = new TarReader(archiveStream))
            {
                PaxTarEntry readEntry = reader.GetNextEntry() as PaxTarEntry;
                Assert.NotNull(readEntry);

                Assert.Equal(timestamp, readEntry.ModificationTime);

                Assert.Contains(PaxEaATime, readEntry.ExtendedAttributes);
                DateTimeOffset actualATime = GetDateTimeOffsetFromTimestampString(readEntry.ExtendedAttributes, PaxEaATime);
                Assert.Equal(timestamp, actualATime);

                Assert.Contains(PaxEaCTime, readEntry.ExtendedAttributes);
                DateTimeOffset actualCTime = GetDateTimeOffsetFromTimestampString(readEntry.ExtendedAttributes, PaxEaCTime);
                Assert.Equal(timestamp, actualCTime);
            }
        }

        [Theory]
        [InlineData(TarEntryType.HardLink)]
        [InlineData(TarEntryType.SymbolicLink)]
        public void Write_LinkEntry_EmptyLinkName_Throws(TarEntryType entryType)
        {
            using MemoryStream archiveStream = new MemoryStream();
            using TarWriter writer = new TarWriter(archiveStream, leaveOpen: false);
            Assert.Throws<ArgumentException>("entry", () => writer.WriteEntry(new PaxTarEntry(entryType, "link")));
        }
    }
}
