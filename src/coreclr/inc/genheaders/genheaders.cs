﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.IO;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;

if (args.Length != 3)
{
    Console.WriteLine("Usage:genheaders XML-file header-file resource-file");
    return;
}

ValidateXML(args[0]);

using StreamWriter HSW = File.CreateText(args[1]);
using StreamWriter RSW = File.CreateText(args[2]);

int FaciltyUrt = 0x13;
int SeveritySuccess = 0;
int SeverityError = 1;

int minSR = MakeHresult(SeveritySuccess, FaciltyUrt, 0);
int maxSR = MakeHresult(SeveritySuccess, FaciltyUrt, 0xffff);
int minHR = MakeHresult(SeverityError, FaciltyUrt, 0);
int maxHR = MakeHresult(SeverityError, FaciltyUrt, 0xffff);

PrintLicenseHeader(HSW);
PrintHeader(HSW);
PrintLicenseHeader(RSW);
PrintResourceHeader(RSW);

XDocument doc = XDocument.Load(args[0]);
foreach (XElement element in doc.Descendants("HRESULT"))
{
    string NumericValue = element.Attribute("NumericValue")!.Value;
    string? Message = element.Element("Message")?.Value;
    string? SymbolicName = element.Element("SymbolicName")?.Value;

    // For CLR Hresult's we take the last 4 digits as the resource strings.

    if (NumericValue.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
    {
        int num = int.Parse(NumericValue.AsSpan(2), System.Globalization.NumberStyles.HexNumber);

        if ((num > minSR) && (num <= maxSR))
        {
            num &= 0xffff;
            HSW.WriteLine("#define " + SymbolicName + " SMAKEHR(0x" + num.ToString("x") + ")");
        }
        else if ((num > minHR) && (num <= maxHR))
        {
            num &= 0xffff;
            HSW.WriteLine("#define " + SymbolicName + " EMAKEHR(0x" + num.ToString("x") + ")");
        }
        else
        {
            HSW.WriteLine("#define " + SymbolicName + " " + NumericValue);
        }
    }
    else
    {
        HSW.WriteLine("#define " + SymbolicName + " " + NumericValue);
    }

    if (Message != null)
    {
        RSW.Write("\tMSG_FOR_URT_HR(" + SymbolicName + ") ");
        RSW.WriteLine(Message);
    }
}

PrintFooter(HSW);
PrintResourceFooter(RSW);

void ValidateXML(string XMLFile)
{

    // Set the validation settings on the XmlReaderSettings object.
    XmlReaderSettings settings = new XmlReaderSettings();

    settings.ValidationType = ValidationType.Schema;
    settings.ValidationFlags |= XmlSchemaValidationFlags.ProcessInlineSchema;

    settings.ValidationEventHandler += (s, e) =>
    {
        Console.WriteLine("Validation Error: {0}", e.Message);
        Environment.Exit(-1);
    };

    // Create the XmlReader object.
    XmlReader reader = XmlReader.Create(XMLFile, settings);

    // Parse the file.

    while (reader.Read())
    {
    }
}

void PrintLicenseHeader(StreamWriter SW)
{
    SW.WriteLine("// Licensed to the .NET Foundation under one or more agreements.");
    SW.WriteLine("// The .NET Foundation licenses this file to you under the MIT license.");
    SW.WriteLine();
}

void PrintHeader(StreamWriter SW)
{

    SW.WriteLine("#ifndef __COMMON_LANGUAGE_RUNTIME_HRESULTS__");
    SW.WriteLine("#define __COMMON_LANGUAGE_RUNTIME_HRESULTS__");
    SW.WriteLine();
    SW.WriteLine("#include <winerror.h>");
    SW.WriteLine();
    SW.WriteLine();
    SW.WriteLine("//");
    SW.WriteLine("//This file is AutoGenerated -- Do Not Edit by hand!!!");
    SW.WriteLine("//");
    SW.WriteLine("//Add new HRESULTS along with their corresponding error messages to");
    SW.WriteLine("//corerror.xml");
    SW.WriteLine("//");
    SW.WriteLine();
    SW.WriteLine("#ifndef FACILITY_URT");
    SW.WriteLine("#define FACILITY_URT            0x13");
    SW.WriteLine("#endif");
    SW.WriteLine("#ifndef EMAKEHR");
    SW.WriteLine("#define SMAKEHR(val) MAKE_HRESULT(SEVERITY_SUCCESS, FACILITY_URT, val)");
    SW.WriteLine("#define EMAKEHR(val) MAKE_HRESULT(SEVERITY_ERROR, FACILITY_URT, val)");
    SW.WriteLine("#endif");
    SW.WriteLine();
}

void PrintFooter(StreamWriter SW)
{
    SW.WriteLine();
    SW.WriteLine();
    SW.WriteLine("#endif // __COMMON_LANGUAGE_RUNTIME_HRESULTS__");
}

void PrintResourceHeader(StreamWriter SW)
{
    SW.WriteLine("STRINGTABLE DISCARDABLE");
    SW.WriteLine("BEGIN");
}

void PrintResourceFooter(StreamWriter SW)
{
    SW.WriteLine("END");
}

int MakeHresult(int sev, int fac, int code)
{
    return ((sev << 31) | (fac << 16) | (code));
}
