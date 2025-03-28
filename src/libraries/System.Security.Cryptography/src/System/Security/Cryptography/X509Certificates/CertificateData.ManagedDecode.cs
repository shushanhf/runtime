// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.X509Certificates.Asn1;
using System.Text;

namespace System.Security.Cryptography.X509Certificates
{
    internal enum GeneralNameType
    {
        OtherName = 0,
        Rfc822Name = 1,
        // RFC 822: Standard for the format of ARPA Internet Text Messages.
        // That means "email", and an RFC 822 Name: "Email address"
        Email = Rfc822Name,
        DnsName = 2,
        X400Address = 3,
        DirectoryName = 4,
        EdiPartyName = 5,
        UniformResourceIdentifier = 6,
        IPAddress = 7,
        RegisteredId = 8,
    }

    internal struct CertificateData
    {
        internal struct AlgorithmIdentifier
        {
            public AlgorithmIdentifier(AlgorithmIdentifierAsn algorithmIdentifier)
            {
                AlgorithmId = algorithmIdentifier.Algorithm;
                Parameters = algorithmIdentifier.Parameters?.ToArray();
            }

            internal string? AlgorithmId;
            internal byte[]? Parameters;
        }

        private CertificateAsn certificate;
        internal byte[] RawData;
        internal byte[] SubjectPublicKeyInfo;
        internal X500DistinguishedName Issuer;
        internal X500DistinguishedName Subject;
        internal List<X509Extension> Extensions;
        internal string IssuerName;
        internal string SubjectName;

        internal int Version => certificate.TbsCertificate.Version;

        internal byte[] SerialNumber => certificate.TbsCertificate.SerialNumber.ToArray();

        internal DateTime NotBefore => certificate.TbsCertificate.Validity.NotBefore.GetValue().UtcDateTime;

        internal DateTime NotAfter => certificate.TbsCertificate.Validity.NotAfter.GetValue().UtcDateTime;

        internal AlgorithmIdentifier PublicKeyAlgorithm => new AlgorithmIdentifier(certificate.TbsCertificate.SubjectPublicKeyInfo.Algorithm);

        internal byte[] PublicKey => certificate.TbsCertificate.SubjectPublicKeyInfo.SubjectPublicKey.ToArray();

        internal byte[]? IssuerUniqueId => certificate.TbsCertificate.IssuerUniqueId?.ToArray();

        internal byte[]? SubjectUniqueId => certificate.TbsCertificate.SubjectUniqueId?.ToArray();

        internal AlgorithmIdentifier SignatureAlgorithm => new AlgorithmIdentifier(certificate.SignatureAlgorithm);

        internal byte[] SignatureValue => certificate.SignatureValue.ToArray();

        internal CertificateData(byte[] rawData)
        {
#if DEBUG
        try
        {
#endif
            // Windows and Unix permit trailing data after the DER contents of the certificate, so we will allow
            // it here, too.
            AsnValueReader reader = new AsnValueReader(rawData, AsnEncodingRules.DER);
            ReadOnlySpan<byte> encodedValue = reader.PeekEncodedValue();

            CertificateAsn.Decode(ref reader, rawData, out certificate);
            certificate.TbsCertificate.ValidateVersion();

            // Use of == on Span is intentional. If the encodedValue is identical to the rawData, then we can use
            // raw data as-is, meaning it had no trailing data. Otherwise, use the encodedValue.
            RawData = encodedValue == rawData ? rawData : encodedValue.ToArray();

            Issuer = new X500DistinguishedName(certificate.TbsCertificate.Issuer.Span);
            Subject = new X500DistinguishedName(certificate.TbsCertificate.Subject.Span);
            IssuerName = Issuer.Name;
            SubjectName = Subject.Name;

            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            certificate.TbsCertificate.SubjectPublicKeyInfo.Encode(writer);
            SubjectPublicKeyInfo = writer.Encode();

            Extensions = new List<X509Extension>((certificate.TbsCertificate.Extensions?.Length).GetValueOrDefault());
            if (certificate.TbsCertificate.Extensions != null)
            {
                foreach (X509ExtensionAsn rawExtension in certificate.TbsCertificate.Extensions)
                {
                    X509Extension extension = new X509Extension(
                        rawExtension.ExtnId,
                        rawExtension.ExtnValue.Span,
                        rawExtension.Critical);

                    Extensions.Add(extension);
                }
            }
#if DEBUG
        }
        catch (Exception e)
        {
            string pem = PemEncoding.WriteString(PemLabels.X509Certificate, rawData);
            throw new CryptographicException($"Error in reading certificate:{Environment.NewLine}{pem}", e);
        }
#endif
        }

        public string GetNameInfo(X509NameType nameType, bool forIssuer)
        {
            // Algorithm behaviors (pseudocode).  When forIssuer is true, replace "Subject" with "Issuer" and
            // SAN (Subject Alternative Names) with IAN (Issuer Alternative Names).
            //
            // SimpleName: Subject[CN] ?? Subject[OU] ?? Subject[O] ?? Subject[E] ?? Subject.Rdns.FirstOrDefault() ??
            // SAN.Entries.FirstOrDefault(type == GEN_EMAIL);
            // EmailName: SAN.Entries.FirstOrDefault(type == GEN_EMAIL) ?? Subject[E];
            // UpnName: SAN.Entries.FirsOrDefaultt(type == GEN_OTHER && entry.AsOther().OID == szOidUpn).AsOther().Value;
            // DnsName: SAN.Entries.FirstOrDefault(type == GEN_DNS) ?? Subject[CN];
            // DnsFromAlternativeName: SAN.Entries.FirstOrDefault(type == GEN_DNS);
            // UrlName: SAN.Entries.FirstOrDefault(type == GEN_URI);

            if (nameType == X509NameType.SimpleName)
            {
                X500DistinguishedName name = forIssuer ? Issuer : Subject;
                string? candidate = GetSimpleNameInfo(name);

                if (candidate != null)
                {
                    return candidate;
                }
            }

            // Check the Subject Alternative Name (or Issuer Alternative Name) for the right value;
            {
                string extensionId = forIssuer ? Oids.IssuerAltName : Oids.SubjectAltName;
                GeneralNameType? matchType = null;
                string? otherOid = null;

                // Currently all X509NameType types have a path where they look at the SAN/IAN,
                // but we need to figure out which kind they want.
                switch (nameType)
                {
                    case X509NameType.DnsName:
                    case X509NameType.DnsFromAlternativeName:
                        matchType = GeneralNameType.DnsName;
                        break;
                    case X509NameType.SimpleName:
                    case X509NameType.EmailName:
                        matchType = GeneralNameType.Email;
                        break;
                    case X509NameType.UpnName:
                        matchType = GeneralNameType.OtherName;
                        otherOid = Oids.UserPrincipalName;
                        break;
                    case X509NameType.UrlName:
                        matchType = GeneralNameType.UniformResourceIdentifier;
                        break;
                }

                if (matchType.HasValue)
                {
                    foreach (X509Extension extension in Extensions)
                    {
                        if (extension.Oid!.Value == extensionId)
                        {
                            string? candidate = FindAltNameMatch(extension.RawData, matchType.Value, otherOid);

                            if (candidate != null)
                            {
                                return candidate;
                            }
                        }
                    }
                }
                else
                {
                    Debug.Fail($"Unresolved matchType for X509NameType.{nameType}");
                }
            }

            // Subject-based fallback
            {
                string? expectedKey = null;

                switch (nameType)
                {
                    case X509NameType.EmailName:
                        expectedKey = Oids.EmailAddress;
                        break;
                    case X509NameType.DnsName:
                        // Note: This does not include DnsFromAlternativeName, since
                        // the subject (or issuer) is not the Alternative Name.
                        expectedKey = Oids.CommonName;
                        break;
                }

                if (expectedKey != null)
                {
                    X500DistinguishedName name = forIssuer ? Issuer : Subject;

                    foreach (var kvp in ReadReverseRdns(name))
                    {
                        if (kvp.Key == expectedKey)
                        {
                            return kvp.Value;
                        }
                    }
                }
            }

            return "";
        }

        private static string? GetSimpleNameInfo(X500DistinguishedName name)
        {
            string? ou = null;
            string? o = null;
            string? e = null;
            string? firstRdn = null;

            foreach (var kvp in ReadReverseRdns(name))
            {
                string oid = kvp.Key;
                string value = kvp.Value;

                // TODO: Check this (and the OpenSSL-using version) if OU/etc are specified more than once.
                // (Compare against Windows)
                switch (oid)
                {
                    case Oids.CommonName:
                        return value;
                    case Oids.OrganizationalUnit:
                        ou = value;
                        break;
                    case Oids.Organization:
                        o = value;
                        break;
                    case Oids.EmailAddress:
                        e = value;
                        break;
                    default:
                        firstRdn ??= value;
                        break;
                }
            }

            return ou ?? o ?? e ?? firstRdn;
        }

        private static string? FindAltNameMatch(byte[] extensionBytes, GeneralNameType matchType, string? otherOid)
        {
            // If Other, have OID, else, no OID.
            Debug.Assert(
                (otherOid == null) == (matchType != GeneralNameType.OtherName),
                $"otherOid has incorrect nullarity for matchType {matchType}");

            Debug.Assert(
                matchType == GeneralNameType.UniformResourceIdentifier ||
                matchType == GeneralNameType.DnsName ||
                matchType == GeneralNameType.Email ||
                matchType == GeneralNameType.OtherName,
                $"matchType ({matchType}) is not currently supported");

            Debug.Assert(
                otherOid == null || otherOid == Oids.UserPrincipalName,
                $"otherOid ({otherOid}) is not supported");

            try
            {
                AsnValueReader reader = new AsnValueReader(extensionBytes, AsnEncodingRules.DER);
                AsnValueReader sequenceReader = reader.ReadSequence();
                reader.ThrowIfNotEmpty();

                while (sequenceReader.HasData)
                {
                    GeneralNameAsn.Decode(ref sequenceReader, extensionBytes, out GeneralNameAsn generalName);

                    switch (matchType)
                    {
                        case GeneralNameType.OtherName:
                            // If the OtherName OID didn't match, move to the next entry.
                            if (generalName.OtherName.HasValue && generalName.OtherName.Value.TypeId == otherOid)
                            {
                                // Currently only UPN is supported, which is a UTF8 string per
                                // https://msdn.microsoft.com/en-us/library/ff842518.aspx
                                AsnValueReader nameReader = new AsnValueReader(
                                    generalName.OtherName.Value.Value.Span,
                                    AsnEncodingRules.DER);

                                string udnName = nameReader.ReadCharacterString(UniversalTagNumber.UTF8String);
                                nameReader.ThrowIfNotEmpty();
                                return udnName;
                            }

                            break;
                        case GeneralNameType.Rfc822Name:
                            if (generalName.Rfc822Name != null)
                            {
                                return generalName.Rfc822Name;
                            }

                            break;
                        case GeneralNameType.DnsName:
                            if (generalName.DnsName != null)
                            {
                                return generalName.DnsName;
                            }

                            break;
                        case GeneralNameType.UniformResourceIdentifier:
                            if (generalName.Uri != null)
                            {
                                return generalName.Uri;
                            }

                            break;
                    }
                }
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }

            return null;
        }

        private static IEnumerable<KeyValuePair<string, string>> ReadReverseRdns(X500DistinguishedName name)
        {
            Stack<AsnReader> rdnReaders;

            try
            {
                AsnReader x500NameReader = new AsnReader(name.RawData, AsnEncodingRules.DER);
                AsnReader sequenceReader = x500NameReader.ReadSequence();
                x500NameReader.ThrowIfNotEmpty();
                rdnReaders = new Stack<AsnReader>();

                while (sequenceReader.HasData)
                {
                    rdnReaders.Push(sequenceReader.ReadSetOf());
                }
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }

            while (rdnReaders.Count > 0)
            {
                AsnReader rdnReader = rdnReaders.Pop();
                while (rdnReader.HasData)
                {
                    string oid;
                    string value;

                    try
                    {
                        AsnReader tavReader = rdnReader.ReadSequence();
                        oid = tavReader.ReadObjectIdentifier();
                        value = tavReader.ReadAnyAsnString();
                        tavReader.ThrowIfNotEmpty();
                    }
                    catch (AsnContentException e)
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
                    }

                    yield return new KeyValuePair<string, string>(oid, value);
                }
            }
        }
    }
}
