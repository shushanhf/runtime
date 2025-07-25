// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace System.Net.Security
{
    internal static class SslStreamPal
    {
        private static readonly byte[] s_http1 = Interop.Sec_Application_Protocols.ToByteArray(new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 });
        private static readonly byte[] s_http2 = Interop.Sec_Application_Protocols.ToByteArray(new List<SslApplicationProtocol> { SslApplicationProtocol.Http2 });
        private static readonly byte[] s_http12 = Interop.Sec_Application_Protocols.ToByteArray(new List<SslApplicationProtocol> { SslApplicationProtocol.Http11, SslApplicationProtocol.Http2 });
        private static readonly byte[] s_http21 = Interop.Sec_Application_Protocols.ToByteArray(new List<SslApplicationProtocol> { SslApplicationProtocol.Http2, SslApplicationProtocol.Http11 });

        private static readonly bool UseNewCryptoApi =
            // On newer Windows version we use new API to get TLS1.3.
            // API is supported since Windows 10 1809 (17763) but there is no reason to use at the moment.
            Environment.OSVersion.Version.Major >= 10 && Environment.OSVersion.Version.Build >= 18836;

        private const string SecurityPackage = "Microsoft Unified Security Protocol Provider";

        private const Interop.SspiCli.ContextFlags RequiredFlags =
            Interop.SspiCli.ContextFlags.ReplayDetect |
            Interop.SspiCli.ContextFlags.SequenceDetect |
            Interop.SspiCli.ContextFlags.Confidentiality |
            Interop.SspiCli.ContextFlags.AllocateMemory;

        private const Interop.SspiCli.ContextFlags ServerRequiredFlags =
            RequiredFlags | Interop.SspiCli.ContextFlags.AcceptStream | Interop.SspiCli.ContextFlags.AcceptExtendedError;

        public static Exception GetException(SecurityStatusPal status)
        {
            int win32Code = (int)SecurityStatusAdapterPal.GetInteropFromSecurityStatusPal(status);
            return new Win32Exception(win32Code);
        }

        internal const bool StartMutualAuthAsAnonymous = true;
        internal const bool CanEncryptEmptyMessage = true;
        internal const bool CanGenerateCustomAlerts = true;

        private static readonly byte[] s_sessionTokenBuffer = InitSessionTokenBuffer();

        private static byte[] InitSessionTokenBuffer()
        {
            var schannelSessionToken = new Interop.SChannel.SCHANNEL_SESSION_TOKEN()
            {
                dwTokenType = Interop.SChannel.SCHANNEL_SESSION,
                dwFlags = Interop.SChannel.SSL_SESSION_DISABLE_RECONNECTS,
            };
            return MemoryMarshal.AsBytes(new ReadOnlySpan<Interop.SChannel.SCHANNEL_SESSION_TOKEN>(in schannelSessionToken)).ToArray();
        }

        public static void VerifyPackageInfo()
        {
            SSPIWrapper.GetVerifyPackageInfo(GlobalSSPI.SSPISecureChannel, SecurityPackage, true);
        }

        private static unsafe void SetAlpn(ref InputSecurityBuffers inputBuffers, List<SslApplicationProtocol> alpn, Span<byte> localBuffer)
        {
            if (alpn.Count == 1 && alpn[0] == SslApplicationProtocol.Http11)
            {
                inputBuffers.SetNextBuffer(new InputSecurityBuffer(s_http1, SecurityBufferType.SECBUFFER_APPLICATION_PROTOCOLS));
            }
            else if (alpn.Count == 1 && alpn[0] == SslApplicationProtocol.Http2)
            {
                inputBuffers.SetNextBuffer(new InputSecurityBuffer(s_http2, SecurityBufferType.SECBUFFER_APPLICATION_PROTOCOLS));
            }
            else if (alpn.Count == 2 && alpn[0] == SslApplicationProtocol.Http11 && alpn[1] == SslApplicationProtocol.Http2)
            {
                inputBuffers.SetNextBuffer(new InputSecurityBuffer(s_http12, SecurityBufferType.SECBUFFER_APPLICATION_PROTOCOLS));
            }
            else if (alpn.Count == 2 && alpn[0] == SslApplicationProtocol.Http2 && alpn[1] == SslApplicationProtocol.Http11)
            {
                inputBuffers.SetNextBuffer(new InputSecurityBuffer(s_http21, SecurityBufferType.SECBUFFER_APPLICATION_PROTOCOLS));
            }
            else
            {
                int protocolLength = Interop.Sec_Application_Protocols.GetProtocolLength(alpn);
                int bufferLength = sizeof(Interop.Sec_Application_Protocols) + protocolLength;

                Span<byte> alpnBuffer = bufferLength <= localBuffer.Length ? localBuffer : new byte[bufferLength];
                Interop.Sec_Application_Protocols.SetProtocols(alpnBuffer, alpn, protocolLength);
                inputBuffers.SetNextBuffer(new InputSecurityBuffer(alpnBuffer, SecurityBufferType.SECBUFFER_APPLICATION_PROTOCOLS));
            }
        }

        public static SecurityStatusPal SelectApplicationProtocol(
            SafeFreeCredentials? credentialsHandle,
            SafeDeleteSslContext? context,
            SslAuthenticationOptions sslAuthenticationOptions,
            ReadOnlySpan<byte> clientProtocols)
        {
            throw new PlatformNotSupportedException(nameof(SelectApplicationProtocol));
        }

        public static ProtocolToken AcceptSecurityContext(
            ref SafeFreeCredentials? credentialsHandle,
            ref SafeDeleteSslContext? context,
            ReadOnlySpan<byte> inputBuffer,
            out int consumed,
            SslAuthenticationOptions sslAuthenticationOptions)
        {
            Interop.SspiCli.ContextFlags unusedAttributes = default;

            scoped InputSecurityBuffers inputBuffers = default;
            inputBuffers.SetNextBuffer(new InputSecurityBuffer(inputBuffer, SecurityBufferType.SECBUFFER_TOKEN));
            inputBuffers.SetNextBuffer(new InputSecurityBuffer(default, SecurityBufferType.SECBUFFER_EMPTY));
            if (context == null && sslAuthenticationOptions.ApplicationProtocols != null && sslAuthenticationOptions.ApplicationProtocols.Count != 0)
            {
                Span<byte> localBuffer = stackalloc byte[64];
                SetAlpn(ref inputBuffers, sslAuthenticationOptions.ApplicationProtocols, localBuffer);
            }

            ProtocolToken token = default;
            token.RentBuffer = true;

            int errorCode = SSPIWrapper.AcceptSecurityContext(
                GlobalSSPI.SSPISecureChannel,
                credentialsHandle,
                ref context,
                ServerRequiredFlags | (sslAuthenticationOptions.RemoteCertRequired ? Interop.SspiCli.ContextFlags.MutualAuth : Interop.SspiCli.ContextFlags.Zero),
                Interop.SspiCli.Endianness.SECURITY_NATIVE_DREP,
                ref inputBuffers,
                ref token,
                ref unusedAttributes);

            consumed = inputBuffer.Length;
            if (inputBuffers._item1.Type == SecurityBufferType.SECBUFFER_EXTRA)
            {
                // not all data were consumed
                consumed -= inputBuffers._item1.Token.Length;
            }

            token.Status = SecurityStatusAdapterPal.GetSecurityStatusPalFromNativeInt(errorCode);
            return token;
        }

        public static bool TryUpdateClintCertificate(
            SafeFreeCredentials? _1,
            SafeDeleteSslContext? _2,
            SslAuthenticationOptions _3)
        {
            // We will need to allocate new credential handle
            return false;
        }

        public static ProtocolToken InitializeSecurityContext(
            ref SafeFreeCredentials? credentialsHandle,
            ref SafeDeleteSslContext? context,
            string? targetName,
            ReadOnlySpan<byte> inputBuffer,
            out int consumed,
            SslAuthenticationOptions sslAuthenticationOptions)
        {
            bool newContext = context == null;
            Interop.SspiCli.ContextFlags unusedAttributes = default;

            scoped InputSecurityBuffers inputBuffers = default;
            inputBuffers.SetNextBuffer(new InputSecurityBuffer(inputBuffer, SecurityBufferType.SECBUFFER_TOKEN));
            inputBuffers.SetNextBuffer(new InputSecurityBuffer(default, SecurityBufferType.SECBUFFER_EMPTY));
            if (context == null && sslAuthenticationOptions.ApplicationProtocols != null && sslAuthenticationOptions.ApplicationProtocols.Count != 0)
            {
                Span<byte> localBuffer = stackalloc byte[64];
                SetAlpn(ref inputBuffers, sslAuthenticationOptions.ApplicationProtocols, localBuffer);
            }

            ProtocolToken token = default;
            token.RentBuffer = true;
            int errorCode = SSPIWrapper.InitializeSecurityContext(
                                GlobalSSPI.SSPISecureChannel,
                                ref credentialsHandle,
                                ref context,
                                targetName,
                                RequiredFlags | Interop.SspiCli.ContextFlags.InitManualCredValidation,
                                Interop.SspiCli.Endianness.SECURITY_NATIVE_DREP,
                                ref inputBuffers,
                                ref token,
                                ref unusedAttributes);

            token.Status = SecurityStatusAdapterPal.GetSecurityStatusPalFromNativeInt(errorCode);

            consumed = inputBuffer.Length;
            if (inputBuffers._item1.Type == SecurityBufferType.SECBUFFER_EXTRA)
            {
                // not all data were consumed
                consumed -= inputBuffers._item1.Token.Length;
            }

            bool allowTlsResume = sslAuthenticationOptions.AllowTlsResume && !SslStream.DisableTlsResume;

            if (!allowTlsResume && newContext && context != null)
            {
                var securityBuffer = new SecurityBuffer(s_sessionTokenBuffer, SecurityBufferType.SECBUFFER_TOKEN);

                SecurityStatusPal result = SecurityStatusAdapterPal.GetSecurityStatusPalFromNativeInt(SSPIWrapper.ApplyControlToken(
                    GlobalSSPI.SSPISecureChannel,
                    ref context,
                    in securityBuffer));


                if (result.ErrorCode != SecurityStatusPalErrorCode.OK)
                {
                    token.Status = result;
                }
            }

            return token;
        }

        public static ProtocolToken Renegotiate(
            ref SafeFreeCredentials? credentialsHandle,
            ref SafeDeleteSslContext? context,
            SslAuthenticationOptions sslAuthenticationOptions)
        {
            return AcceptSecurityContext(ref credentialsHandle, ref context, ReadOnlySpan<byte>.Empty, out _, sslAuthenticationOptions);
        }

        public static SafeFreeCredentials AcquireCredentialsHandle(SslAuthenticationOptions sslAuthenticationOptions, bool newCredentialsRequested)
        {
            SslStreamCertificateContext? certificateContext = sslAuthenticationOptions.CertificateContext;

            try
            {
                EncryptionPolicy policy = sslAuthenticationOptions.EncryptionPolicy;

                // New crypto API supports TLS1.3 but it does not allow to force NULL encryption.
#pragma warning disable SYSLIB0040 // NoEncryption and AllowNoEncryption are obsolete
                SafeFreeCredentials cred = !UseNewCryptoApi || policy == EncryptionPolicy.NoEncryption ?
                    AcquireCredentialsHandleSchannelCred(sslAuthenticationOptions) :
                    AcquireCredentialsHandleSchCredentials(sslAuthenticationOptions);
#pragma warning restore SYSLIB0040

                if (certificateContext != null && certificateContext.Trust != null && certificateContext.Trust._sendTrustInHandshake)
                {
                    AttachCertificateStore(cred, certificateContext.Trust._store!);
                }

                // Windows can fail to get local credentials in case of TLS Resume.
                // We will store associated certificate in credentials and use it in case
                // of TLS resume. It will be disposed when the credentials are.
                if (newCredentialsRequested && sslAuthenticationOptions.CertificateContext != null)
                {
                    SafeFreeCredential_SECURITY handle = (SafeFreeCredential_SECURITY)cred;
                    handle.HasLocalCertificate = true;
                }

                return cred;
            }
            catch (Win32Exception e) when (e.NativeErrorCode == (int)Interop.SECURITY_STATUS.NoCredentials && certificateContext != null)
            {
                Debug.Assert(certificateContext.TargetCertificate.HasPrivateKey);
                using SafeCertContextHandle safeCertContextHandle = Interop.Crypt32.CertDuplicateCertificateContext(certificateContext.TargetCertificate.Handle);
                // on Windows we do not support ephemeral keys.
                throw new AuthenticationException(safeCertContextHandle.HasEphemeralPrivateKey ? SR.net_auth_ephemeral : SR.net_auth_SSPI, e);
            }
            catch (Win32Exception e)
            {
                throw new AuthenticationException(SR.net_auth_SSPI, e);
            }
        }

        private static unsafe void AttachCertificateStore(SafeFreeCredentials cred, X509Store store)
        {
            Interop.SspiCli.SecPkgCred_ClientCertPolicy clientCertPolicy = default;
            fixed (char* ptr = store.Name)
            {
                clientCertPolicy.pwszSslCtlStoreName = ptr;
                Interop.SECURITY_STATUS errorCode = Interop.SspiCli.SetCredentialsAttributesW(
                            cred._handle,
                            (long)Interop.SspiCli.ContextAttribute.SECPKG_ATTR_CLIENT_CERT_POLICY,
                            clientCertPolicy,
                            sizeof(Interop.SspiCli.SecPkgCred_ClientCertPolicy));

                if (errorCode != Interop.SECURITY_STATUS.OK)
                {
                    throw new Win32Exception((int)errorCode);
                }
            }

            return;
        }

        // This is legacy crypto API used on .NET Framework and older Windows versions.
        // It only supports TLS up to 1.2
        public static unsafe SafeFreeCredentials AcquireCredentialsHandleSchannelCred(SslAuthenticationOptions authOptions)
        {
            X509Certificate2? certificate = authOptions.CertificateContext?.TargetCertificate;
            bool isServer = authOptions.IsServer;
            int protocolFlags = GetProtocolFlagsFromSslProtocols(authOptions.EnabledSslProtocols, isServer);
            Interop.SspiCli.SCHANNEL_CRED.Flags flags;
            Interop.SspiCli.CredentialUse direction;

            bool allowTlsResume = authOptions.AllowTlsResume && !SslStream.DisableTlsResume;

            if (!isServer)
            {
                direction = Interop.SspiCli.CredentialUse.SECPKG_CRED_OUTBOUND;
                flags =
                    Interop.SspiCli.SCHANNEL_CRED.Flags.SCH_CRED_MANUAL_CRED_VALIDATION |
                    Interop.SspiCli.SCHANNEL_CRED.Flags.SCH_CRED_NO_DEFAULT_CREDS |
                    Interop.SspiCli.SCHANNEL_CRED.Flags.SCH_SEND_AUX_RECORD;

                // Request OCSP Stapling from the server
                if (authOptions.CertificateRevocationCheckMode != X509RevocationMode.NoCheck)
                {
                    flags |=
                        Interop.SspiCli.SCHANNEL_CRED.Flags.SCH_CRED_REVOCATION_CHECK_END_CERT |
                        Interop.SspiCli.SCHANNEL_CRED.Flags.SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
                        Interop.SspiCli.SCHANNEL_CRED.Flags.SCH_CRED_IGNORE_REVOCATION_OFFLINE;
                }
            }
            else
            {
                direction = Interop.SspiCli.CredentialUse.SECPKG_CRED_INBOUND;
                flags =
                    Interop.SspiCli.SCHANNEL_CRED.Flags.SCH_SEND_AUX_RECORD |
                    Interop.SspiCli.SCHANNEL_CRED.Flags.SCH_CRED_NO_SYSTEM_MAPPER;
                if (!allowTlsResume)
                {
                    // Works only on server
                    flags |= Interop.SspiCli.SCHANNEL_CRED.Flags.SCH_CRED_DISABLE_RECONNECTS;
                }
            }

            EncryptionPolicy policy = authOptions.EncryptionPolicy;

#pragma warning disable SYSLIB0040 // NoEncryption and AllowNoEncryption are obsolete
            // Always opt-in SCH_USE_STRONG_CRYPTO for TLS.
            if (((protocolFlags == 0) ||
                    (protocolFlags & ~(Interop.SChannel.SP_PROT_SSL2 | Interop.SChannel.SP_PROT_SSL3)) != 0)
                    && (policy != EncryptionPolicy.AllowNoEncryption) && (policy != EncryptionPolicy.NoEncryption))
            {
                flags |= Interop.SspiCli.SCHANNEL_CRED.Flags.SCH_USE_STRONG_CRYPTO;
            }
#pragma warning restore SYSLIB0040

            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info($"flags=({flags}), ProtocolFlags=({protocolFlags}), EncryptionPolicy={policy}");
            Interop.SspiCli.SCHANNEL_CRED secureCredential = CreateSecureCredential(
                flags,
                protocolFlags,
                policy);

            if (!isServer && !allowTlsResume)
            {
                secureCredential.dwSessionLifespan = -1;
            }

            Interop.Crypt32.CERT_CONTEXT* certificateHandle;
            if (certificate != null)
            {
                secureCredential.cCreds = 1;
                certificateHandle = (Interop.Crypt32.CERT_CONTEXT*)certificate.Handle;
                secureCredential.paCred = &certificateHandle;
            }

            return AcquireCredentialsHandle(direction, &secureCredential);
        }

        // This function uses new crypto API to support TLS 1.3 and beyond.
        public static unsafe SafeFreeCredentials AcquireCredentialsHandleSchCredentials(SslAuthenticationOptions authOptions)
        {
            X509Certificate2? certificate = authOptions.CertificateContext?.TargetCertificate;
            bool isServer = authOptions.IsServer;
            int protocolFlags = GetProtocolFlagsFromSslProtocols(authOptions.EnabledSslProtocols, isServer);
            Interop.SspiCli.SCH_CREDENTIALS.Flags flags;
            Interop.SspiCli.CredentialUse direction;

            bool allowTlsResume = authOptions.AllowTlsResume && !SslStream.DisableTlsResume;

            if (isServer)
            {
                direction = Interop.SspiCli.CredentialUse.SECPKG_CRED_INBOUND;
                flags =
                    Interop.SspiCli.SCH_CREDENTIALS.Flags.SCH_SEND_AUX_RECORD |
                    Interop.SspiCli.SCH_CREDENTIALS.Flags.SCH_CRED_NO_SYSTEM_MAPPER;
                if (!allowTlsResume)
                {
                    // Works only on server
                    flags |= Interop.SspiCli.SCH_CREDENTIALS.Flags.SCH_CRED_DISABLE_RECONNECTS;
                }
            }
            else
            {
                direction = Interop.SspiCli.CredentialUse.SECPKG_CRED_OUTBOUND;
                flags =
                    Interop.SspiCli.SCH_CREDENTIALS.Flags.SCH_CRED_MANUAL_CRED_VALIDATION |
                    Interop.SspiCli.SCH_CREDENTIALS.Flags.SCH_CRED_NO_DEFAULT_CREDS |
                    Interop.SspiCli.SCH_CREDENTIALS.Flags.SCH_SEND_AUX_RECORD;

                // Request OCSP Stapling from the server
                if (authOptions.CertificateRevocationCheckMode != X509RevocationMode.NoCheck)
                {
                    flags |=
                        Interop.SspiCli.SCH_CREDENTIALS.Flags.SCH_CRED_REVOCATION_CHECK_END_CERT |
                        Interop.SspiCli.SCH_CREDENTIALS.Flags.SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
                        Interop.SspiCli.SCH_CREDENTIALS.Flags.SCH_CRED_IGNORE_REVOCATION_OFFLINE;
                }
            }

            EncryptionPolicy policy = authOptions.EncryptionPolicy;

            if (policy == EncryptionPolicy.RequireEncryption)
            {
                // Always opt-in SCH_USE_STRONG_CRYPTO for TLS.
                if ((protocolFlags & Interop.SChannel.SP_PROT_SSL3) == 0)
                {
                    flags |= Interop.SspiCli.SCH_CREDENTIALS.Flags.SCH_USE_STRONG_CRYPTO;
                }
            }
#pragma warning disable SYSLIB0040 // NoEncryption and AllowNoEncryption are obsolete
            else if (policy == EncryptionPolicy.AllowNoEncryption)
            {
                // Allow null encryption cipher in addition to other ciphers.
                flags |= Interop.SspiCli.SCH_CREDENTIALS.Flags.SCH_ALLOW_NULL_ENCRYPTION;
            }
#pragma warning restore SYSLIB0040
            else
            {
                throw new ArgumentException(SR.Format(SR.net_invalid_enum, "EncryptionPolicy"), nameof(policy));
            }

            Interop.SspiCli.SCH_CREDENTIALS credential = default;
            credential.dwVersion = Interop.SspiCli.SCH_CREDENTIALS.CurrentVersion;
            credential.dwFlags = flags;
            if (!isServer && !allowTlsResume)
            {
                credential.dwSessionLifespan = -1;
            }

            Interop.Crypt32.CERT_CONTEXT* certificateHandle;
            if (certificate != null)
            {
                credential.cCreds = 1;
                certificateHandle = (Interop.Crypt32.CERT_CONTEXT*)certificate.Handle;
                credential.paCred = &certificateHandle;
            }

            if (NetEventSource.Log.IsEnabled()) NetEventSource.Info($"flags=({flags}), ProtocolFlags=({protocolFlags}), EncryptionPolicy={policy}");

            Interop.SspiCli.TLS_PARAMETERS tlsParameters = default;
            credential.cTlsParameters = 1;
            credential.pTlsParameters = &tlsParameters;

            if (protocolFlags != 0)
            {
                tlsParameters.grbitDisabledProtocols = (uint)protocolFlags ^ uint.MaxValue;
            }

            Span<Interop.SspiCli.CRYPTO_SETTINGS> cryptoSettings = stackalloc Interop.SspiCli.CRYPTO_SETTINGS[2];

            // init to null ptrs to prevent freeing uninitialized memory in finally block
            Span<IntPtr> algIdPtrs = stackalloc IntPtr[2] { IntPtr.Zero, IntPtr.Zero };
            int cryptoSettingsCount = 0;

            try
            {
                if (!authOptions.AllowRsaPkcs1Padding)
                {
                    algIdPtrs[cryptoSettingsCount] = Marshal.StringToHGlobalUni("SCH_RSA_PKCS_PAD");

                    cryptoSettings[cryptoSettingsCount] = new()
                    {
                        eAlgorithmUsage = Interop.SspiCli.CRYPTO_SETTINGS.TlsAlgorithmUsage.TlsParametersCngAlgUsageCertSig
                    };

                    Interop.NtDll.RtlInitUnicodeString(out cryptoSettings[cryptoSettingsCount].strCngAlgId, algIdPtrs[cryptoSettingsCount]);
                    cryptoSettingsCount++;
                }

                if (!authOptions.AllowRsaPssPadding)
                {
                    algIdPtrs[cryptoSettingsCount] = Marshal.StringToHGlobalUni("SCH_RSA_PSS_PAD");

                    cryptoSettings[cryptoSettingsCount] = new()
                    {
                        eAlgorithmUsage = Interop.SspiCli.CRYPTO_SETTINGS.TlsAlgorithmUsage.TlsParametersCngAlgUsageCertSig
                    };
                    Interop.NtDll.RtlInitUnicodeString(out cryptoSettings[cryptoSettingsCount].strCngAlgId, algIdPtrs[cryptoSettingsCount]);
                    cryptoSettingsCount++;
                }

                tlsParameters.pDisabledCrypto = (Interop.SspiCli.CRYPTO_SETTINGS*)Unsafe.AsPointer(ref MemoryMarshal.GetReference(cryptoSettings));
                tlsParameters.cDisabledCrypto = cryptoSettingsCount;

                return AcquireCredentialsHandle(direction, &credential);
            }
            finally
            {
                foreach (IntPtr algIdPtr in algIdPtrs.Slice(0, cryptoSettingsCount))
                {
                    if (algIdPtr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(algIdPtr);
                    }
                }
            }
        }

        public static unsafe ProtocolToken EncryptMessage(SafeDeleteSslContext securityContext, ReadOnlyMemory<byte> input, int headerSize, int trailerSize)
        {
            ProtocolToken token = default;
            token.RentBuffer = true;

            // Ensure that there is sufficient space for the message output.
            int bufferSizeNeeded = checked(input.Length + headerSize + trailerSize);
            token.EnsureAvailableSpace(bufferSizeNeeded);
            // Copy the input into the output buffer to prepare for SCHANNEL's expectations
            input.Span.CopyTo(token.AvailableSpan.Slice(headerSize, input.Length));

            const int NumSecBuffers = 4; // header + data + trailer + empty
            Span<Interop.SspiCli.SecBuffer> unmanagedBuffers = stackalloc Interop.SspiCli.SecBuffer[NumSecBuffers];
            Interop.SspiCli.SecBufferDesc sdcInOut = new Interop.SspiCli.SecBufferDesc(NumSecBuffers)
            {
                pBuffers = Unsafe.AsPointer(ref MemoryMarshal.GetReference(unmanagedBuffers))
            };
            fixed (byte* outputPtr = token.Payload)
            {
                ref Interop.SspiCli.SecBuffer headerSecBuffer = ref unmanagedBuffers[0];
                headerSecBuffer.BufferType = SecurityBufferType.SECBUFFER_STREAM_HEADER;
                headerSecBuffer.pvBuffer = (IntPtr)outputPtr;
                headerSecBuffer.cbBuffer = headerSize;

                ref Interop.SspiCli.SecBuffer dataSecBuffer = ref unmanagedBuffers[1];
                dataSecBuffer.BufferType = SecurityBufferType.SECBUFFER_DATA;
                dataSecBuffer.pvBuffer = (IntPtr)(outputPtr + headerSize);
                dataSecBuffer.cbBuffer = input.Length;

                ref Interop.SspiCli.SecBuffer trailerSecBuffer = ref unmanagedBuffers[2];
                trailerSecBuffer.BufferType = SecurityBufferType.SECBUFFER_STREAM_TRAILER;
                trailerSecBuffer.pvBuffer = (IntPtr)(outputPtr + headerSize + input.Length);
                trailerSecBuffer.cbBuffer = trailerSize;

                ref Interop.SspiCli.SecBuffer emptySecBuffer = ref unmanagedBuffers[3];
                emptySecBuffer.BufferType = SecurityBufferType.SECBUFFER_EMPTY;
                emptySecBuffer.cbBuffer = 0;
                emptySecBuffer.pvBuffer = IntPtr.Zero;

                int errorCode = GlobalSSPI.SSPISecureChannel.EncryptMessage(securityContext, ref sdcInOut, 0);

                if (errorCode != 0)
                {
                    if (NetEventSource.Log.IsEnabled())
                        NetEventSource.Info(securityContext, $"Encrypt ERROR {errorCode:X}");
                    token.Size = 0;
                    token.Status = SecurityStatusAdapterPal.GetSecurityStatusPalFromNativeInt(errorCode);
                    return token;
                }

                Debug.Assert(headerSecBuffer.cbBuffer >= 0 && dataSecBuffer.cbBuffer >= 0 && trailerSecBuffer.cbBuffer >= 0);
                Debug.Assert(checked(headerSecBuffer.cbBuffer + dataSecBuffer.cbBuffer + trailerSecBuffer.cbBuffer) <= token.Payload!.Length);

                token.Size = checked(headerSecBuffer.cbBuffer + dataSecBuffer.cbBuffer + trailerSecBuffer.cbBuffer);
                token.Status = new SecurityStatusPal(SecurityStatusPalErrorCode.OK);
            }

            return token;
        }

        public static unsafe SecurityStatusPal DecryptMessage(SafeDeleteSslContext? securityContext, Span<byte> buffer, out int offset, out int count)
        {
            const int NumSecBuffers = 4; // data + empty + empty + empty

            Span<Interop.SspiCli.SecBuffer> unmanagedBuffers = stackalloc Interop.SspiCli.SecBuffer[NumSecBuffers];
            for (int i = 1; i < NumSecBuffers; i++)
            {
                ref Interop.SspiCli.SecBuffer emptyBuffer = ref unmanagedBuffers[i];
                emptyBuffer.BufferType = SecurityBufferType.SECBUFFER_EMPTY;
                emptyBuffer.pvBuffer = IntPtr.Zero;
                emptyBuffer.cbBuffer = 0;
            }

            fixed (byte* bufferPtr = buffer)
            {
                ref Interop.SspiCli.SecBuffer dataBuffer = ref unmanagedBuffers[0];
                dataBuffer.BufferType = SecurityBufferType.SECBUFFER_DATA;
                dataBuffer.pvBuffer = (IntPtr)bufferPtr;
                dataBuffer.cbBuffer = buffer.Length;

                Interop.SspiCli.SecBufferDesc sdcInOut = new Interop.SspiCli.SecBufferDesc(NumSecBuffers)
                {
                    pBuffers = Unsafe.AsPointer(ref MemoryMarshal.GetReference(unmanagedBuffers))
                };
                Interop.SECURITY_STATUS errorCode = (Interop.SECURITY_STATUS)GlobalSSPI.SSPISecureChannel.DecryptMessage(securityContext!, ref sdcInOut, out _);

                // Decrypt may repopulate the sec buffers, likely with header + data + trailer + empty.
                // We need to find the data.
                count = 0;
                offset = 0;
                for (int i = 0; i < NumSecBuffers; i++)
                {
                    // Successfully decoded data and placed it at the following position in the buffer,
                    if ((errorCode == Interop.SECURITY_STATUS.OK && unmanagedBuffers[i].BufferType == SecurityBufferType.SECBUFFER_DATA)
                        // or we failed to decode the data, here is the encoded data.
                        || (errorCode != Interop.SECURITY_STATUS.OK && unmanagedBuffers[i].BufferType == SecurityBufferType.SECBUFFER_EXTRA))
                    {
                        offset = (int)((byte*)unmanagedBuffers[i].pvBuffer - bufferPtr);
                        count = unmanagedBuffers[i].cbBuffer;

                        // output is ignored on Windows. We always decrypt in place and we set outputOffset to indicate where the data start.
                        Debug.Assert(offset >= 0 && count >= 0, $"Expected offset and count greater than 0, got {offset} and {count}");
                        Debug.Assert(checked(offset + count) <= buffer.Length, $"Expected offset+count <= buffer.Length, got {offset}+{count}>={buffer.Length}");

                        break;
                    }
                }

                return SecurityStatusAdapterPal.GetSecurityStatusPalFromInterop(errorCode);
            }
        }

        public static SecurityStatusPal ApplyAlertToken(SafeDeleteSslContext? securityContext, TlsAlertType alertType, TlsAlertMessage alertMessage)
        {
            var alertToken = new Interop.SChannel.SCHANNEL_ALERT_TOKEN
            {
                dwTokenType = Interop.SChannel.SCHANNEL_ALERT,
                dwAlertType = (uint)alertType,
                dwAlertNumber = (uint)alertMessage
            };
            byte[] buffer = MemoryMarshal.AsBytes(new ReadOnlySpan<Interop.SChannel.SCHANNEL_ALERT_TOKEN>(in alertToken)).ToArray();
            var securityBuffer = new SecurityBuffer(buffer, SecurityBufferType.SECBUFFER_TOKEN);

            var errorCode = (Interop.SECURITY_STATUS)SSPIWrapper.ApplyControlToken(
                GlobalSSPI.SSPISecureChannel,
                ref securityContext,
                in securityBuffer);

            return SecurityStatusAdapterPal.GetSecurityStatusPalFromInterop(errorCode, attachException: true);
        }

        private static readonly byte[] s_schannelShutdownBytes = BitConverter.GetBytes(Interop.SChannel.SCHANNEL_SHUTDOWN);

        public static SecurityStatusPal ApplyShutdownToken(SafeDeleteSslContext? securityContext)
        {
            var securityBuffer = new SecurityBuffer(s_schannelShutdownBytes, SecurityBufferType.SECBUFFER_TOKEN);

            var errorCode = (Interop.SECURITY_STATUS)SSPIWrapper.ApplyControlToken(
                GlobalSSPI.SSPISecureChannel,
                ref securityContext,
                in securityBuffer);

            return SecurityStatusAdapterPal.GetSecurityStatusPalFromInterop(errorCode, attachException: true);
        }

        public static SafeFreeContextBufferChannelBinding? QueryContextChannelBinding(SafeDeleteContext securityContext, ChannelBindingKind attribute)
        {
            return SSPIWrapper.QueryContextChannelBinding(GlobalSSPI.SSPISecureChannel, securityContext, (Interop.SspiCli.ContextAttribute)attribute);
        }

        public static void QueryContextStreamSizes(SafeDeleteContext securityContext, out StreamSizes streamSizes)
        {
            SecPkgContext_StreamSizes interopStreamSizes = default;
            bool success = SSPIWrapper.QueryBlittableContextAttributes(GlobalSSPI.SSPISecureChannel, securityContext, Interop.SspiCli.ContextAttribute.SECPKG_ATTR_STREAM_SIZES, ref interopStreamSizes);
            Debug.Assert(success);
            streamSizes = new StreamSizes(interopStreamSizes);
        }

        public static void QueryContextConnectionInfo(SafeDeleteContext securityContext, ref SslConnectionInfo connectionInfo)
        {
            connectionInfo.UpdateSslConnectionInfo(securityContext);
        }

        private static int GetProtocolFlagsFromSslProtocols(SslProtocols protocols, bool isServer)
        {
            int protocolFlags = (int)protocols;

            if (isServer)
            {
                protocolFlags &= Interop.SChannel.ServerProtocolMask;
            }
            else
            {
                protocolFlags &= Interop.SChannel.ClientProtocolMask;
            }

            return protocolFlags;
        }

        private static Interop.SspiCli.SCHANNEL_CRED CreateSecureCredential(
            Interop.SspiCli.SCHANNEL_CRED.Flags flags,
            int protocols, EncryptionPolicy policy)
        {
            var credential = new Interop.SspiCli.SCHANNEL_CRED()
            {
                hRootStore = IntPtr.Zero,
                aphMappers = IntPtr.Zero,
                palgSupportedAlgs = IntPtr.Zero,
                paCred = null,
                cCreds = 0,
                cMappers = 0,
                cSupportedAlgs = 0,
                dwSessionLifespan = 0,
                reserved = 0,
                dwVersion = Interop.SspiCli.SCHANNEL_CRED.CurrentVersion
            };

            if (policy == EncryptionPolicy.RequireEncryption)
            {
                // Prohibit null encryption cipher.
                credential.dwMinimumCipherStrength = 0;
                credential.dwMaximumCipherStrength = 0;
            }
#pragma warning disable SYSLIB0040 // NoEncryption and AllowNoEncryption are obsolete
            else if (policy == EncryptionPolicy.AllowNoEncryption)
            {
                // Allow null encryption cipher in addition to other ciphers.
                credential.dwMinimumCipherStrength = -1;
                credential.dwMaximumCipherStrength = 0;
            }
            else if (policy == EncryptionPolicy.NoEncryption)
            {
                // Suppress all encryption and require null encryption cipher only
                credential.dwMinimumCipherStrength = -1;
                credential.dwMaximumCipherStrength = -1;
            }
#pragma warning restore SYSLIB0040
            else
            {
                throw new ArgumentException(SR.Format(SR.net_invalid_enum, "EncryptionPolicy"), nameof(policy));
            }

            credential.dwFlags = flags;
            credential.grbitEnabledProtocols = protocols;

            return credential;
        }

        //
        // Security: we temporarily reset thread token to open the handle under process account.
        //
        private static unsafe SafeFreeCredentials AcquireCredentialsHandle(Interop.SspiCli.CredentialUse credUsage, Interop.SspiCli.SCHANNEL_CRED* secureCredential)
        {
            // First try without impersonation, if it fails, then try the process account.
            // I.E. We don't know which account the certificate context was created under.
            try
            {
                //
                // For app-compat we want to ensure the credential are accessed under >>process<< account.
                //
                using SafeAccessTokenHandle invalidHandle = SafeAccessTokenHandle.InvalidHandle;
                return WindowsIdentity.RunImpersonated<SafeFreeCredentials>(invalidHandle, () =>
                {
                    return SSPIWrapper.AcquireCredentialsHandle(GlobalSSPI.SSPISecureChannel, SecurityPackage, credUsage, secureCredential);
                });
            }
            catch
            {
                return SSPIWrapper.AcquireCredentialsHandle(GlobalSSPI.SSPISecureChannel, SecurityPackage, credUsage, secureCredential);
            }
        }

        private static unsafe SafeFreeCredentials AcquireCredentialsHandle(Interop.SspiCli.CredentialUse credUsage, Interop.SspiCli.SCH_CREDENTIALS* secureCredential)
        {
            // First try without impersonation, if it fails, then try the process account.
            // I.E. We don't know which account the certificate context was created under.
            try
            {
                //
                // For app-compat we want to ensure the credential are accessed under >>process<< account.
                //
                using SafeAccessTokenHandle invalidHandle = SafeAccessTokenHandle.InvalidHandle;
                return WindowsIdentity.RunImpersonated<SafeFreeCredentials>(invalidHandle, () =>
                {
                    return SSPIWrapper.AcquireCredentialsHandle(GlobalSSPI.SSPISecureChannel, SecurityPackage, credUsage, secureCredential);
                });
            }
            catch
            {
                return SSPIWrapper.AcquireCredentialsHandle(GlobalSSPI.SSPISecureChannel, SecurityPackage, credUsage, secureCredential);
            }
        }

    }
}
