// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography;
using System.Xml.Linq;
using Microsoft.AspNetCore.Cryptography.Cng;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
    /// <summary>
    /// Represents a generalized authenticated encryption mechanism.
    /// </summary>
    public sealed class AuthenticatedEncryptorConfiguration : AlgorithmConfiguration
    {
        /// <summary>
        /// The algorithm to use for symmetric encryption (confidentiality).
        /// </summary>
        /// <remarks>
        /// The default value is <see cref="EncryptionAlgorithm.AES_256_CBC"/>.
        /// </remarks>
        public EncryptionAlgorithm EncryptionAlgorithm { get; set; } = EncryptionAlgorithm.AES_256_CBC;

        /// <summary>
        /// The algorithm to use for message authentication (tamper-proofing).
        /// </summary>
        /// <remarks>
        /// The default value is <see cref="ValidationAlgorithm.HMACSHA256"/>.
        /// This property is ignored if <see cref="EncryptionAlgorithm"/> specifies a 'GCM' algorithm.
        /// </remarks>
        public ValidationAlgorithm ValidationAlgorithm { get; set; } = ValidationAlgorithm.HMACSHA256;

        internal override ISecret MasterKey { get; set; }

        public override XmlSerializedDescriptorInfo ExportToXml()
        {
            return ExportToXml(Secret.Random(KDK_SIZE_IN_BYTES));
        }

        internal override XmlSerializedDescriptorInfo ExportToXml(ISecret masterKey)
        {
            MasterKey = masterKey;

            // <descriptor>
            //   <encryption algorithm="..." />
            //   <validation algorithm="..." /> <!-- only if not GCM -->
            //   <masterKey requiresEncryption="true">...</masterKey>
            // </descriptor>

            var encryptionElement = new XElement("encryption",
                new XAttribute("algorithm", EncryptionAlgorithm));

            var validationElement = (this.IsGcmAlgorithm())
                ? (object)new XComment(" AES-GCM includes a 128-bit authentication tag, no extra validation algorithm required. ")
                : (object)new XElement("validation",
                    new XAttribute("algorithm", ValidationAlgorithm));

            var outerElement = new XElement("descriptor",
                encryptionElement,
                validationElement,
                masterKey.ToMasterKeyElement());

            return new XmlSerializedDescriptorInfo(outerElement, typeof(AuthenticatedEncryptorDescriptorDeserializer));
        }

        internal override void Validate()
        {
            var loggerFactory = DataProtectionProviderFactory.GetDefaultLoggerFactory();
            var sampleSecret = Secret.Random(512 / 8);
            IAuthenticatedEncryptor encryptor = null;

            try
            {
                // Run a sample payload through an encrypt -> decrypt operation to make sure data round-trips properly.
                if (IsGcmAlgorithm())
                {
                    // GCM requires CNG, and CNG is only supported on Windows.
                    if (!OSVersionUtil.IsWindows())
                    {
                        throw new PlatformNotSupportedException(Resources.Platform_WindowsRequiredForGcm);
                    }
                    encryptor = new CngGcmAuthenticatedEncryptorFactory(this, loggerFactory).CreateAuthenticatedEncryptorInstance(sampleSecret);
                }
                else
                {
                    if (OSVersionUtil.IsWindows())
                    {
                        // CNG preferred over managed implementations if running on Windows
                        encryptor = new CngCbcAuthenticatedEncryptorFactory(this, loggerFactory).CreateAuthenticatedEncryptorInstance(sampleSecret);
                    }
                    else
                    {
                        // Use managed implementations as a fallback
                        encryptor = new ManagedAuthenticatedEncryptorFactory(this, loggerFactory).CreateAuthenticatedEncryptorInstance(sampleSecret);
                    }
                }

                encryptor.PerformSelfTest();
            }
            finally
            {
                (encryptor as IDisposable)?.Dispose();
            }
        }

        public bool IsGcmAlgorithm()
        {
            return (EncryptionAlgorithm.AES_128_GCM <= EncryptionAlgorithm && EncryptionAlgorithm <= EncryptionAlgorithm.AES_256_GCM);
        }

        public int GetAlgorithmKeySizeInBits()
        {
            switch (EncryptionAlgorithm)
            {
                case EncryptionAlgorithm.AES_128_CBC:
                case EncryptionAlgorithm.AES_128_GCM:
                    return 128;

                case EncryptionAlgorithm.AES_192_CBC:
                case EncryptionAlgorithm.AES_192_GCM:
                    return 192;

                case EncryptionAlgorithm.AES_256_CBC:
                case EncryptionAlgorithm.AES_256_GCM:
                    return 256;

                default:
                    throw new ArgumentOutOfRangeException(nameof(EncryptionAlgorithm));
            }
        }

        public string GetBCryptAlgorithmNameFromEncryptionAlgorithm()
        {
            switch (EncryptionAlgorithm)
            {
                case EncryptionAlgorithm.AES_128_CBC:
                case EncryptionAlgorithm.AES_192_CBC:
                case EncryptionAlgorithm.AES_256_CBC:
                case EncryptionAlgorithm.AES_128_GCM:
                case EncryptionAlgorithm.AES_192_GCM:
                case EncryptionAlgorithm.AES_256_GCM:
                    return Constants.BCRYPT_AES_ALGORITHM;

                default:
                    throw new ArgumentOutOfRangeException(nameof(EncryptionAlgorithm));
            }
        }

        public string GetBCryptAlgorithmNameFromValidationAlgorithm()
        {
            switch (ValidationAlgorithm)
            {
                case ValidationAlgorithm.HMACSHA256:
                    return Constants.BCRYPT_SHA256_ALGORITHM;

                case ValidationAlgorithm.HMACSHA512:
                    return Constants.BCRYPT_SHA512_ALGORITHM;

                default:
                    throw new ArgumentOutOfRangeException(nameof(ValidationAlgorithm));
            }
        }

        public Type GetManagedTypeFromEncryptionAlgorithm()
        {
            switch (EncryptionAlgorithm)
            {
                case EncryptionAlgorithm.AES_128_CBC:
                case EncryptionAlgorithm.AES_192_CBC:
                case EncryptionAlgorithm.AES_256_CBC:
                case EncryptionAlgorithm.AES_128_GCM:
                case EncryptionAlgorithm.AES_192_GCM:
                case EncryptionAlgorithm.AES_256_GCM:
                    return typeof(Aes);

                default:
                    throw new ArgumentOutOfRangeException(nameof(EncryptionAlgorithm));
            }
        }

        public Type GetManagedTypeFromValidationAlgorithm()
        {
            switch (ValidationAlgorithm)
            {
                case ValidationAlgorithm.HMACSHA256:
                    return typeof(HMACSHA256);

                case ValidationAlgorithm.HMACSHA512:
                    return typeof(HMACSHA512);

                default:
                    throw new ArgumentOutOfRangeException(nameof(ValidationAlgorithm));
            }
        }
    }
}
