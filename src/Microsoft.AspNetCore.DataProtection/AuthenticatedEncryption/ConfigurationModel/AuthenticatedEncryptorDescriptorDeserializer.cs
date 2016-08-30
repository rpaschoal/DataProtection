// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
    /// <summary>
    /// A class that can deserialize an <see cref="XElement"/> that represents the serialized version
    /// of an <see cref="AuthenticatedEncryptorConfiguration"/>.
    /// </summary>
    public sealed class AuthenticatedEncryptorDescriptorDeserializer : IAuthenticatedEncryptorDescriptorDeserializer
    {
        /// <summary>
        /// Imports the <see cref="AuthenticatedEncryptorConfiguration"/> from serialized XML.
        /// </summary>
        public AlgorithmConfiguration ImportFromXml(XElement element)
        {
            if (element == null)
            {
                throw new ArgumentNullException(nameof(element));
            }

            // <descriptor>
            //   <encryption algorithm="..." />
            //   <validation algorithm="..." /> <!-- only if not GCM -->
            //   <masterKey requiresEncryption="true">...</masterKey>
            // </descriptor>

            var configuration = new AuthenticatedEncryptorConfiguration();

            var encryptionElement = element.Element("encryption");
            configuration.EncryptionAlgorithm = (EncryptionAlgorithm)Enum.Parse(typeof(EncryptionAlgorithm), (string)encryptionElement.Attribute("algorithm"));

            // only read <validation> if not GCM
            if (!configuration.IsGcmAlgorithm())
            {
                var validationElement = element.Element("validation");
                configuration.ValidationAlgorithm = (ValidationAlgorithm)Enum.Parse(typeof(ValidationAlgorithm), (string)validationElement.Attribute("algorithm"));
            }

            configuration.MasterKey = ((string)element.Elements("masterKey").Single()).ToSecret();
            return configuration;
        }
    }
}
