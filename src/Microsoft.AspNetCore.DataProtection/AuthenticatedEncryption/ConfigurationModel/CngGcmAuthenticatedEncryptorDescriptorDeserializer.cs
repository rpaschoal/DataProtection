// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Xml.Linq;

namespace Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel
{
    /// <summary>
    /// A class that can deserialize an <see cref="XElement"/> that represents the serialized version
    /// of an <see cref="CngGcmAuthenticatedEncryptorConfiguration"/>.
    /// </summary>
    public sealed class CngGcmAuthenticatedEncryptorDescriptorDeserializer : IAuthenticatedEncryptorDescriptorDeserializer
    {
        /// <summary>
        /// Imports the <see cref="CngGcmAuthenticatedEncryptorConfiguration"/> from serialized XML.
        /// </summary>
        public AlgorithmConfiguration ImportFromXml(XElement element)
        {
            if (element == null)
            {
                throw new ArgumentNullException(nameof(element));
            }

            // <descriptor>
            //   <!-- Windows CNG-GCM -->
            //   <encryption algorithm="..." keyLength="..." [provider="..."] />
            //   <masterKey>...</masterKey>
            // </descriptor>

            var configuration = new CngGcmAuthenticatedEncryptorConfiguration();

            var encryptionElement = element.Element("encryption");
            configuration.EncryptionAlgorithm = (string)encryptionElement.Attribute("algorithm");
            configuration.EncryptionAlgorithmKeySize = (int)encryptionElement.Attribute("keyLength");
            configuration.EncryptionAlgorithmProvider = (string)encryptionElement.Attribute("provider"); // could be null

            configuration.MasterKey = ((string)element.Element("masterKey")).ToSecret();

            return configuration;
        }
    }
}
