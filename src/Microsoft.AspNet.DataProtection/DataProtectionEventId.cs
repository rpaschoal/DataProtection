// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace Microsoft.AspNet.DataProtection
{
    public enum DataProtectionEventId
    {
        KeyServices = 1,
        XmlKeyManager,
        KeyRingProvider,
        CertificateXmlEncryptor,
        DpapiNGXmlEncryptor,
        DpapiNGXmlDecryptor,
        DpapiXmlEncryptor,
        DpapiXmlDecryptor,
        NullXmlDecryptor,
        DefaultKeyResolver,
        RegistryXmlRepository,
        EphemeralXmlRepository,
        FileSystemXmlRepository,
        KeyRingBasedDataProtector,
        EphemeralDataProtectionProvider,
        CngGcmAuthenticatedEncryptionOptions,
        ManagedAuthenticatedEncryptionOptions,
        CngCbcAuthenticatedEncryptionOptions
    }
}
