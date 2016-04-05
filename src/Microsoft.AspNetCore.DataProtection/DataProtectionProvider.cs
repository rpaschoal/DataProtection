// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Cryptography.Cng;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.Cng;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Microsoft.AspNetCore.DataProtection
{
    public abstract class DataProtectionProvider : IDataProtectionProvider
    {
        public abstract IDataProtector CreateProtector(string purpose);

        public static IDataProtectionProvider Create(DataProtectionOptions dataProtectionOptions, KeyManagementOptions keyManagementOptions)
        {
            var loggerFactory = new LoggerFactory();
            var authenticatedEncryptorConfiguration =
                ((IInternalAuthenticatedEncryptionSettings)new AuthenticatedEncryptionSettings(loggerFactory)).ToConfiguration();

            IXmlRepository xmlRepository = null;
            IXmlEncryptor xmlEncryptor = null;

            // If we're running in Azure Web Sites, the key repository goes in the %HOME% directory.
            var azureWebSitesKeysFolder = FileSystemXmlRepository.GetKeyStorageDirectoryForAzureWebSites();
            if (azureWebSitesKeysFolder != null)
            {
                // Cloud DPAPI isn't yet available, so we don't encrypt keys at rest.
                // This isn't all that different than what Azure Web Sites does today, and we can always add this later.
                xmlRepository = new FileSystemXmlRepository(azureWebSitesKeysFolder, loggerFactory);
            }
            else
            {
                // If the user profile is available, store keys in the user profile directory.
                var localAppDataKeysFolder = FileSystemXmlRepository.DefaultKeyStorageDirectory;
                if (localAppDataKeysFolder != null)
                {
                    if (OSVersionUtil.IsWindows())
                    {
                        // If the user profile is available, we can protect using DPAPI.
                        // Probe to see if protecting to local user is available, and use it as the default if so.
                        xmlEncryptor = new DpapiXmlEncryptor(!DpapiSecretSerializerHelper.CanProtectToCurrentUserAccount(), loggerFactory);
                    }

                    xmlRepository = new FileSystemXmlRepository(localAppDataKeysFolder, loggerFactory);
                }
                else
                {
                    RegistryKey defaultRegistryKey = RegistryXmlRepository.DefaultRegistryKey;
                    // Use profile isn't available - can we use the HKLM registry?
                    if (OSVersionUtil.IsWindows() && defaultRegistryKey != null)
                    {
                        // If the user profile isn't available, we can protect using DPAPI (to machine).
                        xmlEncryptor = new DpapiXmlEncryptor(protectToLocalMachine: true, loggerFactory: loggerFactory);
                        xmlRepository = new RegistryXmlRepository(defaultRegistryKey, loggerFactory);
                    }
                    else
                    {
                        // Final fallback - use an ephemeral repository since we don't know where else to go.
                        // This can only be used for development scenarios.
                        xmlRepository = new EphemeralXmlRepository(loggerFactory);
                    }
                }
            }

            var keyManager = new XmlKeyManager(
                repository: xmlRepository,
                configuration: authenticatedEncryptorConfiguration,
                keyEncryptor: xmlEncryptor,
                internalXmlKeyManager: null,
                escrowSinks: null,
                loggerFactory: loggerFactory,
                activator: new SimpleActivator(loggerFactory));

            var defaultKeyResolver = new DefaultKeyResolver(keyManagementOptions.KeyPropagationWindow, keyManagementOptions.MaxServerClockSkew, loggerFactory);
            var keyRingProvider = new KeyRingProvider(keyManager, keyManagementOptions, defaultKeyResolver, loggerFactory);

            IDataProtectionProvider dataProtectionProvider = new KeyRingBasedDataProtectionProvider(keyRingProvider, loggerFactory);
            if (!string.IsNullOrEmpty(dataProtectionOptions.ApplicationDiscriminator))
            {
                dataProtectionProvider = dataProtectionProvider.CreateProtector(dataProtectionOptions.ApplicationDiscriminator);
            }

            return dataProtectionProvider;
        }
    }
}
