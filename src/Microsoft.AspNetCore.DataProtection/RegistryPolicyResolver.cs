// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using Microsoft.AspNetCore.Cryptography;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.Internal;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Microsoft.AspNetCore.DataProtection
{
    /// <summary>
    /// A type which allows reading policy from the system registry.
    /// </summary>
    internal sealed class RegistryPolicyResolver
    {
        private readonly RegistryKey _policyRegKey;
        private readonly IActivator _activator;
        private readonly ILoggerFactory _loggerFactory;

        internal RegistryPolicyResolver(RegistryKey policyRegKey, IActivator activator, ILoggerFactory loggerFactory)
        {
            _policyRegKey = policyRegKey;
            _activator = activator;
            _loggerFactory = loggerFactory;
        }

        // populates an options object from values stored in the registry
        private static void PopulateOptions(object options, RegistryKey key)
        {
            foreach (PropertyInfo propInfo in options.GetType().GetProperties())
            {
                if (propInfo.IsDefined(typeof(ApplyPolicyAttribute)))
                {
                    var valueFromRegistry = key.GetValue(propInfo.Name);
                    if (valueFromRegistry != null)
                    {
                        if (propInfo.PropertyType == typeof(string))
                        {
                            propInfo.SetValue(options, Convert.ToString(valueFromRegistry, CultureInfo.InvariantCulture));
                        }
                        else if (propInfo.PropertyType == typeof(int))
                        {
                            propInfo.SetValue(options, Convert.ToInt32(valueFromRegistry, CultureInfo.InvariantCulture));
                        }
                        else if (propInfo.PropertyType == typeof(Type))
                        {
                            propInfo.SetValue(options, Type.GetType(Convert.ToString(valueFromRegistry, CultureInfo.InvariantCulture), throwOnError: true));
                        }
                        else
                        {
                            throw CryptoUtil.Fail("Unexpected type on property: " + propInfo.Name);
                        }
                    }
                }
            }
        }

        private static List<string> ReadKeyEscrowSinks(RegistryKey key)
        {
            List<string> sinks = new List<string>();

            // The format of this key is "type1; type2; ...".
            // We call Type.GetType to perform an eager check that the type exists.
            string sinksFromRegistry = (string)key.GetValue("KeyEscrowSinks");
            if (sinksFromRegistry != null)
            {
                foreach (string sinkFromRegistry in sinksFromRegistry.Split(';'))
                {
                    var candidate = sinkFromRegistry.Trim();
                    if (!String.IsNullOrEmpty(candidate))
                    {
                        typeof(IKeyEscrowSink).AssertIsAssignableFrom(Type.GetType(candidate, throwOnError: true));
                        sinks.Add(candidate);
                    }
                }
            }

            return sinks;
        }

        /// <summary>
        /// Returns a <see cref="RegistryPolicyContext"/> from the default registry location.
        /// </summary>
        public static RegistryPolicyContext ResolveDefaultPolicy(IActivator activator, ILoggerFactory loggerFactory)
        {
            var subKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\DotNetPackages\Microsoft.AspNetCore.DataProtection");
            if (subKey != null)
            {
                using (subKey)
                {
                    return new RegistryPolicyResolver(subKey, activator, loggerFactory).ResolvePolicy();
                }
            }

            return null;
        }

        internal RegistryPolicyContext ResolvePolicy()
        {
            return ResolvePolicyCore(); // fully evaluate enumeration while the reg key is open
        }

        private RegistryPolicyContext ResolvePolicyCore()
        {
            // Read the encryption options type: CNG-CBC, CNG-GCM, Managed
            IInternalAuthenticatedEncryptionSettings options = null;
            IAuthenticatedEncryptorConfiguration configuration = null;

            var encryptionType = (string)_policyRegKey.GetValue("EncryptionType");
            if (String.Equals(encryptionType, "CNG-CBC", StringComparison.OrdinalIgnoreCase))
            {
                options = new CngCbcAuthenticatedEncryptionSettings();
            }
            else if (String.Equals(encryptionType, "CNG-GCM", StringComparison.OrdinalIgnoreCase))
            {
                options = new CngGcmAuthenticatedEncryptionSettings();
            }
            else if (String.Equals(encryptionType, "Managed", StringComparison.OrdinalIgnoreCase))
            {
                options = new ManagedAuthenticatedEncryptionSettings();
            }
            else if (!String.IsNullOrEmpty(encryptionType))
            {
                throw CryptoUtil.Fail("Unrecognized EncryptionType: " + encryptionType);
            }
            if (options != null)
            {
                PopulateOptions(options, _policyRegKey);
                configuration = options.ToConfiguration(_loggerFactory);
            }

            // Read ancillary data

            var defaultKeyLifetime = (int?)_policyRegKey.GetValue("DefaultKeyLifetime");

            var keyEscrowSinks = ReadKeyEscrowSinks(_policyRegKey).Select(item => _activator.CreateInstance<IKeyEscrowSink>(item));

            return new RegistryPolicyContext(configuration, keyEscrowSinks, defaultKeyLifetime);
        }
    }
}
