// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.DataProtection.Internal;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.DataProtection
{
    /// <summary>
    /// A simplified default implementation of <see cref="IActivator"/> that understands
    /// how to call ctors which take <see cref="ILoggerFactory"/>.
    /// </summary>
    internal sealed class SimpleActivator : IActivator
    {
        private readonly ILoggerFactory _loggerFactory;

        public SimpleActivator(ILoggerFactory loggerFactory)
        {
            _loggerFactory = loggerFactory;
        }

        public object CreateInstance(Type expectedBaseType, string implementationTypeName)
        {
            // Would the assignment even work?
            var implementationType = Type.GetType(implementationTypeName, throwOnError: true);
            expectedBaseType.AssertIsAssignableFrom(implementationType);

            // If no ILoggerFactory was specified, prefer .ctor() [if it exists]
            if (_loggerFactory == null)
            {
                var ctorParameterless = implementationType.GetConstructor(Type.EmptyTypes);
                if (ctorParameterless != null)
                {
                    return Activator.CreateInstance(implementationType);
                }
            }

            // If an ILoggerFactory was specified or if .ctor() doesn't exist, prefer .ctor(ILoggerFactory) [if it exists]
            var ctorWhichTakesLoggerFactory = implementationType.GetConstructor(new Type[] { typeof(ILoggerFactory) });
            if (ctorWhichTakesLoggerFactory != null)
            {
                return ctorWhichTakesLoggerFactory.Invoke(new[] { _loggerFactory });
            }

            // Finally, prefer .ctor() as an ultimate fallback.
            // This will throw if the ctor cannot be called.
            return Activator.CreateInstance(implementationType);
        }
    }
}
