// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;

namespace Microsoft.AspNetCore.DataProtection.KeyManagement.Internal
{
    public interface IKeyRingProvider
    {
        IEnumerable<IAuthenticatedEncryptorFactory> EncryptorFactories { get; set; }

        IKeyRing GetCurrentKeyRing();
    }
}
