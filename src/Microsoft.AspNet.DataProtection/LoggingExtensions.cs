// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Runtime.CompilerServices;
using Microsoft.AspNet.DataProtection;
using Microsoft.Extensions.Logging.Internal;

namespace Microsoft.Extensions.Logging
{
    /// <summary>
    /// Helpful extension methods on <see cref="ILogger"/>.
    /// Methods ending in *F take <see cref="FormattableString"/> as a parameter.
    /// </summary>
    internal static class LoggingExtensions
    {
        /// <summary>
        /// Returns a value stating whether the 'debug' log level is enabled.
        /// Returns false if the logger instance is null.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsDebugLevelEnabled(this ILogger logger)
        {
            return IsLogLevelEnabledCore(logger, LogLevel.Debug);
        }

        /// <summary>
        /// Returns a value stating whether the 'error' log level is enabled.
        /// Returns false if the logger instance is null.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsErrorLevelEnabled(this ILogger logger)
        {
            return IsLogLevelEnabledCore(logger, LogLevel.Error);
        }

        /// <summary>
        /// Returns a value stating whether the 'information' log level is enabled.
        /// Returns false if the logger instance is null.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsInformationLevelEnabled(this ILogger logger)
        {
            return IsLogLevelEnabledCore(logger, LogLevel.Information);
        }

        /// <summary>
        /// Returns a value stating whether the 'verbose' log level is enabled.
        /// Returns false if the logger instance is null.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsVerboseLevelEnabled(this ILogger logger)
        {
            return IsLogLevelEnabledCore(logger, LogLevel.Verbose);
        }

        /// <summary>
        /// Returns a value stating whether the 'warning' log level is enabled.
        /// Returns false if the logger instance is null.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsWarningLevelEnabled(this ILogger logger)
        {
            return IsLogLevelEnabledCore(logger, LogLevel.Warning);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsLogLevelEnabledCore(ILogger logger, LogLevel level)
        {
            return (logger != null && logger.IsEnabled(level));
        }

        public static void LogDebug(this ILogger logger, DataProtectionEventId eventId, FormattableString message)
        {
            logger.LogDebug((int)eventId, message.Format, message.GetArguments());
        }

        public static void LogDebug(this ILogger logger, DataProtectionEventId eventId, string message)
        {
            logger.LogDebug((int)eventId, message);
        }

        public static void LogDebug(this ILogger logger, DataProtectionEventId eventId, Exception error, FormattableString message)
        {
            logger.LogDebug((int)eventId, new FormattedLogValues(message.Format, message.GetArguments()), error);
        }

        public static void LogError(this ILogger logger, DataProtectionEventId eventId, string message)
        {
            logger.LogError((int)eventId, message);
        }

        public static void LogError(this ILogger logger, DataProtectionEventId eventId, Exception error, string message)
        {
            logger.LogError((int)eventId, message, error);
        }

        public static void LogError(this ILogger logger, DataProtectionEventId eventId, Exception error, FormattableString message)
        {
            logger.LogError((int)eventId, new FormattedLogValues(message.Format, message.GetArguments()), error);
        }

        public static void LogInformation(this ILogger logger, DataProtectionEventId eventId, FormattableString message)
        {
            logger.LogInformation((int)eventId, message.Format, message.GetArguments());
        }

        public static void LogInformation(this ILogger logger, DataProtectionEventId eventId, string message)
        {
            logger.LogInformation((int)eventId, message);
        }

        public static void LogVerbose(this ILogger logger, DataProtectionEventId eventId, FormattableString message)
        {
            logger.LogVerbose((int)eventId, message.Format, message.GetArguments());
        }
        public static void LogVerbose(this ILogger logger, DataProtectionEventId eventId, string message)
        {
            logger.LogVerbose((int)eventId, message);
        }

        public static void LogWarning(this ILogger logger, DataProtectionEventId eventId, FormattableString message)
        {
            logger.LogWarning((int)eventId, message.Format, message.GetArguments());
        }
        public static void LogWarning(this ILogger logger, DataProtectionEventId eventId, string message)
        {
            logger.LogWarning((int)eventId, message);
        }

        public static void LogWarning(this ILogger logger, DataProtectionEventId eventId, Exception error, FormattableString message)
        {
            logger.LogWarning((int)eventId, new FormattedLogValues(message.Format, message.GetArguments()), error);
        }

        public static void LogWarning(this ILogger logger, DataProtectionEventId eventId, Exception error, string message)
        {
            logger.LogWarning((int)eventId, message, error);
        }
    }
}
