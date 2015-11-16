// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Internal;
using Microsoft.AspNet.DataProtection.KeyManagement;

namespace Microsoft.Extensions.Logging
{
    /// <summary>
    /// Helpful extension methods on <see cref="ILogger"/>.
    /// Methods ending in *F take <see cref="FormattableString"/> as a parameter.
    /// </summary>
    internal static class LoggingExtensions
    {

        private static Action<ILogger, string, string, Exception> _oppeningCngAlgoritmHmac;
        private static Action<ILogger, string, string, Exception> _oppeningCngAlgoritmCbc;
        private static Action<ILogger, string, string, Exception> _oppeningCngAlgoritmCgm;
        private static Action<ILogger, string, Exception> _usingManagedKeyedHashAlgoritm;
        private static Action<ILogger, string, Exception> _usingManagedSymmetricAlgoritm;
        private static Action<ILogger, Guid, Exception> _keyCreateEncryptorInstanceFailed;
        private static Action<ILogger, Guid, DateTimeOffset, Exception> _consideringDefaultKey;
        private static Action<ILogger, Guid, Exception> _notConsideringDefaultKey;
        private static Action<ILogger, Guid, string, Exception> _performingProtect;
        private static Action<ILogger, Guid, string, Exception> _performingUnprotect;
        private static Action<ILogger, Guid, Exception> _keyNotFoundInKeyRing;
        private static Action<ILogger, Guid, Exception> _keyRevokedProceeding;
        private static Action<ILogger, Guid, Exception> _keyRevokedNotProceeding;

        static LoggingExtensions()
        {
            _oppeningCngAlgoritmHmac = LoggerMessage.Define<string, string>(
                logLevel: LogLevel.Verbose,
                eventId: 1,
                formatString: "Opening CNG algorithm '{HashAlgorithm}' from provider '{HashAlgorithmProvider}' with HMAC.");


            _oppeningCngAlgoritmCbc = LoggerMessage.Define<string, string>(
                logLevel: LogLevel.Verbose,
                eventId: 1,
                formatString: "Opening CNG algorithm '{EncryptionAlgorithm}' from provider '{EncryptionAlgorithmProvider}' with chaining mode CBC.");


            _oppeningCngAlgoritmCgm = LoggerMessage.Define<string, string>(
                logLevel: LogLevel.Verbose,
                eventId: 1,
                formatString: "Opening CNG algorithm '{EncryptionAlgorithm}' from provider '{EncryptionAlgorithmProvider}' with chaining mode GCM.");

            _usingManagedKeyedHashAlgoritm = LoggerMessage.Define<string>(
                logLevel: LogLevel.Verbose,
                eventId: 1,
                formatString: "Using managed keyed hash algorithm '{ValidationAlgorithmType}'.");

            _usingManagedSymmetricAlgoritm = LoggerMessage.Define<string>(
                logLevel: LogLevel.Verbose,
                eventId: 1,
                formatString: "Using managed symmetric algorithm '{EncryptionAlgorithmType}'.");

            _keyCreateEncryptorInstanceFailed = LoggerMessage.Define<Guid>(
                logLevel: LogLevel.Warning,
                eventId: 1,
                formatString: $"Key {{KeyId:B}} is ineligible to be the default key because its {nameof(IKey.CreateEncryptorInstance)} method failed.");

            _consideringDefaultKey = LoggerMessage.Define<Guid, DateTimeOffset>(
                logLevel: LogLevel.Verbose,
                eventId: 1,
                formatString: "Considering key {KeyId:B} with expiration date {ExpirationDate:u} as default key..");

            _notConsideringDefaultKey = LoggerMessage.Define<Guid>(
                logLevel: LogLevel.Verbose,
                eventId: 1,
                formatString: "Key {KeyId:B} is no longer under consideration as default key because it is expired, revoked, or cannot be deciphered.");

            _performingProtect = LoggerMessage.Define<Guid, string>(
                logLevel: LogLevel.Debug,
                eventId: 1,
                formatString: "Performing protect operation to key {KeyId:B} with purposes {Purposes}.");

            _performingUnprotect = LoggerMessage.Define<Guid, string>(
                  logLevel: LogLevel.Debug,
                  eventId: 1,
                  formatString: "Performing unprotect operation to key {KeyId:B} with purposes {Purposes}.");

            _keyNotFoundInKeyRing = LoggerMessage.Define<Guid>(
                 logLevel: LogLevel.Debug,
                 eventId: 1,
                 formatString: "Key {KeyId:B} was not found in the key ring. Unprotect operation cannot proceed.");

            _keyRevokedProceeding = LoggerMessage.Define<Guid>(
                logLevel: LogLevel.Verbose,
                eventId: 1,
                formatString: "Key {KeyId:B} was revoked. Caller requested unprotect operation proceed regardless.");

            _keyRevokedNotProceeding = LoggerMessage.Define<Guid>(
                 logLevel: LogLevel.Verbose,
                 eventId: 1,
                 formatString: "Key {KeyId:B} was revoked. Unprotect operation cannot proceed.");

        }

        public static void OpeningCngAlgoritmHmac(this ILogger logger, string hashAlgorithm, string hashAlgorithmProvider)
        {
            _oppeningCngAlgoritmHmac(logger, hashAlgorithm, hashAlgorithmProvider, null);
        }

        public static void OpeningCngAlgoritmCbc(this ILogger logger, string hashAlgorithm, string hashAlgorithmProvider)
        {
            _oppeningCngAlgoritmCbc(logger, hashAlgorithm, hashAlgorithmProvider, null);
        }

        public static void OpeningCngAlgoritmCgm(this ILogger logger, string hashAlgorithm, string hashAlgorithmProvider)
        {
            _oppeningCngAlgoritmCgm(logger, hashAlgorithm, hashAlgorithmProvider, null);
        }

        public static void UsingManagedKeyedHashAlgoritm(this ILogger logger, string validationAlgorithmType)
        {
            _usingManagedKeyedHashAlgoritm(logger, validationAlgorithmType, null);
        }
        public static void UsingManagedSymmetricAlgoritm(this ILogger logger, string encryptionAlgorithmType)
        {
            _usingManagedSymmetricAlgoritm(logger, encryptionAlgorithmType, null);
        }
        public static void KeyCreateEncryptorInstanceFailed(this ILogger logger, Guid keyId)
        {
            _keyCreateEncryptorInstanceFailed(logger, keyId, null);
        }

        public static void ConsideringDefaultKey(this ILogger logger, Guid keyId, DateTimeOffset expirationDate)
        {
            _consideringDefaultKey(logger, keyId, expirationDate, null);
        }

        public static void NotConsideringDefaultKey(this ILogger logger, Guid keyId)
        {
            _notConsideringDefaultKey(logger, keyId, null);
        }

        public static void PerformingProtect(this ILogger logger, Guid keyId, string purposes)
        {
            _performingProtect(logger, keyId, purposes, null);
        }

        public static void PerformingUnpotect(this ILogger logger, Guid keyId, string purposes)
        {
            _performingProtect(logger, keyId, purposes, null);
        }

        public static void KeyNotFoundInKeyRing(this ILogger logger, Guid keyId)
        {
            _keyNotFoundInKeyRing(logger, keyId, null);
        }

        public static void KeyRevokedProceeding(this ILogger logger, Guid keyId)
        {
            _keyRevokedProceeding(logger, keyId, null);
        }

        public static void KeyRevokedNotProceeding(this ILogger logger, Guid keyId)
        {
            _keyRevokedNotProceeding(logger, keyId, null);
        }



        public static void NewKeyShouldBeAddedToKeyRing(this ILogger logger)
        {
            if (logger.IsVerboseLevelEnabled())
            {
                logger.LogVerbose("Policy resolution states that a new key should be added to the key ring.");
            }
        }

        public static void KeyRingDoesNotContainKeyAutogenerationDisabled(this ILogger logger)
        {
            if (logger.IsVerboseLevelEnabled())
            {
                logger.LogVerbose("The key ring does not contain a valid default key, and the key manager is configured with auto-generation of keys disabled.");
            }
        }




        public static void DefaultKeyImminentAndRepositoryContainsNotSuccessor(this ILogger logger)
        {
            if (logger.IsVerboseLevelEnabled())
            {
                logger.LogVerbose("Default key expiration imminent and repository contains no viable successor. Caller should generate a successor.");
            }
        }

        public static void RepositoryContainsNoViableDefaultKey(this ILogger logger)
        {
            if (logger.IsVerboseLevelEnabled())
            {
                logger.LogVerbose("Repository contains no viable default key. Caller should generate a key with immediate activation.");
            }
        }
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

        public static void LogDebugF(this ILogger logger, FormattableString message)
        {
            logger.LogDebug(message.Format, message.GetArguments());
        }

        public static void LogDebugF(this ILogger logger, Exception error, FormattableString message)
        {
            logger.LogDebug(new FormattedLogValues(message.Format, message.GetArguments()), error);
        }

        public static void LogError(this ILogger logger, Exception error, string message)
        {
            logger.LogError(message, error);
        }

        public static void LogErrorF(this ILogger logger, Exception error, FormattableString message)
        {
            logger.LogError(new FormattedLogValues(message.Format, message.GetArguments()), error);
        }

        public static void LogInformationF(this ILogger logger, FormattableString message)
        {
            logger.LogInformation(message.Format, message.GetArguments());
        }

        public static void LogVerboseF(this ILogger logger, FormattableString message)
        {
            logger.LogVerbose(message.Format, message.GetArguments());
        }

        public static void LogWarningF(this ILogger logger, FormattableString message)
        {
            logger.LogWarning(message.Format, message.GetArguments());
        }

        public static void LogWarningF(this ILogger logger, Exception error, FormattableString message)
        {
            logger.LogWarning(new FormattedLogValues(message.Format, message.GetArguments()), error);
        }
    }
}
