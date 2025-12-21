// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    /// <summary>
    /// Extension methods for <see cref="JsonWebTokenHandler"/>.
    /// </summary>
    public static class JsonWebTokenHandlerExtensions
    {
        /// <summary>
        /// Validates a token asynchronously with automatic retry logic similar to ValidateTokenAsync.
        /// This method handles configuration retrieval, retries on recoverable errors, and Last Known Good (LKG) configuration fallback.
        /// </summary>
        /// <param name="handler">The <see cref="JsonWebTokenHandler"/> instance.</param>
        /// <param name="token">The token to be validated.</param>
        /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
        /// <returns>A <see cref="Task{TokenValidationResult}"/>.</returns>
        /// <remarks>
        /// This extension method provides the same retry and LKG behavior as ValidateTokenAsync.
        /// The configuration is retrieved asynchronously from the ConfigurationManager if present.
        /// On recoverable validation failures, the method will:
        /// <list type="number">
        /// <item>Request a configuration refresh and retry validation if a new configuration is available</item>
        /// <item>Fall back to Last Known Good (LKG) configurations if UseLastKnownGoodConfiguration is enabled</item>
        /// </list>
        /// </remarks>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="handler"/> is null.</exception>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="token"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="validationParameters"/> is null.</exception>
        public static async Task<TokenValidationResult> ValidateTokenWithRetryAsync(
            this JsonWebTokenHandler handler,
            string token,
            TokenValidationParameters validationParameters)
        {
            if (handler == null)
                throw LogHelper.LogArgumentNullException(nameof(handler));

            if (string.IsNullOrEmpty(token))
                return new TokenValidationResult { Exception = LogHelper.LogArgumentNullException(nameof(token)), IsValid = false };

            if (validationParameters == null)
                return new TokenValidationResult { Exception = LogHelper.LogArgumentNullException(nameof(validationParameters)), IsValid = false };

            if (token.Length > handler.MaximumTokenSizeInBytes)
                return new TokenValidationResult { Exception = LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(TokenLogMessages.IDX10209, LogHelper.MarkAsNonPII(token.Length), LogHelper.MarkAsNonPII(handler.MaximumTokenSizeInBytes)))), IsValid = false };

            try
            {
                // Read the token using the public method
                var jsonWebToken = handler.ReadToken(token) as JsonWebToken;
                if (jsonWebToken == null)
                {
                    return new TokenValidationResult
                    {
                        Exception = LogHelper.LogExceptionMessage(new SecurityTokenMalformedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10204, LogHelper.MarkAsSecurityArtifact(token, JwtTokenUtilities.SafeLogJwtToken)))),
                        IsValid = false
                    };
                }

                return await ValidateTokenWithRetryAsync(handler, jsonWebToken, validationParameters).ConfigureAwait(false);
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new TokenValidationResult
                {
                    Exception = ex,
                    IsValid = false
                };
            }
        }

        /// <summary>
        /// Validates a JsonWebToken asynchronously with automatic retry logic similar to ValidateTokenAsync.
        /// This method handles configuration retrieval, retries on recoverable errors, and Last Known Good (LKG) configuration fallback.
        /// </summary>
        /// <param name="handler">The <see cref="JsonWebTokenHandler"/> instance.</param>
        /// <param name="jsonWebToken">The <see cref="JsonWebToken"/> to validate.</param>
        /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to be used for validating the token.</param>
        /// <returns>A <see cref="Task{TokenValidationResult}"/>.</returns>
        /// <remarks>
        /// This extension method provides the same retry and LKG behavior as ValidateTokenAsync.
        /// The configuration is retrieved asynchronously from the ConfigurationManager if present.
        /// On recoverable validation failures, the method will:
        /// <list type="number">
        /// <item>Request a configuration refresh and retry validation if a new configuration is available</item>
        /// <item>Fall back to Last Known Good (LKG) configurations if UseLastKnownGoodConfiguration is enabled</item>
        /// </list>
        /// </remarks>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="handler"/> is null.</exception>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="jsonWebToken"/> is null.</exception>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="validationParameters"/> is null.</exception>
        public static async Task<TokenValidationResult> ValidateTokenWithRetryAsync(
            this JsonWebTokenHandler handler,
            JsonWebToken jsonWebToken,
            TokenValidationParameters validationParameters)
        {
            if (handler == null)
                throw LogHelper.LogArgumentNullException(nameof(handler));

            if (jsonWebToken == null)
                return new TokenValidationResult { Exception = LogHelper.LogArgumentNullException(nameof(jsonWebToken)), IsValid = false };

            if (validationParameters == null)
                return new TokenValidationResult { Exception = LogHelper.LogArgumentNullException(nameof(validationParameters)), IsValid = false };

            try
            {
                BaseConfiguration currentConfiguration = null;
                if (validationParameters.ConfigurationManager != null)
                {
                    try
                    {
                        // Asynchronously get configuration
                        currentConfiguration = await validationParameters.ConfigurationManager.GetBaseConfigurationAsync(CancellationToken.None).ConfigureAwait(false);
                    }
#pragma warning disable CA1031 // Do not catch general exception types
                    catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
                    {
                        // The exception is not re-thrown as the TokenValidationParameters may have the issuer and signing key set
                        // directly on them, allowing the library to continue with token validation.
                        if (LogHelper.IsEnabled(EventLogLevel.Warning))
                            LogHelper.LogWarning(LogHelper.FormatInvariant(TokenLogMessages.IDX10261, validationParameters.ConfigurationManager.MetadataAddress, ex.ToString()));
                    }
                }

                TokenValidationResult tokenValidationResult = handler.ValidateTokenWithConfiguration(
                    jsonWebToken,
                    validationParameters,
                    currentConfiguration);

                if (validationParameters.ConfigurationManager != null)
                {
                    if (tokenValidationResult.IsValid)
                    {
                        // Set current configuration as LKG if it exists.
                        if (currentConfiguration != null)
                            validationParameters.ConfigurationManager.LastKnownGoodConfiguration = currentConfiguration;

                        return tokenValidationResult;
                    }
                    else if (TokenUtilities.IsRecoverableException(tokenValidationResult.Exception, (currentConfiguration != null && currentConfiguration.TokenDecryptionKeys.Count > 0)))
                    {
                        // If we were still unable to validate, attempt to refresh the configuration and validate using it
                        // but ONLY if the currentConfiguration is not null. We want to avoid refreshing the configuration on
                        // retrieval error as this case should have already been hit before. This refresh handles the case
                        // where a new valid configuration was somehow published during validation time.
                        if (currentConfiguration != null)
                        {
                            validationParameters.ConfigurationManager.RequestRefresh();
                            validationParameters.RefreshBeforeValidation = true;
                            var lastConfig = currentConfiguration;
                            currentConfiguration = await validationParameters.ConfigurationManager.GetBaseConfigurationAsync(CancellationToken.None).ConfigureAwait(false);

                            // Only try to re-validate using the newly obtained config if it doesn't reference equal the previously used configuration.
                            if (lastConfig != currentConfiguration)
                            {
                                tokenValidationResult = handler.ValidateTokenWithConfiguration(
                                    jsonWebToken,
                                    validationParameters,
                                    currentConfiguration);

                                if (tokenValidationResult.IsValid)
                                {
                                    validationParameters.ConfigurationManager.LastKnownGoodConfiguration = currentConfiguration;
                                    return tokenValidationResult;
                                }
                            }
                        }

                        if (validationParameters.ConfigurationManager.UseLastKnownGoodConfiguration)
                        {
                            validationParameters.RefreshBeforeValidation = false;
                            validationParameters.ValidateWithLKG = true;
                            var recoverableException = tokenValidationResult.Exception;

                            foreach (BaseConfiguration lkgConfiguration in validationParameters.ConfigurationManager.GetValidLkgConfigurations())
                            {
                                if (!lkgConfiguration.Equals(currentConfiguration) && TokenUtilities.IsRecoverableConfiguration(jsonWebToken.Kid, currentConfiguration, lkgConfiguration, recoverableException))
                                {
                                    tokenValidationResult = handler.ValidateTokenWithConfiguration(
                                        jsonWebToken,
                                        validationParameters,
                                        lkgConfiguration);

                                    if (tokenValidationResult.IsValid)
                                        return tokenValidationResult;
                                }
                            }
                        }
                    }
                }

                return tokenValidationResult;
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new TokenValidationResult
                {
                    Exception = ex,
                    IsValid = false
                };
            }
        }
    }
}
