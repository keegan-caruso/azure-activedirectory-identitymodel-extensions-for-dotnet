// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    /// <summary>
    /// Tests for asynchronous token validation extension methods with retry logic.
    /// </summary>
    public class JsonWebTokenHandlerValidateTokenWithRetryTests
    {
        [Fact]
        public async Task ValidateTokenWithRetryAsync_NullHandler_ThrowsArgumentNullException()
        {
            JsonWebTokenHandler handler = null;
            var token = "******";
            var validationParameters = new TokenValidationParameters();

            await Assert.ThrowsAsync<ArgumentNullException>(() => handler.ValidateTokenWithRetryAsync(token, validationParameters));
        }

        [Fact]
        public async Task ValidateTokenWithRetryAsync_NullToken_ReturnsInvalid()
        {
            var handler = new JsonWebTokenHandler();
            var validationParameters = new TokenValidationParameters();

            var result = await handler.ValidateTokenWithRetryAsync(null as string, validationParameters);

            Assert.False(result.IsValid);
            Assert.NotNull(result.Exception);
            Assert.IsType<ArgumentNullException>(result.Exception);
        }

        [Fact]
        public async Task ValidateTokenWithRetryAsync_EmptyToken_ReturnsInvalid()
        {
            var handler = new JsonWebTokenHandler();
            var validationParameters = new TokenValidationParameters();

            var result = await handler.ValidateTokenWithRetryAsync(string.Empty, validationParameters);

            Assert.False(result.IsValid);
            Assert.NotNull(result.Exception);
            Assert.IsType<ArgumentNullException>(result.Exception);
        }

        [Fact]
        public async Task ValidateTokenWithRetryAsync_NullValidationParameters_ReturnsInvalid()
        {
            var handler = new JsonWebTokenHandler();
            var token = "******";

            var result = await handler.ValidateTokenWithRetryAsync(token, null);

            Assert.False(result.IsValid);
            Assert.NotNull(result.Exception);
            Assert.IsType<ArgumentNullException>(result.Exception);
        }

        [Fact]
        public async Task ValidateTokenWithRetryAsync_ValidToken_NoConfigManager_ReturnsValid()
        {
            var handler = new JsonWebTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new CaseSensitiveClaimsIdentity(new[]
                {
                    new System.Security.Claims.Claim("sub", "user123")
                }),
                Issuer = Default.Issuer,
                Audience = Default.Audience,
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials
            };

            var token = handler.CreateToken(tokenDescriptor);

            var validationParameters = new TokenValidationParameters
            {
                ValidIssuer = Default.Issuer,
                ValidAudience = Default.Audience,
                IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                ValidateLifetime = false
            };

            var result = await handler.ValidateTokenWithRetryAsync(token, validationParameters);

            Assert.True(result.IsValid);
            Assert.NotNull(result.SecurityToken);
            Assert.NotNull(result.ClaimsIdentity);
        }

        [Fact]
        public async Task ValidateTokenWithRetryAsync_JsonWebToken_ValidToken_ReturnsValid()
        {
            var handler = new JsonWebTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new CaseSensitiveClaimsIdentity(new[]
                {
                    new System.Security.Claims.Claim("sub", "user123")
                }),
                Issuer = Default.Issuer,
                Audience = Default.Audience,
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials
            };

            var tokenString = handler.CreateToken(tokenDescriptor);
            var jsonWebToken = new JsonWebToken(tokenString);

            var validationParameters = new TokenValidationParameters
            {
                ValidIssuer = Default.Issuer,
                ValidAudience = Default.Audience,
                IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                ValidateLifetime = false
            };

            var result = await handler.ValidateTokenWithRetryAsync(jsonWebToken, validationParameters);

            Assert.True(result.IsValid);
            Assert.NotNull(result.SecurityToken);
            Assert.NotNull(result.ClaimsIdentity);
        }

        [Fact]
        public async Task ValidateTokenWithRetryAsync_JsonWebToken_NullToken_ReturnsInvalid()
        {
            var handler = new JsonWebTokenHandler();
            var validationParameters = new TokenValidationParameters();

            var result = await handler.ValidateTokenWithRetryAsync(null as JsonWebToken, validationParameters);

            Assert.False(result.IsValid);
            Assert.NotNull(result.Exception);
            Assert.IsType<ArgumentNullException>(result.Exception);
        }

        [Fact]
        public async Task ValidateTokenWithRetryAsync_InvalidIssuer_ReturnsInvalid()
        {
            var handler = new JsonWebTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new CaseSensitiveClaimsIdentity(new[]
                {
                    new System.Security.Claims.Claim("sub", "user123")
                }),
                Issuer = "http://wrongissuer.com",
                Audience = Default.Audience,
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials
            };

            var token = handler.CreateToken(tokenDescriptor);

            var validationParameters = new TokenValidationParameters
            {
                ValidIssuer = Default.Issuer,
                ValidAudience = Default.Audience,
                IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                ValidateLifetime = false
            };

            var result = await handler.ValidateTokenWithRetryAsync(token, validationParameters);

            Assert.False(result.IsValid);
            Assert.NotNull(result.Exception);
            Assert.IsType<SecurityTokenInvalidIssuerException>(result.Exception);
        }

        [Fact]
        public async Task ValidateTokenWithRetryAsync_TokenTooLarge_ReturnsInvalid()
        {
            var handler = new JsonWebTokenHandler();
            var validationParameters = new TokenValidationParameters();

            // Create a token that exceeds the maximum size
            var largeToken = new string('a', handler.MaximumTokenSizeInBytes + 1);

            var result = await handler.ValidateTokenWithRetryAsync(largeToken, validationParameters);

            Assert.False(result.IsValid);
            Assert.NotNull(result.Exception);
            Assert.IsType<ArgumentException>(result.Exception);
        }

        [Fact]
        public async Task ValidateTokenWithRetryAsync_WithConfigManager_ReturnsValid()
        {
            var handler = new JsonWebTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new CaseSensitiveClaimsIdentity(new[]
                {
                    new System.Security.Claims.Claim("sub", "user123")
                }),
                Issuer = Default.Issuer,
                Audience = Default.Audience,
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials
            };

            var token = handler.CreateToken(tokenDescriptor);

            var configuration = new OpenIdConnectConfiguration
            {
                Issuer = Default.Issuer
            };
            configuration.SigningKeys.Add(KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key);

            // Create a simple config manager that returns our configuration
            var configManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);

            var validationParameters = new TokenValidationParameters
            {
                ValidAudience = Default.Audience,
                ValidateLifetime = false,
                ConfigurationManager = configManager
            };

            var result = await handler.ValidateTokenWithRetryAsync(token, validationParameters);

            Assert.True(result.IsValid);
            Assert.NotNull(result.SecurityToken);
            Assert.NotNull(result.ClaimsIdentity);
        }
    }
}
