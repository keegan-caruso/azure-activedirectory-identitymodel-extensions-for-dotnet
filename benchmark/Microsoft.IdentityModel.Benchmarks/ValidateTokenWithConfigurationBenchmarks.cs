// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ValidateTokenWithConfigurationBenchmarks*

    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    public class ValidateTokenWithConfigurationBenchmarks
    {
        private JsonWebTokens.JsonWebTokenHandler _jsonWebTokenHandler;
        private SecurityTokenDescriptor _tokenDescriptor;
        private string _jws;
        private string _jwsExtendedClaims;
        private TokenValidationParameters _tokenValidationParameters;
        private OpenIdConnectConfiguration _configuration;

        [GlobalSetup]
        public void Setup()
        {
            _tokenDescriptor = new SecurityTokenDescriptor
            {
                Claims = BenchmarkUtils.Claims,
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            };

            var tokenDescriptorExtendedClaims = new SecurityTokenDescriptor
            {
                Claims = BenchmarkUtils.ClaimsExtendedExample,
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            };

            _jsonWebTokenHandler = new JsonWebTokens.JsonWebTokenHandler();
            _jws = _jsonWebTokenHandler.CreateToken(_tokenDescriptor);
            _jwsExtendedClaims = _jsonWebTokenHandler.CreateToken(tokenDescriptorExtendedClaims);

            _tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
            };

            _configuration = new OpenIdConnectConfiguration
            {
                Issuer = BenchmarkUtils.Issuer
            };
            _configuration.SigningKeys.Add(BenchmarkUtils.SigningCredentialsRsaSha256.Key);
        }

        [BenchmarkCategory("ValidateTokenAsync_vs_Sync"), Benchmark(Baseline = true)]
        public async Task<TokenValidationResult> JsonWebTokenHandler_ValidateTokenAsync()
        {
            return await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters).ConfigureAwait(false);
        }

        [BenchmarkCategory("ValidateTokenAsync_vs_Sync"), Benchmark]
        public TokenValidationResult JsonWebTokenHandler_ValidateTokenWithConfiguration_Sync()
        {
            return _jsonWebTokenHandler.ValidateTokenWithConfiguration(_jwsExtendedClaims, _tokenValidationParameters, null);
        }

        [BenchmarkCategory("ValidateTokenAsync_vs_Sync"), Benchmark]
        public TokenValidationResult JsonWebTokenHandler_ValidateTokenWithConfiguration_WithConfig()
        {
            return _jsonWebTokenHandler.ValidateTokenWithConfiguration(_jwsExtendedClaims, _tokenValidationParameters, _configuration);
        }

        [BenchmarkCategory("ValidateToken_NoRetry"), Benchmark(Baseline = true)]
        public async Task<TokenValidationResult> JsonWebTokenHandler_ValidateTokenAsync_NoRetry()
        {
            return await _jsonWebTokenHandler.ValidateTokenAsync(_jws, _tokenValidationParameters).ConfigureAwait(false);
        }

        [BenchmarkCategory("ValidateToken_NoRetry"), Benchmark]
        public TokenValidationResult JsonWebTokenHandler_ValidateTokenWithConfiguration_NoRetry()
        {
            return _jsonWebTokenHandler.ValidateTokenWithConfiguration(_jws, _tokenValidationParameters, null);
        }

        [BenchmarkCategory("ValidateToken_CallerHandlesRetry"), Benchmark(Baseline = true)]
        public async Task<TokenValidationResult> JsonWebTokenHandler_ValidateTokenAsync_CallerRetries()
        {
            // Simulate caller handling retries
            TokenValidationResult result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters).ConfigureAwait(false);
            if (!result.IsValid)
            {
                // First retry
                result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters).ConfigureAwait(false);
                if (!result.IsValid)
                {
                    // Second retry
                    result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters).ConfigureAwait(false);
                }
            }
            return result;
        }

        [BenchmarkCategory("ValidateToken_CallerHandlesRetry"), Benchmark]
        public TokenValidationResult JsonWebTokenHandler_ValidateTokenWithConfiguration_CallerRetries()
        {
            // Simulate caller handling retries - synchronous version
            TokenValidationResult result = _jsonWebTokenHandler.ValidateTokenWithConfiguration(_jwsExtendedClaims, _tokenValidationParameters, null);
            if (!result.IsValid)
            {
                // First retry
                result = _jsonWebTokenHandler.ValidateTokenWithConfiguration(_jwsExtendedClaims, _tokenValidationParameters, null);
                if (!result.IsValid)
                {
                    // Second retry
                    result = _jsonWebTokenHandler.ValidateTokenWithConfiguration(_jwsExtendedClaims, _tokenValidationParameters, null);
                }
            }
            return result;
        }

        [BenchmarkCategory("ValidateToken_WithConfiguration"), Benchmark(Baseline = true)]
        public async Task<TokenValidationResult> JsonWebTokenHandler_ValidateTokenAsync_WithConfigManager()
        {
            // Simulate configuration being provided through configuration manager (involves async overhead)
            return await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters).ConfigureAwait(false);
        }

        [BenchmarkCategory("ValidateToken_WithConfiguration"), Benchmark]
        public TokenValidationResult JsonWebTokenHandler_ValidateTokenWithConfiguration_DirectConfig()
        {
            // Direct configuration provided by caller - no async overhead
            return _jsonWebTokenHandler.ValidateTokenWithConfiguration(_jwsExtendedClaims, _tokenValidationParameters, _configuration);
        }
    }
}
