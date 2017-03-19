namespace TokenAuthentication
{
    using System;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;

    public class TokenGenerator<TKey, TUser>
    {
        private readonly ITokenStore<TKey, TUser> _tokenStore;
        private readonly TokenAuthenticationOptions _tokenAuthenticationOptions;

        public TokenGenerator(ITokenStore<TKey, TUser> tokenStore, TokenAuthenticationOptions tokenAuthenticationOptions)
        {
            _tokenStore = tokenStore;
            _tokenAuthenticationOptions = tokenAuthenticationOptions;
        }
        
        public AccessToken New(TKey userId)
        {
            var now = DateTime.UtcNow;
            var nowUntill = now.Add(_tokenAuthenticationOptions.ExpiresIn);

            // Specifically add the jti (random nonce), iat (issued timestamp), and sub (subject/user) claims.
            // You can add other claims here, if you want:
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, now.Ticks.ToString(), ClaimValueTypes.Integer64)
            };

            // Create the JWT and write it to a string
            var jwt = new JwtSecurityToken(
                issuer: _tokenAuthenticationOptions.Issuer,
                audience: _tokenAuthenticationOptions.Audience,
                claims: claims,
                notBefore: now,
                expires: nowUntill,
                signingCredentials: _tokenAuthenticationOptions.SigningCredentials);
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            var accessToken = new AccessToken
            {
                Token = encodedJwt,
                ExpiresOn = nowUntill
            };

            _tokenStore.Add(new Token<TKey, TUser>
            {
                Client = "Http Client",
                ClientVersion = "n/a",
                CreatedOn = DateTime.UtcNow,
                Platform = "n/a",
                PlatformVersion = "n/a",
                UserId = userId,
                ValidUntil = nowUntill,
                Value = encodedJwt
            });

            return accessToken;
        }
    }
}