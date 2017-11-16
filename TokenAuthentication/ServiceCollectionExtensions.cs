namespace TokenAuthentication
{
    using System;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authentication.JwtBearer;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.IdentityModel.Tokens;

    public static class ServiceCollectionExtensions
    {
        private static readonly Task<int> FailedResult = Task.FromResult(0);

        public static IServiceCollection AddTokenAuthentication<TKey, TUser>(this IServiceCollection services,
            TokenAuthenticationOptions options) where TUser : class
        {
            options = options ?? new TokenAuthenticationOptions();

            services.AddSingleton(options);

            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            services.AddSingleton<ITokenStore<TKey, TUser>, TokenStore<TKey, TUser>>();

            services.AddSingleton<TokenGenerator<TKey, TUser>>();

            if (options.AutoLoadClaims)
            {
                services.AddScoped<IClaimsTransformation, ClaimsTransformer<TKey, TUser>>();
            }

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(x =>
                {
                    x.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = ctx => options.UnAuthenticatedFunc != null
                            ? options.UnAuthenticatedFunc.Invoke(ctx.Request.Path)
                            : FailedResult,

                        OnChallenge = ctx => options.UnAuthenticatedFunc != null
                            ? options.UnAuthenticatedFunc.Invoke(ctx.Request.Path)
                            : FailedResult
                    };
                    
                    x.TokenValidationParameters = new TokenValidationParameters
                    {
                        // The signing key must match!
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = options.SecurityKey,

                        // Validate the JWT Issuer (iss) claim
                        ValidateIssuer = true,
                        ValidIssuer = options.Issuer,

                        // Validate the JWT Audience (aud) claim
                        ValidateAudience = true,
                        ValidAudience = options.Audience,

                        // Validate the token expiry
                        ValidateLifetime = true,

                        // If you want to allow a certain amount of clock drift, set that here:
                        ClockSkew = TimeSpan.Zero
                    };
                });

            return services;
        }
    }
}