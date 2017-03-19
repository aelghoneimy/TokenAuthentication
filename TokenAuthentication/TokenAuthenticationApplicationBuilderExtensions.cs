namespace TokenAuthentication
{
    using System;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication.JwtBearer;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.IdentityModel.Tokens;

    public class TokenAuthentication
    {
        public string LoginUrl { get; set; }
        public Func<HttpContext, Task> Func { get; set; }
    }

    public static class TokenAuthenticationApplicationBuilderExtensions
    {
        public static IApplicationBuilder UseTokenAuthentication<TKey, TUser>(this IApplicationBuilder app) 
            where TUser : class
        {
            var services = app.ApplicationServices;
            var tokenStore = services.GetRequiredService<ITokenStore<TKey, TUser>>();
            var options = services.GetRequiredService<TokenAuthenticationOptions>();

            app.UseMiddleware<TokenAuthenticationMiddleware<TKey, TUser>>();

            app.UseJwtBearerAuthentication(new JwtBearerOptions
            {
                Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = ctx =>
                    {
                        if (options.UnAuthenticatedFunc != null)
                        {
                            return options.UnAuthenticatedFunc.Invoke(ctx.Request.Path);
                        }

                        return Task.FromResult(0);
                    },
                    OnChallenge = ctx =>
                    {
                        if (options.UnAuthenticatedFunc != null)
                        {
                            return options.UnAuthenticatedFunc.Invoke(ctx.Request.Path);
                        }

                        return Task.FromResult(0);
                    }
                },
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                TokenValidationParameters = new TokenValidationParameters
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
                }
            });

            if (options.AutoLoadClaims)
            {
                app.UseClaimsTransformation(new ClaimsTransformationOptions
                {
                    Transformer = new ClaimsTransformer<TKey, TUser>(tokenStore)
                });
            }
            
            return app;
        }
    }
}