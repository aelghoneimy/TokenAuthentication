namespace TokenAuthentication
{
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.DependencyInjection;

    public static class TokenAuthenticationServiceCollectionExtensions
    {
        public static IServiceCollection AddTokenAuthentication<TKey, TUser>(this IServiceCollection services, 
            TokenAuthenticationOptions options) where TUser : class
        {
            services.AddSingleton(options ?? new TokenAuthenticationOptions());

            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            services.AddSingleton<ITokenStore<TKey, TUser>, TokenStore<TKey, TUser>>();

            services.AddSingleton<TokenGenerator<TKey, TUser>>();

            return services;
        }
    }
}