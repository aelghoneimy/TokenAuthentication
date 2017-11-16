namespace TokenAuthentication
{
    using Microsoft.AspNetCore.Builder;
    
    public static class ApplicationBuilderExtensions
    {
        public static IApplicationBuilder UseTokenAuthentication<TKey, TUser>(this IApplicationBuilder app) 
            where TUser : class
        {
            app.UseMiddleware<TokenAuthenticationMiddleware<TKey, TUser>>();
            
            app.UseAuthentication();

            return app;
        }
    }
}