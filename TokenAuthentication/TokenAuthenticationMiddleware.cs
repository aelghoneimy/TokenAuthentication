namespace TokenAuthentication
{
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Server.Kestrel.Internal.Http;

    public class TokenAuthenticationMiddleware<TKey, TUser>
    {
        private readonly RequestDelegate _next;
        private readonly ITokenStore<TKey, TUser> _tokenStore;

        public TokenAuthenticationMiddleware(RequestDelegate next, ITokenStore<TKey, TUser> tokenStore)
        {
            _next = next;
            _tokenStore = tokenStore;
        }

        public async Task Invoke(HttpContext context)
        {
            var authorizationHeader = ((FrameRequestHeaders)context.Request.Headers).HeaderAuthorization;

            if (authorizationHeader.Count > 1)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Multiple Authorization headers is not allowed.");
                return;
            }

            if (authorizationHeader.Count == 1)
            {
                var tokenValue = authorizationHeader.First().Substring(7);

                if (!_tokenStore.IsValid(tokenValue))
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Invalid authorization token.");
                    return;
                }
            }

            await _next(context);
        }
    }
}