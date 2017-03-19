namespace TokenAuthentication
{
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.DependencyInjection;

    public class ClaimsTransformer<TKey, TUser> : IClaimsTransformer where TUser : class
    {
        private readonly ITokenStore<TKey, TUser> _tokenStore;

        public ClaimsTransformer(ITokenStore<TKey, TUser> tokenStore)
        {
            _tokenStore = tokenStore;
        }

        public async Task<ClaimsPrincipal> TransformAsync(ClaimsTransformationContext context)
        {
            var services = context.Context.RequestServices;
            var userManager = services.GetRequiredService<UserManager<TUser>>();
            var userClaimsPrincipalFactory = services.GetRequiredService<IUserClaimsPrincipalFactory<TUser>>();
            
            var userId = _tokenStore.GetCurrentUserId().ToString();

            if (userId != "0")
            {
                var user = await userManager.FindByIdAsync(userId);

                var principal =  await userClaimsPrincipalFactory.CreateAsync(user);

                context.Principal.AddIdentities(principal.Identities);
            }
            
            return context.Principal;
        }
    }
}