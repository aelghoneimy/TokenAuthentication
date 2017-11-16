namespace TokenAuthentication
{
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Identity;

    public class ClaimsTransformer<TKey, TUser> : IClaimsTransformation where TUser : class
    {
        private readonly ITokenStore<TKey, TUser> _tokenStore;
        private readonly UserManager<TUser> _userManager;
        private readonly IUserClaimsPrincipalFactory<TUser> _userClaimsPrincipalFactory;

        public ClaimsTransformer(ITokenStore<TKey, TUser> tokenStore, UserManager<TUser> userManager, IUserClaimsPrincipalFactory<TUser> userClaimsPrincipalFactory)
        {
            _tokenStore = tokenStore;
            _userManager = userManager;
            _userClaimsPrincipalFactory = userClaimsPrincipalFactory;
        }

        public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            var userId = _tokenStore.GetCurrentUserId().ToString();

            if (userId != "0")
            {
                var user = await _userManager.FindByIdAsync(userId);

                var newPrincipal =  await _userClaimsPrincipalFactory.CreateAsync(user);

                principal.AddIdentities(newPrincipal.Identities);
            }
            
            return principal;
        }
    }
}