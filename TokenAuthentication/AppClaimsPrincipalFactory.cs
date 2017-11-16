namespace TokenAuthentication
{
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Options;

    public class AppClaimsPrincipalFactory<TKey, TUser, TRole> : UserClaimsPrincipalFactory<TUser, TRole> 
        where TUser : class 
        where TRole : class
    {
        private readonly UserManager<TUser> _userManager;
        private readonly ITokenStore<TKey, TUser> _tokenStore;

        public AppClaimsPrincipalFactory(UserManager<TUser> userManager, RoleManager<TRole> roleManager, IOptions<IdentityOptions> optionsAccessor, ITokenStore<TKey, TUser> tokenStore) 
            : base(userManager, roleManager, optionsAccessor)
        {
            _userManager = userManager;
            _tokenStore = tokenStore;
        }

        public override async Task<ClaimsPrincipal> CreateAsync(TUser user)
        {
            var userId = _tokenStore.GetCurrentUserId().ToString();

            if (userId != "0")
            {
                user = await _userManager.FindByIdAsync(userId);

            }
            var principal = await base.CreateAsync(user);
            
            return principal;
        }
    }
}
