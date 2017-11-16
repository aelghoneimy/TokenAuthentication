namespace TokenAuthentication
{
    using System;
    using System.Security.Claims;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.IdentityModel.Tokens;

    public class TokenAuthenticationOptions
    {
        private string _key = "DefaultKey";

        internal SecurityKey SecurityKey { get; private set; }
        internal SigningCredentials SigningCredentials { get; private set; }
        
        public string Audience { get; set; } = "DefaultAudience";
        public bool AutoLoadClaims { get; set; }
        public TimeSpan ExpiresIn { get; set; } = TimeSpan.FromDays(7);
        public string Issuer { get; set; } = ClaimsIdentity.DefaultIssuer;
        public string Key
        {
            get => _key;
            set
            {
                _key = value;

                SecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(value));
                SigningCredentials = new SigningCredentials(SecurityKey, SecurityAlgorithms.HmacSha256);
            }
        }
        public string LoginUrl { get; set; } = "/login";
        public Func<string, Task> UnAuthenticatedFunc { get; set; }
    }
}