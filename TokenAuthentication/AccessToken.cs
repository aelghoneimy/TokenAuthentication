namespace TokenAuthentication
{
    using System;

    public class AccessToken
    {
        public string Token { get; set; }
        public DateTime ExpiresOn { get; set; }
    }
}