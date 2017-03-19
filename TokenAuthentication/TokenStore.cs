namespace TokenAuthentication
{
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Server.Kestrel.Internal.Http;

    public class TokenStore<TKey, TUser> : ITokenStore<TKey, TUser>
    {
        private readonly IHttpContextAccessor _context;

        public string CurrentToken => ((FrameRequestHeaders)_context.HttpContext?.Request.Headers)?.HeaderAuthorization.FirstOrDefault()?.Substring(7);

        public IDictionary<string, Token<TKey, TUser>> Tokens { get; } = new Dictionary<string, Token<TKey, TUser>>();

        public TokenStore(IHttpContextAccessor context)
        {
            _context = context;
        }

        public void Add(Token<TKey, TUser> token)
        {
            Tokens[token.Value] = token;
        }

        public void AddRange(IEnumerable<Token<TKey, TUser>> tokens)
        {
            foreach (var token in tokens)
            {
                Tokens[token.Value] = token;
            }
        }

        public void Remove(string tokenValue)
        {
            if (Tokens.ContainsKey(tokenValue))
            {
                Tokens.Remove(tokenValue);
            }
        }

        public void RemoveUserTokens(TKey userId, IEnumerable<string> exceptionTokens = null)
        {
            exceptionTokens = exceptionTokens ?? new List<string>();

            var tokens = Tokens
                .Where(x => x.Value.UserId.Equals(userId) && !exceptionTokens.Contains(x.Key))
                .Select(x => x.Value.Value)
                .ToList();
            
            foreach (var token in tokens)
            {
                Tokens.Remove(token);
            }
        }

        public bool IsValid(string tokenValue)
        {
            return Tokens.ContainsKey(tokenValue) && Tokens[tokenValue].Status == TokenStatuses.Active;
        }

        public TKey GetUserId(string token) => Tokens.ContainsKey(token) ? Tokens[token].UserId : default(TKey);

        public TKey GetCurrentUserId()
        {
            var token = CurrentToken; // Cache

            return token == null || !Tokens.ContainsKey(token) ? default(TKey) : Tokens[token].UserId;
        }
    }
}