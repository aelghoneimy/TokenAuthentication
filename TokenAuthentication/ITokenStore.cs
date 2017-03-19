namespace TokenAuthentication
{
    using System.Collections.Generic;

    public interface ITokenStore<TKey, TUser>
    {
        string CurrentToken { get; }
        IDictionary<string, Token<TKey, TUser>> Tokens { get; }
        void Add(Token<TKey, TUser> token);
        void AddRange(IEnumerable<Token<TKey, TUser>> tokens);
        void Remove(string tokenValue);
        void RemoveUserTokens(TKey userId, IEnumerable<string> exceptionTokens = null);
        bool IsValid(string tokenValue);
        TKey GetUserId(string token);
        TKey GetCurrentUserId();
    }
}