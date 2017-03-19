namespace TokenAuthentication
{
    using System;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    
    public class Token<TKey, TUser>
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int TokenId { get; set; }
        [Required]
        public TKey UserId { get; set; }
        [Required]
        public string Value { get; set; }
        [Required]
        public DateTime CreatedOn { get; set; } = DateTime.UtcNow;
        [Required]
        public DateTime ValidUntil { get; set; }
        [Required]
        public TokenStatuses Status { get; set; } = TokenStatuses.Active;

        public string Platform { get; set; }
        public string PlatformVersion { get; set; }
        public string Client { get; set; }
        public string ClientVersion { get; set; }

        [ForeignKey(nameof(UserId))]
        public virtual TUser User { get; set; }
    }
}