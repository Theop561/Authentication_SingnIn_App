namespace Authentication_SingnIn_App.Domain
{
    public class TokenInfo
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Name { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiry { get; set; }
    }
}
