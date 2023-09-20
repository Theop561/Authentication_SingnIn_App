namespace Authentication_SingnIn_App.DTO
{
    public class TokenResponse
    {
        public string TokenString { get; set; }
        public DateTime ValidTo { get; set; }
    }
}
