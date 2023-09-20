using System.ComponentModel.DataAnnotations;

namespace Authentication_SingnIn_App.DTO
{
    public class RegisterationModel
    {
        [Required]
        public string? Name { get; set; }
        public string? Username { get; set; }
        [Required]
        public string? Email { get; set; }
        [Required]
        public string? Password { get; set; }

    }
}
