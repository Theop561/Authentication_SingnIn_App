using Microsoft.AspNetCore.Identity;

namespace Authentication_SingnIn_App.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? Name { get; set; }
    }
}
