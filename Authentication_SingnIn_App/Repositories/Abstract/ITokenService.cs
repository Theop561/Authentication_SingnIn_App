using Authentication_SingnIn_App.DTO;
using System.Security.Claims;

namespace Authentication_SingnIn_App.Repositories.Abstract
{
    public interface ITokenService
    {
        TokenResponse GetToken(IEnumerable<Claim> claims);
        string GetRefreshToken();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}
 