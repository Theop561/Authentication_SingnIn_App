using Authentication_SingnIn_App.Domain;
using Authentication_SingnIn_App.DTO;
using Authentication_SingnIn_App.Repositories.Abstract;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Client;

namespace Authentication_SingnIn_App.Controllers
{
    [Route("api/[controller]/{action}")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly ApplicationDbContext _Context;
        private readonly ITokenService _tokenSrvice;

        public TokenController(ApplicationDbContext Context,
            ITokenService tokenSrvice )
        {
            _Context = Context;
            _tokenSrvice = tokenSrvice;
        }
        [HttpPost]
        public IActionResult Refresh(RefreshTokenRequest tokenApiModel)
        {
            if (tokenApiModel is null)
                return BadRequest("Invalid client request");
            string accessToken = tokenApiModel.AccessToken;
            string refreshToken = tokenApiModel.RefreshToken;
            var principal = _tokenSrvice.GetPrincipalFromExpiredToken(accessToken);
            var Username = principal.Identity.Name;
            var user = _Context.TokenInfos.SingleOrDefault(u => u.Username == Username);
            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiry<= DateTime.Now)
                return BadRequest("Invalid client request");
            var newAccessToken = _tokenSrvice.GetToken(principal.Claims);
            var newRefreshToken = _tokenSrvice.GetRefreshToken();
            user.RefreshToken = newRefreshToken;
            _Context.SaveChanges();
            return Ok(new RefreshTokenRequest()
            {
                AccessToken = newAccessToken.TokenString,
                RefreshToken = newRefreshToken,
            });
        }
        [HttpPost, Authorize]
        public IActionResult Revoke()
        {
            try
            {
                var username = User.Identity.Name;
                var user = _Context.TokenInfos.SingleOrDefault(u => u.Username == username);
                if (user is null)
                    return BadRequest();
                user.RefreshToken = null;
                _Context.SaveChanges();
                return Ok(true);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
           
        }
    }
}

