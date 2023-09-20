using Authentication_SingnIn_App.Domain;
using Authentication_SingnIn_App.DTO;
using Authentication_SingnIn_App.Models;
using Authentication_SingnIn_App.Repositories.Abstract;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Security.Claims;


namespace Authentication_SingnIn_App.Controllers
{
    [Route("api/[controller]/{action}")]
    [ApiController]
    public class AuthorizationController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole>   _roleManager;
        private readonly ITokenService _tokenService;

        public AuthorizationController(ApplicationDbContext context, 
            UserManager<ApplicationUser> userManager, 
            RoleManager<IdentityRole> roleManager, ITokenService tokenService)
        {
            _context = context;
             _userManager = userManager;
             _roleManager = roleManager;
            _tokenService = tokenService;
        }
        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordModel model)
        {
            var status = new Status();
            if(!ModelState.IsValid)
            {
                status.StutusCode = 0;
                status.Message = "Please pass all the valid fields";
                return Ok(status);
            }
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user is null)
            {
                status.StutusCode = 0;
                status.Message = "invalid username";
                return Ok(status);
            }
            if(!await _userManager.CheckPasswordAsync(user,model.CurrentPassword))
            {
                status.StutusCode = 0;
                status.Message = "invalid currentpassword";
                return Ok(status);
            }
            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
                if(!result.Succeeded)
                {
                    status.StutusCode = 0;
                    status.Message = "Failed to change password";
                    return Ok(status);
                }
            status.StutusCode = 0;
            status.Message = "password have changed successfully";          
            return Ok(result);
             
        }

        [HttpPost]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await  _userManager.FindByNameAsync(model.Username);
            if (user!= null && await _userManager.CheckPasswordAsync(user,model.Password)) 
            {
                var userRoles = await _userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
                foreach(var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }
                var token = _tokenService.GetToken(authClaims);
                var refreshToken = _tokenService.GetRefreshToken();
                var tokenInfos = _context.TokenInfos.FirstOrDefault(a => a.Username == user.UserName);
                if (tokenInfos == null)
                {
                    var infos = new TokenInfo
                    {
                        Username = user.UserName,
                        RefreshToken = refreshToken,
                        RefreshTokenExpiry = DateTime.Now.AddDays(7)
                    };
                   
                }
                else
                {
                    tokenInfos.RefreshToken = refreshToken;
                    tokenInfos.RefreshTokenExpiry = DateTime.Now.AddDays(7);
                }
                try
                {
                    _context.SaveChanges();
                }
                catch (Exception ex)
                {
                    return BadRequest(ex.Message);
                }
                return Ok(new LoginResponse
                {
                    Name = user.Name,
                    Username = user.UserName,
                    Token = token.TokenString,
                    RefreshToken = refreshToken,
                    Expiration = token.ValidTo,
                    StutusCode = 1,
                    Message = "Logged in"
                });
            }

            return Ok(
                new LoginResponse
                {
                    StutusCode = 0,
                    Message = "Invalid Username or password",
                    Token = "",
                    Expiration = null
                });
        }
        [HttpPost]
        public async Task<IActionResult> Registeration([FromBody] RegisterationModel model)
        {
            var status = new Status();
            if (!ModelState.IsValid)
            {
                status.StutusCode = 0;
                status.Message = "Please pass all the required fields";
                return Ok(status);

            }
            var userExits = await _userManager.FindByNameAsync(model.Username);
            if (userExits != null)
            {
                status.StutusCode = 0;
                status.Message = "InValid username ";
                return Ok(status);
            }
            var user = new ApplicationUser
            {
                UserName = model.Username,
                SecurityStamp = Guid.NewGuid().ToString(),
                Email = model.Email,
                Name = model.Name
            };
            var result = await _userManager.CreateAsync(user,model.Password);
            if(!result.Succeeded)
            {
                status.StutusCode = 0;
                status.Message = "User creation failed";
                return Ok(status);

            }
            if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));

            if (await _roleManager.RoleExistsAsync(UserRoles.User))
            {
                await _userManager.AddToRoleAsync (user, UserRoles.User);
            }
            status.StutusCode = 1;
            status.Message = "Successfully registered";
            return Ok(status);
        }

       [HttpPost]
        public async Task<IActionResult> RegisterationAdmin([FromBody] RegisterationModel model)
        {
            var status = new Status();
            if (!ModelState.IsValid)
            {
                status.StutusCode = 0;
                status.Message = "Please pass all the required fields";
                return Ok(status);

            }
            var userExit = await _userManager.FindByNameAsync(model.Username);
            if (userExit != null)
            {
               status.StutusCode = 0;
                status.Message = "InValid username ";
                return Ok(status);
            }
            var user = new ApplicationUser
            {
                UserName = model.Username,
                SecurityStamp = Guid.NewGuid().ToString(),
                Email = model.Email,
                Name = model.Name
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                status.StutusCode = 0;
                status.Message = "User creation failed";
                return Ok(status);

            }
            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));

            if (await _roleManager.RoleExistsAsync(UserRoles.Admin)) 
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Admin);
            }
            status.StutusCode = 1;
            status.Message = "Successfully registered";
            return Ok(status);
        }
    }

    

}
