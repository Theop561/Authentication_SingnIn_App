using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;


namespace Authentication_SingnIn_App.Controllers
{
    [Route("api/[controller]/{action}")]
    [ApiController]
    [Microsoft.AspNetCore.Authorization.Authorize]
    public class ProtectedController : ControllerBase
    {
        public IActionResult GetData()
        {
            return Ok("Data from protected controller");
        }
    }
}
