using System.IdentityModel.Tokens.Jwt;
using AuthenticationApi.Model;
using AuthenticationApi.Services;
using AuthenticationApi.ViewModel;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;

namespace AuthenticationApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class UserController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;
        private readonly Dictionary<Permission, string> _permissions;

        public UserController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
            _permissions = new Dictionary<Permission, string>
            {
                { Model.Permission.GetUser, "GetUser" },
                { Model.Permission.AddUser, "AddUser" },
                { Model.Permission.UpdateUser, "UpdateUser" },
                { Model.Permission.DeleteUser, "DeleteUser" },
                { Model.Permission.UpdatePermission, "UpdatePermission" }
            };
        }

        [HttpGet("{userName}")]
        [Authorize(Roles = "GetUser")]
        public async Task<UserViewModel> Get(string userName)
        {
            User user =  await _userService.Get(userName);

            UserViewModel userViewModel = new UserViewModel()
            {
                UserName = user.UserName != null ? user.UserName : string.Empty,
                Password = string.Empty,
                Permissions = user.Permissions.Select(permissionValue => _permissions[permissionValue]).ToList()
            };

            return userViewModel;
        }

        [HttpPost("Add")]
        [Authorize(Roles = "AddUser")]
        public async Task<bool> Add(UserViewModel user)
        {
            try
            {
                return await _userService.Add(user.UserName, user.Password);
            }
            catch (Exception)
            {
                return false;
            }
        }

        [HttpDelete("{userName}")]
        [Authorize(Roles = "DeleteUser")]
        public async Task<bool> Delete(string userName)
        {
            try
            {
                return await _userService.Delete(userName);
            }
            catch (Exception)
            {
                return false;
            }
        }

        [HttpPost("Permission")]
        [Authorize(Roles = "UpdatePermission")]
        public async Task<ActionResult> Permission(PermissionViewModel permissions)
        {
            if (string.IsNullOrWhiteSpace(permissions.UserName))
            {
                return BadRequest("Invalid username.");
            }

            List<Permission> permissionList = new List<Permission>();

            foreach (string permission in permissions.Permissions)
            {
                List<KeyValuePair<Permission, string>> permissionEnumList = _permissions.Where(p => p.Value == permission).Take(1).ToList();

                if (permissionEnumList.Any())
                {
                    permissionList.Add(permissionEnumList[0].Key);
                }
            }

            await _userService.UpdatePermissions(permissions.UserName, permissionList);

            return Ok();
        }

        [HttpPost("Login")]
        [AllowAnonymous]
        public async Task<ActionResult<string>> Login(UserViewModel userModel)
        {
            User user = await _userService.Get(userModel.UserName);

            if (user == null)
            {
                return BadRequest("Invalid credentials.");
            }

            bool passwordVerified = await _userService.VerifyPassword(user, userModel.Password);

            if (!passwordVerified)
            {
                return BadRequest("Invalid credentials.");
            }

            string token = CreateToken(user);

            return Ok(token);
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName)
            };

            foreach (Permission permission in user.Permissions)
            {
                claims.Add(new Claim(ClaimTypes.Role, _permissions[permission]));
            }

            SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

            SigningCredentials creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            JwtSecurityToken token = new JwtSecurityToken(
                claims: claims,
                signingCredentials: creds);

            string jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
    }
}
