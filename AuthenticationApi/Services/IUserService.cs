using AuthenticationApi.Model;

namespace AuthenticationApi.Services
{
    public interface IUserService
    {
        Task<User> Get(string userName);
        Task<bool> Add(string userName, string password);
        Task <bool> Delete(string userName);
        Task<bool> VerifyPassword(User user, string password);
        Task UpdatePermissions(string userName, List<Permission> permissions);
    }
}
