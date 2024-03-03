using IdentityManager_Advanced.Data;
using IdentityManager_Advanced.Services.IServices;

namespace IdentityManager_Advanced.Services
{
    public class NumberOfDaysForAccount : INumberOfDaysForAccount
    {
        private readonly ApplicationDbContext _db;
        public NumberOfDaysForAccount(ApplicationDbContext db)
        {
            _db = db;
        }
        public int Get(string userId)
        {
            var user = _db.ApplicationUser.FirstOrDefault(c => c.Id == userId);
            if (user != null && user.CreatedDate != DateTime.MinValue)
            {
                return (DateTime.Today - user.CreatedDate).Days;
            }
            return 0;
        }
    }
}
