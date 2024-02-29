using IdentityManager_Advanced.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityManager_Advanced.Data
{
    public class ApplicationDbContext: IdentityDbContext
    {
        public ApplicationDbContext(DbContextOptions options) :base(options)
        {
            
        }
        public DbSet<ApplicationUser> ApplicationUser { get; set; }
    }
}
