using Microsoft.EntityFrameworkCore;
namespace PasswordManager.Data
{
    public class PasswordManagerContext : DbContext
    {
        public PasswordManagerContext(DbContextOptions<PasswordManagerContext> options)
            : base(options)
        {
        }

        public DbSet<PasswordManager.Models.Users> Users { get; set; }
        public DbSet<PasswordManager.Models.Passwords> Passwords { get; set; }
    }
}
