using Microsoft.EntityFrameworkCore;
using PasswordManager.Data;
namespace PasswordManager.Models
{
    public static class SeedData
    {
        public static void Initialize(IServiceProvider serviceProvider) 
        {
            using (var context = new PasswordManagerContext(
                serviceProvider.GetRequiredService<
                    DbContextOptions<PasswordManagerContext>>()))
            {
                if (context.Users.Any() && context.Passwords.Any()) // Checks if database has been seeded and a user with a password entry exists
                {
                    return;
                }

                context.Users.Add(
                    new Users
                    {
                        Username = "Eddy Gordo",
                        Password = "BEEPbeep6989$"
                    }
                    );
                context.Passwords.Add(
                    new Passwords
                    {
                        UserId = 1,
                        Password = "doubutsuANIMAL6989$",
                        Username = "Eddy",
                        Website = "Amazon",
                    }
                    );
                context.SaveChanges();
            }
        }
    }
}
