using System.ComponentModel.DataAnnotations;
namespace PasswordManager.Models
{
    public class Users
    {
        public int Id { get; set; }
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
