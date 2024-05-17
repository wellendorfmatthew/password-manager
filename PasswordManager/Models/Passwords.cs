using System.ComponentModel.DataAnnotations;

namespace PasswordManager.Models
{
    public class Passwords
    {
        public int Id { get; set; }
        [Required]
        public int UserId { get; set; } // Foreign Key to Users table
        [Required]
        public string Password { get; set; }
        [Required]
        public string Username { get; set; }
        [Required]
        public string Website { get; set; }
        public string? Notes { get; set; }
    }
}
