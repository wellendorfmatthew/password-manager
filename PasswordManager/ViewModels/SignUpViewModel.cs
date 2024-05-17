using System.ComponentModel.DataAnnotations;

namespace PasswordManager.ViewModels
{
    public class SignUpViewModel
    {
        [Required]
        [StringLength(50)]
        public string Username { get; set; }
        [Required]
        [StringLength(64, MinimumLength = 11)]
        public string Password { get; set; }
    }
}
