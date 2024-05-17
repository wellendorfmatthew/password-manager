using System.ComponentModel.DataAnnotations;

namespace PasswordManager.ViewModels
{
    public class SignInViewModel
    {
        [Required]
        public string Username { get; set; }
        [Required]
        [DataType(DataType.Password)] // This will let the Razor view to generate an html input field that's of type password
        public string Password { get; set; }
    }
}
