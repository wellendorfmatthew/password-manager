namespace PasswordManager.ViewModels
{
    public class UserSession
    {
        public bool IsAuthenticated { get; set; } = false;
        public string? UserName { get; set; }
    }
}
