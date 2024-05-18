namespace PasswordManager.ViewModels
{
    public class PasswordGeneratorViewModel
    {
        public int Length { get; set; } = 11;
        public bool IncludeUpper { get; set; }
        public bool IncludeLower { get; set; }
        public bool IncludeNumbers { get; set; }
        public bool IncludeSymbols { get; set; }
        public string GeneratedPassword { get; set; }
        public string PasswordStrength { get; set; }
    }
}
