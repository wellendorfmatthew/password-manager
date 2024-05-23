using PasswordManager.Models;
using System.Collections.Generic;

namespace PasswordManager.ViewModels
{
    public class ReportModel
    {
        public List<Passwords> IdenticalPasswords { get; set; }
        public Dictionary<Passwords, string> WeakPasswords { get; set; }
    }
}
