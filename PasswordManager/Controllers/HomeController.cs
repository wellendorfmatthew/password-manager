using Microsoft.AspNetCore.Mvc;
using PasswordManager.Models;
using PasswordManager.Data;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System;
using System.Collections;
using PasswordManager.ViewModels;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

namespace PasswordManager.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly PasswordManagerContext _context;

        public HomeController(ILogger<HomeController> logger, PasswordManagerContext context)
        {
            _logger = logger;
            _context = context;
        }

        [HttpGet]
        public IActionResult Index()
        {
            const string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string lowercase = "abcdefghijklmnopqrstuvwxyz";
            const string numbers = "0123456789";
            const string specialCharacters = "!@#$%^&*_+-?";
            string allCharacters = uppercase + lowercase + numbers + specialCharacters;
            string password = "";
            Random random = new Random();

            password += uppercase[random.Next(uppercase.Length)];
            password += lowercase[random.Next(lowercase.Length)];
            password += numbers[random.Next(numbers.Length)];
            password += specialCharacters[random.Next(specialCharacters.Length)];

            for (int i = 0; i < 7; i++)
            {
                password += allCharacters[random.Next(allCharacters.Length)];
            }

            var model = new PasswordGeneratorViewModel
            {
                Length = 11,
                IncludeUpper = true,
                IncludeLower = true,
                IncludeNumbers = true,
                IncludeSymbols = true,
                PasswordStrength = "Strong Password",
                GeneratedPassword = password
            };

            return View(model);
        }

        [HttpGet]
        public IActionResult Signin()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Signin(SignInViewModel model)
        {
            _logger.LogInformation($"{ModelState.IsValid}");
            if (ModelState.IsValid) 
            {
                String hashedPassword = HashPassword(model.Password);
                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.Username == model.Username && u.Password == hashedPassword);
                _logger.LogInformation($"{user} yo");

                if (user != null)
                {
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.Username),
                        new Claim("Password", hashedPassword),
                        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
                    };

                    var claimsIdentity = new ClaimsIdentity(
                        claims, CookieAuthenticationDefaults.AuthenticationScheme);

                    var authProperties = new AuthenticationProperties
                    {
                        AllowRefresh = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                        IsPersistent = true,
                        IssuedUtc = DateTimeOffset.UtcNow,
                        RedirectUri = Url.Action("Index", "Home")
                    };


                    // HttpContext.Session.SetString("Username", user.Username);
                    await HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        new ClaimsPrincipal(claimsIdentity),
                        authProperties);

                    _logger.LogInformation($"{user.Username} has logged in");

                    return RedirectToAction("Index");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid username or password please try again");
                    _logger.LogInformation("Cant login");
                }
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult Signup()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignUpViewModel model)
        {
            if (ModelState.IsValid) 
            {
                if (await _context.Users.AnyAsync(u => u.Username == model.Username)) 
                {
                    ModelState.AddModelError(string.Empty, "User already exists, please sign in instead");
                    return View(model);
                }

                var user = new Users
                {
                    Username = model.Username,
                    Password = HashPassword(model.Password)
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.Username),
                        new Claim("Password", user.Password),
                        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
                    };

                var claimsIdentity = new ClaimsIdentity(
                    claims, CookieAuthenticationDefaults.AuthenticationScheme);

                var authProperties = new AuthenticationProperties
                {
                    AllowRefresh = true,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                    IsPersistent = true,
                    IssuedUtc = DateTimeOffset.UtcNow,
                    RedirectUri = Url.Action("Index", "Home")
                };


                // HttpContext.Session.SetString("Username", user.Username);
                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);

                _logger.LogInformation($"{user.Username} has signed up");

                return RedirectToAction("Index");
            }

            return View(model);
        }

        [Authorize]
        public IActionResult NewPassword()
        {
            return View();
        }

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> NewPassword(Passwords model)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);

            if (userIdClaim == null) 
            {
                return Unauthorized();
            }

            int userId = int.Parse(userIdClaim.Value);

            var password = new Passwords
            {
                Username = model.Username,
                Password = model.Password,
                Website = model.Website,
                UserId = userId
            };

            _context.Passwords.Add(password);
            await _context.SaveChangesAsync();

            return RedirectToAction("PasswordManager");
        }

        [Authorize]
        public async Task<IActionResult> PasswordManager()
        {
            var passwords = await GetUserPasswords();

            if (passwords  == null || !passwords.Any()) 
            { 
                return Unauthorized(); // Will likely need to change later
            }

            return View(passwords);
        }

        public async Task<IEnumerable<Passwords>> GetUserPasswords()
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);

            if (userIdClaim == null)
            {
                return [];
            }

            int userId = int.Parse(userIdClaim.Value);

            return await _context.Passwords.Where(p => p.UserId == userId).ToListAsync();
        }

        [Authorize]
        public async Task<IActionResult> Report()
        {
            ReportModel model = new()
            {
                IdenticalPasswords = await NonUniquePasswords(),
                WeakPasswords = await WeakPasswords()
            };

            return View(model);
        }

        public async Task<List<Passwords>> NonUniquePasswords()
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);

            if (userIdClaim == null)
            {
                return [];
            }

            int userId = int.Parse(userIdClaim.Value);

            List<Passwords> passwords = await _context.Passwords
                .Where(p => p.UserId == userId)
                .ToListAsync();

            var nonUniquePasswordGroups = passwords
                .GroupBy(p => p.Password)
                .Where(g => g.Count() > 1)
                .ToList();

            List<Passwords> nonUniquePasswords = nonUniquePasswordGroups
                .SelectMany(g => g)
                .ToList();

            return nonUniquePasswords;
        }

        public async Task<Dictionary<Passwords, string>> WeakPasswords()
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
            Dictionary<Passwords, string> weakPasswords = [];
            const string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string lowercase = "abcdefghijklmnopqrstuvwxyz";
            const string numbers = "0123456789";
            const string specialCharacters = "!@#$%^&*_+-?";

            if (userIdClaim == null)
            {
                return weakPasswords;
            }

            int userId = int.Parse(userIdClaim.Value);

            List<Passwords> passwords = await _context.Passwords
                .Where(p => p.UserId == userId)
                .ToListAsync();

            foreach(var password in passwords)
            {
                string statement = "";

                if (password.Password.Length < 11)
                {
                    statement += "Password must contain at least 11 characters";
                }

                if (!password.Password.Any(c => uppercase.Contains(c)))
                {
                    statement += "Password must contain at least one upper case character";
                }

                if (!password.Password.Any(c => lowercase.Contains(c)))
                {
                    statement += "Password must contain at least one lower case character";
                }

                if (!password.Password.Any(c => numbers.Contains(c)))
                {
                    statement += "Password must contain at least one number";
                }

                if (!password.Password.Any(c => specialCharacters.Contains(c)))
                {
                    statement += "Password must contain at least one special character";
                }

                if (!string.IsNullOrEmpty(statement))
                {
                    weakPasswords.Add(password, statement);
                }
            }

            return weakPasswords;
        }

        [Authorize]
        [HttpGet("EditPassword/{id}")]
        public async Task<IActionResult> EditPassword(int id)
        {
            _logger.LogInformation($"Logging {id}");

            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);

            if (userIdClaim == null)
            {
                return Unauthorized();
            }

            int userId = int.Parse(userIdClaim.Value);

            Passwords password = await _context.Passwords.Where(p => p.UserId == userId && p.Id == id).FirstAsync();

            return View(password);
        }

        [Authorize]
        [HttpPut("EditPassword/{id}")]
        public async Task<IActionResult> EditPassword([FromBody] Passwords model,  int id)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);

            if (userIdClaim == null)
            {
                return Unauthorized();
            }

            int userId = int.Parse(userIdClaim.Value);

            await _context.Passwords.Where(p => p.UserId == userId && p.Id == id).ExecuteUpdateAsync(setters => setters
                .SetProperty(p => p.Username, model.Username)
                .SetProperty(p => p.Password, model.Password)
                .SetProperty(p => p.Notes, model.Notes)
                );

            await _context.SaveChangesAsync();

            return Json(new
            { 
                Username = model.Username,
                Password = model.Password,
                Notes = model.Notes,
            });
        }

        [Authorize]
        [HttpDelete("DeletePassword/{id}")]
        public async Task<IActionResult> DeletePassword(int id)
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);

            if (userIdClaim == null)
            {
                return Unauthorized();
            }

            int userId = int.Parse(userIdClaim.Value);

            await _context.Passwords.Where(p => p.UserId == userId && p.Id == id).ExecuteDeleteAsync();

            await _context.SaveChangesAsync();

            return Json(new { redirectToUrl = Url.Action("PasswordManager", "Home") });
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create()) 
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                StringBuilder builder = new StringBuilder();
                foreach (var b in bytes)
                {
                    builder.Append(b.ToString("x2"));
                }
                return builder.ToString();
            }
        }

        [HttpPost]
        public IActionResult GeneratePassword([FromBody] PasswordGeneratorViewModel model)
        {
            _logger.LogInformation($"{model.GeneratedPassword}y");
            const string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string lowercase = "abcdefghijklmnopqrstuvwxyz";
            const string numbers = "0123456789";
            const string specialCharacters = "!@#$%^&*_+-?";
            string allCharacters = "";
            string password = "";
            int score = 0;
            Random random = new Random();

            if (model.IncludeUpper)
            {
                password += uppercase[random.Next(uppercase.Length)];
                allCharacters += uppercase;
                score++;
            }

            if (model.IncludeLower)
            {
                password += lowercase[random.Next(lowercase.Length)];
                allCharacters += lowercase;
                score++;
            }

            if (model.IncludeNumbers)
            {
                password += numbers[random.Next(numbers.Length)];
                allCharacters += numbers;
                score++;
            }

            if (model.IncludeSymbols)
            {
                password += specialCharacters[random.Next(specialCharacters.Length)];
                allCharacters += specialCharacters;
                score++;
            }

            for (int i = 0; i < model.Length - 4; i++)
            {
                password += allCharacters[random.Next(allCharacters.Length)];
            }

            model.GeneratedPassword = password;
            _logger.LogInformation($"{model.GeneratedPassword}");

            if (score == 4 && password.Length >= 11)
            {
                model.PasswordStrength = "Strong Password";
            }
            else
            {
                model.PasswordStrength = "Weak Password";
            }

            var newModel = new PasswordGeneratorViewModel
            {
                Length = password.Length,
                IncludeUpper = model.IncludeUpper,
                IncludeLower = model.IncludeLower,
                IncludeNumbers = model.IncludeNumbers,
                IncludeSymbols = model.IncludeSymbols,
                PasswordStrength = model.PasswordStrength,
                GeneratedPassword = password
            };

            return Json(new
            {
                GeneratedPassword = model.GeneratedPassword,
                PasswordStrength = model.PasswordStrength
            });
        }
    }
}
