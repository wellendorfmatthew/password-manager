using Microsoft.AspNetCore.Mvc;
using PasswordManager.Models;
using PasswordManager.Data;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;

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

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Signin()
        {
            return View();
        }

        public IActionResult Signup()
        {
            return View();
        }

        public IActionResult NewPassword()
        {
            return View();
        }

        public IActionResult PasswordManager()
        {
            return View();
        }

        public IActionResult Report()
        {
            return View();
        }

        public IActionResult EditPassword()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
