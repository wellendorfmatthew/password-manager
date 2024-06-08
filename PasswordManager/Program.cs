using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using PasswordManager.Data;
using PasswordManager.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<PasswordManagerContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("PasswordManagerContext") ?? throw new InvalidOperationException("Connection string 'PasswordManagerContext' not found.")));

//builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
//    .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureAd"));cd 

builder.Services.AddControllersWithViews();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.ExpireTimeSpan = TimeSpan.FromMinutes(20); // Change later on to increase
        options.SlidingExpiration = true;
        options.AccessDeniedPath = "/Forbidden";
        options.LoginPath = "/Home/Signin";
        options.LogoutPath = "/Home/Signout";
    });

// Add services to the container.
/*builder.Services.AddControllersWithViews(options =>
{
    var policy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
    options.Filters.Add(new AuthorizeFilter(policy));
});*/
//builder.Services.AddRazorPages();
//    .AddMicrosoftIdentityUI();
/*builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.ExpireTimeSpan = TimeSpan.FromMinutes(20); // Change later on to increase
        options.SlidingExpiration = true;
        options.AccessDeniedPath = "/Forbidden";
        options.LoginPath = "/Home/Signin";
        options.LogoutPath = "/Home/Signout";
    }); 
*/
/*builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});*/
builder.Services.AddSession();
builder.Services.AddLogging(config =>
{
    config.AddConsole();
    config.AddDebug();
});

var cookiePolicyOptions = new CookiePolicyOptions
{
    MinimumSameSitePolicy = SameSiteMode.Strict,
};

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;

    try
    {
        SeedData.Initialize(services);
    }
    catch(Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred seeding the DB.");
    }
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseCookiePolicy(cookiePolicyOptions);
app.UseRouting();

//app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
//app.MapRazorPages();

app.Run();
