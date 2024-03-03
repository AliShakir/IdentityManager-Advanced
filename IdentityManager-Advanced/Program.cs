using IdentityManager_Advanced.Authorize;
using IdentityManager_Advanced.Common.Constants;
using IdentityManager_Advanced.Data;
using IdentityManager_Advanced.Models;
using IdentityManager_Advanced.Services;
using IdentityManager_Advanced.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Configure Database
builder.Services.AddDbContext<ApplicationDbContext>(options =>
options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddScoped<INumberOfDaysForAccount, NumberOfDaysForAccount>();
builder.Services.AddScoped<IAuthorizationHandler, AdminWithOver1000DaysHandler>();
// Configure Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Configure password
builder.Services.Configure<IdentityOptions>(opt =>
{
    opt.Password.RequireDigit = false;
    opt.Password.RequireLowercase = false;
    opt.Password.RequireNonAlphanumeric = false;
    opt.Lockout.MaxFailedAccessAttempts = 3;
    opt.Lockout.DefaultLockoutTimeSpan=TimeSpan.FromSeconds(10000);
    opt.SignIn.RequireConfirmedEmail = false;
});
builder.Services.AddAuthentication().AddMicrosoftAccount(opt =>
{
    opt.ClientId = "038436cc-769a-4b90-ad51-f2a3dac043f6";
    opt.ClientSecret = "U3P8Q~9Y0zkHF4d9VmDN8_lRoHLuV.3.yg_PMc.L";
});
//value - 
//id - 
builder.Services.AddAuthorization(opt =>
{
    opt.AddPolicy("Admin", policy => policy.RequireRole(UserRoleConstants.Admin));
    opt.AddPolicy("AdminAndUser", policy => policy.RequireRole(UserRoleConstants.Admin)
        .RequireRole(UserRoleConstants.User));
    opt.AddPolicy("AdminRole_CreateClaim", policy => policy.RequireRole(UserRoleConstants.Admin).RequireClaim("create","True"));
    opt.AddPolicy("AdminRole_CreateEditDeleteClaim", policy => 
        policy.RequireRole(UserRoleConstants.Admin)
        .RequireClaim("create", "True")
        .RequireClaim("edit", "True")
        .RequireClaim("delete", "True")
        );
    opt.AddPolicy("AdminRole_CreateEditDeleteClaim_ORSuperAdmin", policy => policy.RequireAssertion(context=>
    (    
        context.User.IsInRole(UserRoleConstants.Admin) 
        && context.User.HasClaim(c=>c.Type == "Create" && c.Value=="True")
        && context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True")
        && context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
    )
    || context.User.IsInRole(UserRoleConstants.SuperAdmin)));
    opt.AddPolicy("OnlySuperAdminChecker", p => p.Requirements.Add(new OnlySuperAdminChecker()));
    opt.AddPolicy("AdminWithMoreThan1000Days", p => p.Requirements.Add(new AdminWithMoreThan1000DaysRequirement(1000)));
});
//
builder.Services.ConfigureApplicationCookie(opt =>
{
    opt.AccessDeniedPath = new PathString("/Account/NoAccess");
});
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
