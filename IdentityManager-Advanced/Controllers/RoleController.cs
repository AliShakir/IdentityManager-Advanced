using IdentityManager_Advanced.Data;
using IdentityManager_Advanced.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityManager_Advanced.Controllers
{
    public class RoleController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public RoleController(ApplicationDbContext context, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
        }
        [HttpGet]

        public IActionResult Index()
        {
            return View(_context.Roles.ToList());
        }
        public IActionResult Upsert(string roleId)
        {
            if (string.IsNullOrEmpty(roleId))
            {
                // create
                return View();
            }
            else
            {
                // update
                var result = _context.Roles.Where(c => c.Id == roleId).FirstOrDefault();
                return View(result);
            }
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upsert(IdentityRole model)
        {
            if (await _roleManager.RoleExistsAsync(model.Name))
            {
                // Error

            }
            if (string.IsNullOrEmpty(model.NormalizedName))
            {
                // create
                await _roleManager.CreateAsync(new IdentityRole { Name = model.Name });
                TempData["success"] = "Role created successfully.";
            }
            else
            {
                // update
                var existingRole = _context.Roles.FirstOrDefault(c => c.Id == model.Id);
                existingRole.Name = model.Name;
                existingRole.NormalizedName = model.NormalizedName;
                var result = await _roleManager.UpdateAsync(existingRole);
                TempData["success"] = "Role updated successfully.";

            }
            return RedirectToAction(nameof(Index));
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "OnlySuperAdminChecker")]
        public async Task<IActionResult> Delete(string roleId)
        {
            // delete
            var existingRole = _context.Roles.FirstOrDefault(c => c.Id == roleId);
            if(existingRole != null)
            {

                var userRolesForThisRole = _context.UserRoles.Where(c => c.RoleId == roleId).Count();
                if(userRolesForThisRole > 0)
                {
                    TempData["error"] = "Cannot delete this role, since there are users assigned this role";
                    return RedirectToAction(nameof(Index));
                }
                await _roleManager.DeleteAsync(existingRole);
                TempData["success"] = "Role deleted successfully.";
            }
            return RedirectToAction(nameof(Index));
        }
    }
}
