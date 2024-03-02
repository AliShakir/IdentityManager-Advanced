using IdentityManager_Advanced.Common.Constants;
using IdentityManager_Advanced.Data;
using IdentityManager_Advanced.Models;
using IdentityManager_Advanced.Models.ViewModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace IdentityManager_Advanced.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public UserController(ApplicationDbContext context, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
        }
        [HttpGet]

        public async Task<IActionResult> Index()
        {
            var userList = _context.ApplicationUser.ToList();
            var roleList = _context.UserRoles.ToList();
            var roles = _context.Roles.ToList();
            foreach (var user in userList)
            {
                var userRole = await _userManager.GetRolesAsync(user) as List<string>;
                user.Role = string.Join(",", userRole);
                var userClaim = _userManager.GetClaimsAsync(user).GetAwaiter().GetResult().Select(c => c.Type);
                user.UserClaim = string.Join(",", userClaim);

            }
            return View(userList);
        }
        public async Task<IActionResult> ManageRole(string userId)
        {
            ApplicationUser user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            List<string> exsitingUserRoles = await _userManager.GetRolesAsync(user) as List<string>;
            var model = new RolesViewModel()
            {
                User = user
            };

            foreach (var role in _roleManager.Roles)
            {
                RoleSelection roleSelection = new()
                {
                    RoleName = role.Name
                };
                if (exsitingUserRoles.Any(c => c == role.Name))
                {
                    roleSelection.IsSelected = true;
                }
                model.RolesList.Add(roleSelection);
            }
            return View(model);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageRole(RolesViewModel rolesViewModel)
        {
            ApplicationUser user = await _userManager.FindByIdAsync(rolesViewModel.User.Id);
            if (user == null)
            {
                return NotFound();
            }

            var oldUserRoles = await _userManager.GetRolesAsync(user);
            var result = await _userManager.RemoveFromRolesAsync(user, oldUserRoles);
            if (!result.Succeeded)
            {
                TempData["error"] = "Error while removing roles";
                return View(rolesViewModel);
            }

            result = await _userManager.AddToRolesAsync(user,
                rolesViewModel.RolesList.Where(c => c.IsSelected).Select(c => c.RoleName));

            if (!result.Succeeded)
            {
                TempData["error"] = "Error while adding roles";
                return View(rolesViewModel);
            }

            TempData["success"] = "Roles assigned successfully.";
            return RedirectToAction(nameof(Index));
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LockUnlock(string userId)
        {
            ApplicationUser user = _context.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if (user == null)
            {
                return NotFound();
            }
            if (user.LockoutEnd != null && user.LockoutEnd > DateTime.Now)
            {
                //user is locked and will remain locked untill lockoutend time
                //clicking on this action will unlock them
                user.LockoutEnd = DateTime.Now;
                TempData["success"] = "User unlocked successfully";
            }
            else
            {
                //user is not locked, and we want to lock the user
                user.LockoutEnd = DateTime.Now.AddYears(1000);
                TempData["success"] = "User locked successfully";
            }
            _context.SaveChanges();

            return RedirectToAction(nameof(Index));
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteUser(string userId)
        {
            var user = _context.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if (user == null)
            {
                return NotFound();
            }

            _context.ApplicationUser.Remove(user);
            _context.SaveChanges();
            TempData["success"] = "User deleted successfully";
            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> ManageUserClaim(string userId)
        {
            ApplicationUser user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            var exsitingUserClaims = await _userManager.GetClaimsAsync(user);
            var model = new ClaimViewModel()
            {
                User = user
            };

            foreach (Claim claim in ClaimStore.claimsList)
            {
                ClaimSelection userClaim = new()
                {
                    ClaimType = claim.Type
                };
                if (exsitingUserClaims.Any(c => c.Type == claim.Type))
                {
                    userClaim.IsSelected = true;
                }
                model.ClaimsList.Add(userClaim);
            }
            return View(model);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageUserClaim(ClaimViewModel claimsViewModel)
        {
            ApplicationUser user = await _userManager.FindByIdAsync(claimsViewModel.User.Id);
            if (user == null)
            {
                return NotFound();
            }

            var oldClaims = await _userManager.GetClaimsAsync(user);
            var result = await _userManager.RemoveClaimsAsync(user, oldClaims);

            if (!result.Succeeded)
            {
                TempData["error"] = "Error while removing claims";
                return View(claimsViewModel);
            }

            result = await _userManager.AddClaimsAsync(user,
                claimsViewModel.ClaimsList.Where(x => x.IsSelected).Select(y => new Claim(y.ClaimType, y.IsSelected.ToString())));

            if (!result.Succeeded)
            {
                TempData["error"] = "Error while adding claims";
                return View(claimsViewModel);
            }

            TempData["success"] = "Claims assigned successfully";
            return RedirectToAction(nameof(Index));
        }
    }
}
