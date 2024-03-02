using IdentityManager_Advanced.Common.Constants;
using Microsoft.AspNetCore.Authorization;

namespace IdentityManager_Advanced.Authorize
{
    public class OnlySuperAdminChecker : AuthorizationHandler<OnlySuperAdminChecker>, IAuthorizationRequirement
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, OnlySuperAdminChecker requirement)
        {
            if (context.User.IsInRole(UserRoleConstants.SuperAdmin))
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }
            return Task.CompletedTask;
        }
    }
}
