using System.Security.Claims;

namespace IdentityManager_Advanced.Common.Constants
{
    public class ClaimStore
    {
        public static List<Claim> claimsList =
            [
                new Claim("Create", "Create"),
                new Claim("Edit", "Edit"),
                new Claim("Delete", "Delete")
            ];
    }
}
