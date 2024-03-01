using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace IdentityManager_Advanced.Models.ViewModel
{
    public class VerifyAuthenticatorViewModel
    {
        [Required]
        public string Code { get; set; }
        public string? ReturnUrl { get; set; }
        [Display(Name="Remember me?")]
        public bool RememberMe { get; set; }
    }
}
