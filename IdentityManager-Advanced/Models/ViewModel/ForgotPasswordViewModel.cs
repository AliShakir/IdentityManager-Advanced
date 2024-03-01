using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace IdentityManager_Advanced.Models.ViewModel
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        
    }
}
