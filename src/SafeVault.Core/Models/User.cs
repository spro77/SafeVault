using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace SafeVault.Core.Models;

// Inherit from IdentityUser to get authentication features
public class User : IdentityUser<int>
{
    // IdentityUser already provides:
    // - Id (we override to use int instead of string)
    // - UserName
    // - Email
    // - PasswordHash
    // - SecurityStamp
    // - etc.

    [StringLength(100)]
    public string? FullName { get; set; }
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? LastLoginAt { get; set; }
    
    // For our original UserId compatibility
    public int UserId => Id;
}