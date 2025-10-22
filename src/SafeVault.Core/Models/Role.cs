using Microsoft.AspNetCore.Identity;

namespace SafeVault.Core.Models;

public class Role : IdentityRole<int>
{
    // IdentityRole provides:
    // - Id
    // - Name
    // - NormalizedName
    
    public string? Description { get; set; }
}