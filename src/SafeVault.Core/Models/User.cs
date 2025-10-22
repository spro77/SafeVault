using System.ComponentModel.DataAnnotations;

namespace SafeVault.Core.Models;

public class User
{
    [Key]
    public int UserId { get; set; }
    
    [Required]
    [StringLength(100, MinimumLength = 3)]
    public string Username { get; set; } = string.Empty;
    
    [Required]
    [EmailAddress]
    [StringLength(100)]
    public string Email { get; set; } = string.Empty;
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}