using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SafeVault.Core.Models;

namespace SafeVault.Core.Data;

public class SafeVaultDbContext : IdentityDbContext<User, Role, int>
{
    public SafeVaultDbContext(DbContextOptions<SafeVaultDbContext> options) 
        : base(options)
    {
    }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        
        // Configure User entity
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasIndex(e => e.Email).IsUnique();
            entity.Property(e => e.FullName).HasMaxLength(100);
        });
        
        // Seed default roles only
        modelBuilder.Entity<Role>().HasData(
            new Role 
            { 
                Id = 1, 
                Name = "Admin", 
                NormalizedName = "ADMIN",
                Description = "Administrator with full access",
                ConcurrencyStamp = "1"
            },
            new Role 
            { 
                Id = 2, 
                Name = "User", 
                NormalizedName = "USER",
                Description = "Regular user with limited access",
                ConcurrencyStamp = "2"
            }
        );
    }
}