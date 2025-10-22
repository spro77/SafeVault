using Microsoft.EntityFrameworkCore;
using SafeVault.Core.Models;

namespace SafeVault.Core.Data;

public class SafeVaultDbContext : DbContext
{
    public SafeVaultDbContext(DbContextOptions<SafeVaultDbContext> options) 
        : base(options)
    {
    }
    
    public DbSet<User> Users { get; set; }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        
        // Configure User entity
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.UserId);
            entity.Property(e => e.Username).IsRequired().HasMaxLength(100);
            entity.Property(e => e.Email).IsRequired().HasMaxLength(100);
            entity.HasIndex(e => e.Email).IsUnique();
        });
    }
}