using Microsoft.AspNetCore.Identity;
using SafeVault.Core.Models;

namespace SafeVault.Core.Data;

public static class DbInitializer
{
    public static async Task SeedAsync(UserManager<User> userManager, RoleManager<Role> roleManager)
    {
        // Check if admin user already exists
        var adminUser = await userManager.FindByNameAsync("admin");
        if (adminUser == null)
        {
            // Create admin user
            adminUser = new User
            {
                UserName = "admin",
                Email = "admin@safevault.com",
                EmailConfirmed = true,
                FullName = "System Administrator",
                CreatedAt = DateTime.UtcNow
            };

            var result = await userManager.CreateAsync(adminUser, "Admin@123");
            
            if (result.Succeeded)
            {
                // Assign Admin role
                await userManager.AddToRoleAsync(adminUser, "Admin");
            }
        }

        // Create a regular test user if doesn't exist
        var testUser = await userManager.FindByNameAsync("testuser");
        if (testUser == null)
        {
            testUser = new User
            {
                UserName = "testuser",
                Email = "test@safevault.com",
                EmailConfirmed = true,
                FullName = "Test User",
                CreatedAt = DateTime.UtcNow
            };

            var result = await userManager.CreateAsync(testUser, "Test@123");
            
            if (result.Succeeded)
            {
                // Assign User role
                await userManager.AddToRoleAsync(testUser, "User");
            }
        }
    }
}