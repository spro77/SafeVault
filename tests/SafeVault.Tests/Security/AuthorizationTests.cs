using NUnit.Framework;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SafeVault.Core.Data;
using SafeVault.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace SafeVault.Tests.Security;

[TestFixture]
public class AuthorizationTests
{
    private SafeVaultDbContext _context;
    private UserManager<User> _userManager;
    private RoleManager<Role> _roleManager;

    [SetUp]
    public void Setup()
    {
        var options = new DbContextOptionsBuilder<SafeVaultDbContext>()
            .UseInMemoryDatabase(databaseName: "AuthzTestDb_" + Guid.NewGuid())
            .Options;

        _context = new SafeVaultDbContext(options);
        
        var userStore = new Microsoft.AspNetCore.Identity.EntityFrameworkCore.UserStore<User, Role, SafeVaultDbContext, int>(_context);
        _userManager = new UserManager<User>(
            userStore,
            new Mock<IOptions<IdentityOptions>>().Object,
            new PasswordHasher<User>(),
            Array.Empty<IUserValidator<User>>(),
            Array.Empty<IPasswordValidator<User>>(),
            new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(),
            new Mock<IServiceProvider>().Object,
            new Mock<ILogger<UserManager<User>>>().Object);

        var roleStore = new Microsoft.AspNetCore.Identity.EntityFrameworkCore.RoleStore<Role, SafeVaultDbContext, int>(_context);
        _roleManager = new RoleManager<Role>(
            roleStore,
            Array.Empty<IRoleValidator<Role>>(),
            new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(),
            new Mock<ILogger<RoleManager<Role>>>().Object);

        // Create roles
        _roleManager.CreateAsync(new Role { Name = "Admin", NormalizedName = "ADMIN" }).Wait();
        _roleManager.CreateAsync(new Role { Name = "User", NormalizedName = "USER" }).Wait();
    }

    [TearDown]
    public void TearDown()
    {
        _userManager?.Dispose();
        _roleManager?.Dispose();
        _context.Database.EnsureDeleted();
        _context.Dispose();
    }

    [Test]
    public async Task UserRole_ShouldBeAssignedCorrectly()
    {
        // Arrange
        var user = new User
        {
            UserName = "testuser",
            Email = "test@test.com",
            FullName = "Test User"
        };
        
        await _userManager.CreateAsync(user, "Test@123");
        
        // Act
        await _userManager.AddToRoleAsync(user, "User");
        
        // Assert
        var isInRole = await _userManager.IsInRoleAsync(user, "User");
        Assert.That(isInRole, Is.True);
        
        var isAdmin = await _userManager.IsInRoleAsync(user, "Admin");
        Assert.That(isAdmin, Is.False);
    }

    [Test]
    public async Task AdminRole_ShouldBeAssignedCorrectly()
    {
        // Arrange
        var admin = new User
        {
            UserName = "admin",
            Email = "admin@test.com",
            FullName = "Admin User"
        };
        
        await _userManager.CreateAsync(admin, "Admin@123");
        
        // Act
        await _userManager.AddToRoleAsync(admin, "Admin");
        
        // Assert
        var isAdmin = await _userManager.IsInRoleAsync(admin, "Admin");
        Assert.That(isAdmin, Is.True);
    }

    [Test]
    public async Task User_CanHaveMultipleRoles()
    {
        // Arrange
        var user = new User
        {
            UserName = "multiuser",
            Email = "multi@test.com",
            FullName = "Multi Role User"
        };
        
        await _userManager.CreateAsync(user, "Multi@123");
        
        // Act
        await _userManager.AddToRoleAsync(user, "User");
        await _userManager.AddToRoleAsync(user, "Admin");
        
        // Assert
        var isUser = await _userManager.IsInRoleAsync(user, "User");
        var isAdmin = await _userManager.IsInRoleAsync(user, "Admin");
        
        Assert.That(isUser, Is.True);
        Assert.That(isAdmin, Is.True);
        
        var roles = await _userManager.GetRolesAsync(user);
        Assert.That(roles.Count, Is.EqualTo(2));
    }

    [Test]
    public async Task RemoveFromRole_ShouldWork()
    {
        // Arrange
        var user = new User
        {
            UserName = "removeuser",
            Email = "remove@test.com",
            FullName = "Remove User"
        };
        
        await _userManager.CreateAsync(user, "Remove@123");
        await _userManager.AddToRoleAsync(user, "Admin");
        
        // Act
        await _userManager.RemoveFromRoleAsync(user, "Admin");
        
        // Assert
        var isAdmin = await _userManager.IsInRoleAsync(user, "Admin");
        Assert.That(isAdmin, Is.False);
    }

    [Test]
    public async Task GetUsersInRole_ShouldReturnCorrectUsers()
    {
        // Arrange
        var admin1 = new User { UserName = "admin1", Email = "admin1@test.com", FullName = "Admin 1" };
        var admin2 = new User { UserName = "admin2", Email = "admin2@test.com", FullName = "Admin 2" };
        var user1 = new User { UserName = "user1", Email = "user1@test.com", FullName = "User 1" };
        
        await _userManager.CreateAsync(admin1, "Admin1@123");
        await _userManager.CreateAsync(admin2, "Admin2@123");
        await _userManager.CreateAsync(user1, "User1@123");
        
        await _userManager.AddToRoleAsync(admin1, "Admin");
        await _userManager.AddToRoleAsync(admin2, "Admin");
        await _userManager.AddToRoleAsync(user1, "User");
        
        // Act
        var admins = await _userManager.GetUsersInRoleAsync("Admin");
        
        // Assert
        Assert.That(admins.Count, Is.EqualTo(2));
        Assert.That(admins.Any(u => u.UserName == "admin1"), Is.True);
        Assert.That(admins.Any(u => u.UserName == "admin2"), Is.True);
        Assert.That(admins.Any(u => u.UserName == "user1"), Is.False);
    }

    [Test]
    public async Task RoleBasedAccess_ShouldBeEnforced()
    {
        // Arrange - Create admin and regular user
        var admin = new User { UserName = "admin", Email = "admin@test.com", FullName = "Admin" };
        var user = new User { UserName = "user", Email = "user@test.com", FullName = "User" };
        
        await _userManager.CreateAsync(admin, "Admin@123");
        await _userManager.CreateAsync(user, "User@123");
        
        await _userManager.AddToRoleAsync(admin, "Admin");
        await _userManager.AddToRoleAsync(user, "User");
        
        // Act & Assert - Check access rights
        var adminCanAccessAdminFeatures = await _userManager.IsInRoleAsync(admin, "Admin");
        var userCanAccessAdminFeatures = await _userManager.IsInRoleAsync(user, "Admin");
        
        Assert.That(adminCanAccessAdminFeatures, Is.True, "Admin should have admin access");
        Assert.That(userCanAccessAdminFeatures, Is.False, "Regular user should NOT have admin access");
    }
}