using NUnit.Framework;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SafeVault.Core.Data;
using SafeVault.Core.Models;
using SafeVault.Core.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace SafeVault.Tests.Security;

[TestFixture]
public class AuthenticationTests
{
    private SafeVaultDbContext _context;
    private UserManager<User> _userManager;
    private RoleManager<Role> _roleManager;
    private IAuthenticationService _authService;
    private IInputValidationService _validationService;
    private SignInManager<User> _signInManager;

    [SetUp]
public void Setup()
{
    // Create in-memory database
    var options = new DbContextOptionsBuilder<SafeVaultDbContext>()
        .UseInMemoryDatabase(databaseName: "AuthTestDb_" + Guid.NewGuid())
        .Options;

    _context = new SafeVaultDbContext(options);
    
    // Setup UserManager with password options
    var userStore = new Microsoft.AspNetCore.Identity.EntityFrameworkCore.UserStore<User, Role, SafeVaultDbContext, int>(_context);
    
    var identityOptions = new IdentityOptions
    {
        Password = new PasswordOptions
        {
            RequireDigit = true,
            RequireLowercase = true,
            RequireUppercase = true,
            RequireNonAlphanumeric = true,
            RequiredLength = 8,
            RequiredUniqueChars = 1
        }
    };
    
    _userManager = new UserManager<User>(
        userStore,
        Options.Create(identityOptions),
        new PasswordHasher<User>(),
        new IUserValidator<User>[] { },  // User validators
        new IPasswordValidator<User>[] { new PasswordValidator<User>() },  // Password validators
        new UpperInvariantLookupNormalizer(),
        new IdentityErrorDescriber(),
        new Mock<IServiceProvider>().Object,
        new Mock<ILogger<UserManager<User>>>().Object);

    // Setup RoleManager
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

    // Setup SignInManager (mock)
    var contextAccessor = new Mock<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
    var claimsFactory = new Mock<IUserClaimsPrincipalFactory<User>>();
    
    _signInManager = new SignInManager<User>(
        _userManager,
        contextAccessor.Object,
        claimsFactory.Object,
        Options.Create(identityOptions),
        new Mock<ILogger<SignInManager<User>>>().Object,
        new Mock<Microsoft.AspNetCore.Authentication.IAuthenticationSchemeProvider>().Object,
        new Mock<IUserConfirmation<User>>().Object);

    _validationService = new InputValidationService();
    _authService = new AuthenticationService(_userManager, _signInManager, _validationService);
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
    public async Task RegisterAsync_WithValidData_ShouldCreateUser()
    {
        // Arrange
        var username = "newuser";
        var email = "newuser@test.com";
        var password = "Test@123";
        var fullName = "New User";

        // Act
        var result = await _authService.RegisterAsync(username, email, password, fullName);

        // Assert
        Assert.That(result.Succeeded, Is.True);
        
        var user = await _userManager.FindByNameAsync(username);
        Assert.That(user, Is.Not.Null);
        Assert.That(user.Email, Is.EqualTo(email));
        Assert.That(user.FullName, Is.EqualTo(fullName));
    }

    [Test]
    public async Task RegisterAsync_WithWeakPassword_ShouldFail()
    {
        // Arrange
        var username = "testuser";
        var email = "test@test.com";
        var weakPassword = "abc"; // Too short - minimum is 6 by default

        // Act
        var result = await _authService.RegisterAsync(username, email, weakPassword, "Test User");

        // Assert
        Assert.That(result.Succeeded, Is.False, "Weak password should be rejected");
        Assert.That(result.Errors, Is.Not.Empty, "Should have validation errors");
    }

    [Test]
    public async Task RegisterAsync_WithInvalidUsername_ShouldFail()
    {
        // Arrange
        var invalidUsername = "<script>alert('xss')</script>";
        var email = "test@test.com";
        var password = "Test@123";

        // Act
        var result = await _authService.RegisterAsync(invalidUsername, email, password, "Test User");

        // Assert
        Assert.That(result.Succeeded, Is.False);
        Assert.That(result.Errors.Any(e => e.Description.Contains("Invalid username format")), Is.True);
    }

    [Test]
    public async Task RegisterAsync_WithSqlInjectionInUsername_ShouldFail()
    {
        // Arrange
        var maliciousUsername = "admin'; DROP TABLE Users--";
        var email = "test@test.com";
        var password = "Test@123";

        // Act
        var result = await _authService.RegisterAsync(maliciousUsername, email, password, "Test User");

        // Assert
        Assert.That(result.Succeeded, Is.False);
        Assert.That(result.Errors.Any(e => e.Description.Contains("Invalid username format")), Is.True);
    }

    [Test]
    public async Task RegisterAsync_WithInvalidEmail_ShouldFail()
    {
        // Arrange
        var username = "testuser";
        var invalidEmail = "not-an-email";
        var password = "Test@123";

        // Act
        var result = await _authService.RegisterAsync(username, invalidEmail, password, "Test User");

        // Assert
        Assert.That(result.Succeeded, Is.False);
        Assert.That(result.Errors.Any(e => e.Description.Contains("Invalid email format")), Is.True);
    }

    [Test]
    public async Task RegisterAsync_ShouldHashPassword()
    {
        // Arrange
        var username = "secureuser";
        var email = "secure@test.com";
        var password = "MyPassword@123";

        // Act
        var result = await _authService.RegisterAsync(username, email, password, "Secure User");

        // Assert
        Assert.That(result.Succeeded, Is.True);
        
        var user = await _userManager.FindByNameAsync(username);
        Assert.That(user, Is.Not.Null);
        Assert.That(user.PasswordHash, Is.Not.Null);
        Assert.That(user.PasswordHash, Is.Not.EqualTo(password), "Password should be hashed, not stored in plain text");
        
        // Verify password can be verified
        var passwordValid = await _userManager.CheckPasswordAsync(user, password);
        Assert.That(passwordValid, Is.True);
    }

    [Test]
    public async Task PasswordHash_ShouldBeDifferentForSamePassword()
    {
        // Arrange & Act - Create two users with same password
        await _authService.RegisterAsync("user1", "user1@test.com", "Same@Password123", "User One");
        await _authService.RegisterAsync("user2", "user2@test.com", "Same@Password123", "User Two");

        var user1 = await _userManager.FindByNameAsync("user1");
        var user2 = await _userManager.FindByNameAsync("user2");

        // Assert - Hashes should be different (salted)
        Assert.That(user1.PasswordHash, Is.Not.EqualTo(user2.PasswordHash), 
            "Password hashes should be unique due to salt, even for same password");
    }

    [Test]
    public async Task IsInRoleAsync_WithAdminRole_ShouldReturnTrue()
    {
        // Arrange
        await _authService.RegisterAsync("adminuser", "admin@test.com", "Admin@123", "Admin User", "Admin");
        var user = await _userManager.FindByNameAsync("adminuser");

        // Act
        var isAdmin = await _authService.IsInRoleAsync(user!, "Admin");

        // Assert
        Assert.That(isAdmin, Is.True);
    }

    [Test]
    public async Task IsInRoleAsync_WithUserRole_ShouldReturnFalseForAdmin()
    {
        // Arrange
        await _authService.RegisterAsync("regularuser", "user@test.com", "User@123", "Regular User", "User");
        var user = await _userManager.FindByNameAsync("regularuser");

        // Act
        var isAdmin = await _authService.IsInRoleAsync(user!, "Admin");

        // Assert
        Assert.That(isAdmin, Is.False);
    }

    [Test]
    public async Task ChangePasswordAsync_WithCorrectCurrentPassword_ShouldSucceed()
    {
        // Arrange
        var username = "changepassuser";
        var oldPassword = "OldPass@123";
        var newPassword = "NewPass@456";
        
        await _authService.RegisterAsync(username, "change@test.com", oldPassword, "Change User");
        var user = await _userManager.FindByNameAsync(username);

        // Act
        var result = await _authService.ChangePasswordAsync(user!, oldPassword, newPassword);

        // Assert
        Assert.That(result.Succeeded, Is.True);
        
        // Verify new password works
        var newPasswordValid = await _userManager.CheckPasswordAsync(user!, newPassword);
        Assert.That(newPasswordValid, Is.True);
        
        // Verify old password doesn't work
        var oldPasswordValid = await _userManager.CheckPasswordAsync(user!, oldPassword);
        Assert.That(oldPasswordValid, Is.False);
    }

    [Test]
    public async Task ChangePasswordAsync_WithIncorrectCurrentPassword_ShouldFail()
    {
        // Arrange
        var username = "changepassuser2";
        var correctPassword = "Correct@123";
        var wrongPassword = "Wrong@123";
        var newPassword = "NewPass@456";
        
        await _authService.RegisterAsync(username, "change2@test.com", correctPassword, "Change User 2");
        var user = await _userManager.FindByNameAsync(username);

        // Act
        var result = await _authService.ChangePasswordAsync(user!, wrongPassword, newPassword);

        // Assert
        Assert.That(result.Succeeded, Is.False);
        
        // Verify original password still works
        var originalPasswordValid = await _userManager.CheckPasswordAsync(user!, correctPassword);
        Assert.That(originalPasswordValid, Is.True);
    }
}