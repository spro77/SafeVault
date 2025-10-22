using NUnit.Framework;
using SafeVault.Core.Data;
using SafeVault.Core.Services;
using Microsoft.EntityFrameworkCore;

namespace SafeVault.Tests.Security;

[TestFixture]
public class SqlInjectionTests
{
    private SafeVaultDbContext _context;
    private IInputValidationService _validationService;
    private IUserService _userService;

    [SetUp]
    public void Setup()
    {
        // Create in-memory database for testing
        var options = new DbContextOptionsBuilder<SafeVaultDbContext>()
            .UseInMemoryDatabase(databaseName: "TestDatabase_" + Guid.NewGuid())
            .Options;

        _context = new SafeVaultDbContext(options);
        _validationService = new InputValidationService();
        _userService = new UserService(_context, _validationService);

        // Seed test data
        _context.Users.Add(new Core.Models.User
        {
            UserId = 1,
            Username = "testuser",
            Email = "test@example.com",
            CreatedAt = DateTime.UtcNow
        });
        _context.SaveChanges();
    }

    [TearDown]
    public void TearDown()
    {
        _context.Database.EnsureDeleted();
        _context.Dispose();
    }

    [Test]
    public async Task GetUserByEmail_WithSqlInjectionAttempt_ShouldNotReturnUnauthorizedData()
    {
        // Arrange - Common SQL injection patterns
        var sqlInjectionAttempts = new[]
        {
            "' OR '1'='1",
            "admin' --",
            "' OR 1=1--",
            "admin' OR '1'='1'--",
            "'; DROP TABLE Users--",
            "' UNION SELECT * FROM Users--"
        };

        foreach (var maliciousInput in sqlInjectionAttempts)
        {
            // Act
            var result = await _userService.GetUserByEmailAsync(maliciousInput);

            // Assert - Should return null, not bypass security
            Assert.That(result, Is.Null, 
                $"SQL Injection attempt '{maliciousInput}' should not return any user");
        }
    }

    [Test]
    public async Task CreateUser_WithSqlInjectionInUsername_ShouldBeSanitized()
    {
        // Arrange
        var maliciousUsername = "admin'; DROP TABLE Users--";
        var validEmail = "newuser@example.com";

        // Act & Assert
        Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await _userService.CreateUserAsync(maliciousUsername, validEmail);
        }, "Should reject username with SQL injection characters");
    }

    [Test]
    public async Task CreateUser_WithSqlInjectionInEmail_ShouldBeSanitized()
    {
        // Arrange
        var validUsername = "validuser";
        var maliciousEmail = "test@test.com'; DROP TABLE Users--";

        // Act
        var result = await _userService.GetUserByEmailAsync(maliciousEmail);

        // Assert
        Assert.That(result, Is.Null, 
            "Malicious email should not retrieve any data");
    }

    [Test]
    public async Task UpdateUser_WithSqlInjectionAttempt_ShouldNotCompromiseData()
    {
        // Arrange
        var userId = 1;
        var maliciousUsername = "hacker' OR '1'='1";
        var maliciousEmail = "hack@test.com'; DELETE FROM Users WHERE '1'='1";

        // Act & Assert
        Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await _userService.UpdateUserAsync(userId, maliciousUsername, maliciousEmail);
        }, "Should reject update with SQL injection attempt");

        // Verify original data is intact
        var user = await _userService.GetUserByIdAsync(userId);
        Assert.That(user, Is.Not.Null);
        Assert.That(user.Username, Is.EqualTo("testuser"));
        Assert.That(user.Email, Is.EqualTo("test@example.com"));
    }

    [Test]
    public async Task ParameterizedQueries_ShouldPreventSqlInjection()
    {
        // Arrange
        var normalEmail = "test@example.com";
        var injectionEmail = "test@example.com' OR '1'='1";

        // Act
        var normalResult = await _userService.GetUserByEmailAsync(normalEmail);
        var injectionResult = await _userService.GetUserByEmailAsync(injectionEmail);

        // Assert
        Assert.That(normalResult, Is.Not.Null, "Normal query should work");
        Assert.That(injectionResult, Is.Null, "Injection attempt should return null");
        Assert.That(normalResult.Email, Is.EqualTo(normalEmail));
    }

    [Test]
    public async Task DatabaseIntegrity_AfterSqlInjectionAttempts_ShouldRemainIntact()
    {
        // Arrange - Multiple SQL injection attempts
        var injectionAttempts = new[]
        {
            ("user'; DROP TABLE Users--", "email1@test.com"),
            ("user", "email'; DELETE FROM Users--"),
            ("admin' OR '1'='1'--", "admin@test.com"),
        };

        // Act - Try all injection attempts
        foreach (var (username, email) in injectionAttempts)
        {
            try
            {
                await _userService.CreateUserAsync(username, email);
            }
            catch
            {
                // Expected to fail
            }
        }

        // Assert - Database should still have only the original user
        var allUsers = await _userService.GetAllUsersAsync();
        Assert.That(allUsers.Count(), Is.EqualTo(1), 
            "Database should still have exactly 1 user after injection attempts");
        
        var originalUser = allUsers.First();
        Assert.That(originalUser.Username, Is.EqualTo("testuser"));
        Assert.That(originalUser.Email, Is.EqualTo("test@example.com"));
    }
}