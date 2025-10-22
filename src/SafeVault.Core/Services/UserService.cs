using Microsoft.EntityFrameworkCore;
using SafeVault.Core.Data;
using SafeVault.Core.Models;

namespace SafeVault.Core.Services;

public interface IUserService
{
    Task<User?> GetUserByIdAsync(int userId);
    Task<User?> GetUserByEmailAsync(string email);
    Task<IEnumerable<User>> GetAllUsersAsync();
    Task<User> CreateUserAsync(string username, string email);
    Task<bool> UpdateUserAsync(int userId, string username, string email);
    Task<bool> DeleteUserAsync(int userId);
    Task<bool> EmailExistsAsync(string email);
}

public class UserService : IUserService
{
    private readonly SafeVaultDbContext _context;
    private readonly IInputValidationService _validationService;

    public UserService(SafeVaultDbContext context, IInputValidationService validationService)
    {
        _context = context;
        _validationService = validationService;
    }

    /// <summary>
    /// Retrieves a user by ID using parameterized query (SQL injection safe)
    /// </summary>
    public async Task<User?> GetUserByIdAsync(int userId)
    {
        // EF Core uses parameterized queries automatically
        return await _context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.UserId == userId);
    }

    /// <summary>
    /// Retrieves a user by email using parameterized query (SQL injection safe)
    /// </summary>
    public async Task<User?> GetUserByEmailAsync(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return null;

        // Sanitize input before querying
        var sanitizedEmail = _validationService.SanitizeInput(email);

        // EF Core automatically uses parameterized queries - safe from SQL injection
        return await _context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Email == sanitizedEmail);
    }

    /// <summary>
    /// Retrieves all users
    /// </summary>
    public async Task<IEnumerable<User>> GetAllUsersAsync()
    {
        return await _context.Users
            .AsNoTracking()
            .OrderBy(u => u.Username)
            .ToListAsync();
    }

    /// <summary>
    /// Creates a new user with validated and sanitized input
    /// </summary>
    public async Task<User> CreateUserAsync(string username, string email)
    {
        // Validate inputs
        if (!_validationService.IsValidUsername(username))
            throw new ArgumentException("Invalid username format. Use only letters, numbers, underscore, and hyphen (3-100 characters).");

        if (!_validationService.IsValidEmail(email))
            throw new ArgumentException("Invalid email format.");

        // Sanitize inputs
        var sanitizedUsername = _validationService.SanitizeInput(username);
        var sanitizedEmail = _validationService.SanitizeInput(email);

        // Check if email already exists
        if (await EmailExistsAsync(sanitizedEmail))
            throw new InvalidOperationException("Email already exists.");

        // Create user entity
        var user = new User
        {
            Username = sanitizedUsername,
            Email = sanitizedEmail,
            CreatedAt = DateTime.UtcNow
        };

        // EF Core uses parameterized queries for INSERT
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return user;
    }

    /// <summary>
    /// Updates an existing user with validated and sanitized input
    /// </summary>
    public async Task<bool> UpdateUserAsync(int userId, string username, string email)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user == null)
            return false;

        // Validate inputs
        if (!_validationService.IsValidUsername(username))
            throw new ArgumentException("Invalid username format.");

        if (!_validationService.IsValidEmail(email))
            throw new ArgumentException("Invalid email format.");

        // Sanitize inputs
        var sanitizedUsername = _validationService.SanitizeInput(username);
        var sanitizedEmail = _validationService.SanitizeInput(email);

        // Check if new email already exists for another user
        var existingUser = await _context.Users
            .FirstOrDefaultAsync(u => u.Email == sanitizedEmail && u.UserId != userId);
        
        if (existingUser != null)
            throw new InvalidOperationException("Email already exists.");

        // Update user - EF Core uses parameterized queries for UPDATE
        user.Username = sanitizedUsername;
        user.Email = sanitizedEmail;

        await _context.SaveChangesAsync();
        return true;
    }

    /// <summary>
    /// Deletes a user by ID
    /// </summary>
    public async Task<bool> DeleteUserAsync(int userId)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user == null)
            return false;

        // EF Core uses parameterized queries for DELETE
        _context.Users.Remove(user);
        await _context.SaveChangesAsync();
        return true;
    }

    /// <summary>
    /// Checks if an email already exists in the database
    /// </summary>
    public async Task<bool> EmailExistsAsync(string email)
    {
        var sanitizedEmail = _validationService.SanitizeInput(email);
        return await _context.Users.AnyAsync(u => u.Email == sanitizedEmail);
    }
}