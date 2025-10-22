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

    public async Task<User?> GetUserByIdAsync(int userId)
    {
        return await _context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == userId);
    }

    public async Task<User?> GetUserByEmailAsync(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return null;

        var sanitizedEmail = _validationService.SanitizeInput(email);

        return await _context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Email == sanitizedEmail);
    }

    public async Task<IEnumerable<User>> GetAllUsersAsync()
    {
        return await _context.Users
            .AsNoTracking()
            .OrderBy(u => u.UserName)  // Changed from Username to UserName
            .ToListAsync();
    }

    public async Task<User> CreateUserAsync(string username, string email)
    {
        if (!_validationService.IsValidUsername(username))
            throw new ArgumentException("Invalid username format. Use only letters, numbers, underscore, and hyphen (3-100 characters).");

        if (!_validationService.IsValidEmail(email))
            throw new ArgumentException("Invalid email format.");

        var sanitizedUsername = _validationService.SanitizeInput(username);
        var sanitizedEmail = _validationService.SanitizeInput(email);

        if (await EmailExistsAsync(sanitizedEmail))
            throw new InvalidOperationException("Email already exists.");

        var user = new User
        {
            UserName = sanitizedUsername,  // Changed from Username to UserName
            Email = sanitizedEmail,
            CreatedAt = DateTime.UtcNow
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return user;
    }

    public async Task<bool> UpdateUserAsync(int userId, string username, string email)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user == null)
            return false;

        if (!_validationService.IsValidUsername(username))
            throw new ArgumentException("Invalid username format.");

        if (!_validationService.IsValidEmail(email))
            throw new ArgumentException("Invalid email format.");

        var sanitizedUsername = _validationService.SanitizeInput(username);
        var sanitizedEmail = _validationService.SanitizeInput(email);

        var existingUser = await _context.Users
            .FirstOrDefaultAsync(u => u.Email == sanitizedEmail && u.Id != userId);
        
        if (existingUser != null)
            throw new InvalidOperationException("Email already exists.");

        user.UserName = sanitizedUsername;  // Changed from Username to UserName
        user.Email = sanitizedEmail;

        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<bool> DeleteUserAsync(int userId)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user == null)
            return false;

        _context.Users.Remove(user);
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<bool> EmailExistsAsync(string email)
    {
        var sanitizedEmail = _validationService.SanitizeInput(email);
        return await _context.Users.AnyAsync(u => u.Email == sanitizedEmail);
    }
}