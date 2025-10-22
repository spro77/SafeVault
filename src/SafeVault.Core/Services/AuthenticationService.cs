using Microsoft.AspNetCore.Identity;
using SafeVault.Core.Models;

namespace SafeVault.Core.Services;

public interface IAuthenticationService
{
    Task<SignInResult> LoginAsync(string username, string password, bool rememberMe);
    Task LogoutAsync();
    Task<IdentityResult> RegisterAsync(string username, string email, string password, string fullName, string role = "User");
    Task<IdentityResult> ChangePasswordAsync(User user, string currentPassword, string newPassword);
    Task<User?> GetCurrentUserAsync();
    Task<bool> IsInRoleAsync(User user, string role);
}

public class AuthenticationService : IAuthenticationService
{
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;
    private readonly IInputValidationService _validationService;

    public AuthenticationService(
        UserManager<User> userManager,
        SignInManager<User> signInManager,
        IInputValidationService validationService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _validationService = validationService;
    }

    /// <summary>
    /// Authenticates a user with username and password
    /// </summary>
    public async Task<SignInResult> LoginAsync(string username, string password, bool rememberMe)
    {
        // Sanitize username input
        var sanitizedUsername = _validationService.SanitizeInput(username);
        
        if (string.IsNullOrWhiteSpace(sanitizedUsername) || string.IsNullOrWhiteSpace(password))
        {
            return SignInResult.Failed;
        }

        // Sign in with password verification
        var result = await _signInManager.PasswordSignInAsync(
            sanitizedUsername, 
            password, 
            rememberMe, 
            lockoutOnFailure: true  // Lock account after failed attempts
        );

        // Update last login time if successful
        if (result.Succeeded)
        {
            var user = await _userManager.FindByNameAsync(sanitizedUsername);
            if (user != null)
            {
                user.LastLoginAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);
            }
        }

        return result;
    }

    /// <summary>
    /// Logs out the current user
    /// </summary>
    public async Task LogoutAsync()
    {
        await _signInManager.SignOutAsync();
    }

    /// <summary>
    /// Registers a new user with hashed password
    /// </summary>
    public async Task<IdentityResult> RegisterAsync(
        string username, 
        string email, 
        string password, 
        string fullName,
        string role = "User")
    {
        // Validate inputs
        if (!_validationService.IsValidUsername(username))
        {
            return IdentityResult.Failed(new IdentityError 
            { 
                Description = "Invalid username format. Use only letters, numbers, underscore, and hyphen (3-100 characters)." 
            });
        }

        if (!_validationService.IsValidEmail(email))
        {
            return IdentityResult.Failed(new IdentityError 
            { 
                Description = "Invalid email format." 
            });
        }

        // Sanitize inputs
        var sanitizedUsername = _validationService.SanitizeInput(username);
        var sanitizedEmail = _validationService.SanitizeInput(email);
        var sanitizedFullName = _validationService.SanitizeInput(fullName);

        // Create user
        var user = new User
        {
            UserName = sanitizedUsername,
            Email = sanitizedEmail,
            FullName = sanitizedFullName,
            CreatedAt = DateTime.UtcNow
        };

        // UserManager automatically hashes the password using PBKDF2
        var result = await _userManager.CreateAsync(user, password);

        if (result.Succeeded)
        {
            // Assign role
            await _userManager.AddToRoleAsync(user, role);
        }

        return result;
    }

    /// <summary>
    /// Changes user password with verification of current password
    /// </summary>
    public async Task<IdentityResult> ChangePasswordAsync(
        User user, 
        string currentPassword, 
        string newPassword)
    {
        return await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);
    }

    /// <summary>
    /// Gets the currently authenticated user
    /// </summary>
    public async Task<User?> GetCurrentUserAsync()
    {
        return await _userManager.GetUserAsync(_signInManager.Context.User);
    }

    /// <summary>
    /// Checks if user has a specific role
    /// </summary>
    public async Task<bool> IsInRoleAsync(User user, string role)
    {
        return await _userManager.IsInRoleAsync(user, role);
    }
}