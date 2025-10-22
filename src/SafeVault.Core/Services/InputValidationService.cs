using System.Text.RegularExpressions;
using System.Web;

namespace SafeVault.Core.Services;

public interface IInputValidationService
{
    string SanitizeInput(string input);
    bool IsValidUsername(string username);
    bool IsValidEmail(string email);
    string EncodeForHtml(string input);
}

public class InputValidationService : IInputValidationService
{
    private static readonly Regex UsernameRegex = new(@"^[a-zA-Z0-9_-]{3,100}$", RegexOptions.Compiled);
    private static readonly Regex EmailRegex = new(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.Compiled);
    
    // List of dangerous characters/patterns that could be used in XSS attacks
    private static readonly string[] DangerousPatterns = 
    {
        "<script", "</script>", "javascript:", "onerror=", "onload=",
        "<iframe", "</iframe>", "onclick=", "onmouseover=", "eval(",
        "expression(", "<object", "<embed", "<applet"
    };

    /// <summary>
    /// Removes potentially dangerous characters and patterns from input
    /// </summary>
    public string SanitizeInput(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return string.Empty;

        // Trim whitespace
        string sanitized = input.Trim();

        // Check for dangerous patterns (case-insensitive)
        foreach (var pattern in DangerousPatterns)
        {
            if (sanitized.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                // Remove the dangerous pattern
                sanitized = Regex.Replace(sanitized, Regex.Escape(pattern), 
                    string.Empty, RegexOptions.IgnoreCase);
            }
        }

        // Remove any remaining HTML tags
        sanitized = Regex.Replace(sanitized, @"<[^>]+>", string.Empty);

        // Remove null bytes
        sanitized = sanitized.Replace("\0", string.Empty);

        return sanitized;
    }

    /// <summary>
    /// Validates username format: alphanumeric, underscore, hyphen only
    /// </summary>
    public bool IsValidUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return false;

        return UsernameRegex.IsMatch(username);
    }

    /// <summary>
    /// Validates email format
    /// </summary>
    public bool IsValidEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return false;

        return EmailRegex.IsMatch(email) && email.Length <= 100;
    }

    /// <summary>
    /// HTML encodes input for safe display in web pages (prevents XSS)
    /// </summary>
    public string EncodeForHtml(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return string.Empty;

        return HttpUtility.HtmlEncode(input);
    }
}