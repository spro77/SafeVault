using NUnit.Framework;
using SafeVault.Core.Services;

namespace SafeVault.Tests.Security;

[TestFixture]
public class XssTests
{
    private IInputValidationService _validationService;

    [SetUp]
    public void Setup()
    {
        _validationService = new InputValidationService();
    }

    [Test]
    public void SanitizeInput_WithScriptTag_ShouldRemoveScriptTag()
    {
        // Arrange
        var maliciousInput = "<script>alert('XSS')</script>";

        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);

        // Assert
        Assert.That(sanitized, Does.Not.Contain("<script"));
        Assert.That(sanitized, Does.Not.Contain("</script>"));
        Assert.That(sanitized, Does.Not.Contain("alert"));
    }

    [Test]
    public void SanitizeInput_WithInlineJavaScript_ShouldRemoveJavaScript()
    {
        // Arrange
        var maliciousInputs = new[]
        {
            "<img src=x onerror=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<div onclick=alert('XSS')>Click me</div>",
            "javascript:alert('XSS')"
        };

        foreach (var input in maliciousInputs)
        {
            // Act
            var sanitized = _validationService.SanitizeInput(input);

            // Assert
            Assert.That(sanitized, Does.Not.Contain("javascript:"), 
                $"Input '{input}' should not contain 'javascript:'");
            Assert.That(sanitized, Does.Not.Contain("onerror="), 
                $"Input '{input}' should not contain 'onerror='");
            Assert.That(sanitized, Does.Not.Contain("onload="), 
                $"Input '{input}' should not contain 'onload='");
            Assert.That(sanitized, Does.Not.Contain("onclick="), 
                $"Input '{input}' should not contain 'onclick='");
        }
    }

    [Test]
    public void SanitizeInput_WithIframeTag_ShouldRemoveIframe()
    {
        // Arrange
        var maliciousInput = "<iframe src='http://evil.com'></iframe>";

        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);

        // Assert
        Assert.That(sanitized, Does.Not.Contain("<iframe"));
        Assert.That(sanitized, Does.Not.Contain("</iframe>"));
    }

    [Test]
    public void SanitizeInput_WithHtmlTags_ShouldRemoveAllTags()
    {
        // Arrange
        var inputs = new[]
        {
            "<b>Bold text</b>",
            "<h1>Header</h1>",
            "<a href='javascript:alert(1)'>Link</a>",
            "<img src=x>",
            "<style>body{background:red}</style>"
        };

        foreach (var input in inputs)
        {
            // Act
            var sanitized = _validationService.SanitizeInput(input);

            // Assert
            Assert.That(sanitized, Does.Not.Match(@"<[^>]+>"), 
                $"Input '{input}' should not contain any HTML tags");
        }
    }

    [Test]
    public void SanitizeInput_WithNullBytes_ShouldRemoveNullBytes()
    {
        // Arrange
        var maliciousInput = "username\0admin";
        var expectedOutput = "usernameadmin";

        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);

        // Assert - Check that output is the concatenated version without null byte
        Assert.That(sanitized, Is.EqualTo(expectedOutput), 
            "Null byte should be removed, resulting in concatenated string");
    
        // Check length to confirm null byte was removed
        Assert.That(sanitized.Length, Is.EqualTo(13), 
            "Length should be 13 characters (username=8 + admin=5)");
    
        // Ensure no null characters exist by checking each character
        Assert.That(sanitized.Any(c => c == '\0'), Is.False, 
            "Should not contain any null characters");
    }


    [Test]
    public void SanitizeInput_WithMixedCase_ShouldStillDetectThreats()
    {
        // Arrange - Mixed case attempts to bypass filters
        var maliciousInputs = new[]
        {
            "<ScRiPt>alert('XSS')</sCrIpT>",
            "<SCRIPT>alert('XSS')</SCRIPT>",
            "JaVaScRiPt:alert('XSS')",
            "<ImG sRc=x OnErRoR=alert('XSS')>"
        };

        foreach (var input in maliciousInputs)
        {
            // Act
            var sanitized = _validationService.SanitizeInput(input);

            // Assert
            Assert.That(sanitized, Does.Not.Contain("script").IgnoreCase, 
                $"Input '{input}' should not contain 'script' in any case");
            Assert.That(sanitized, Does.Not.Contain("javascript").IgnoreCase);
        }
    }

    [Test]
    public void EncodeForHtml_ShouldEncodeSpecialCharacters()
    {
        // Arrange
        var input = "<script>alert('XSS')</script>";

        // Act
        var encoded = _validationService.EncodeForHtml(input);

        // Assert
        Assert.That(encoded, Does.Contain("&lt;"));
        Assert.That(encoded, Does.Contain("&gt;"));
        Assert.That(encoded, Does.Not.Contain("<script"));
    }

    [Test]
    public void IsValidUsername_WithXssAttempt_ShouldReturnFalse()
    {
        // Arrange
        var maliciousUsernames = new[]
        {
            "<script>alert('XSS')</script>",
            "user<img src=x>",
            "admin'; DROP TABLE--",
            "user@#$%"
        };

        foreach (var username in maliciousUsernames)
        {
            // Act
            var isValid = _validationService.IsValidUsername(username);

            // Assert
            Assert.That(isValid, Is.False, 
                $"Username '{username}' should be invalid");
        }
    }

    [Test]
    public void IsValidUsername_WithValidUsername_ShouldReturnTrue()
    {
        // Arrange
        var validUsernames = new[] { "john_doe", "user123", "test-user", "Alice" };

        foreach (var username in validUsernames)
        {
            // Act
            var isValid = _validationService.IsValidUsername(username);

            // Assert
            Assert.That(isValid, Is.True, 
                $"Username '{username}' should be valid");
        }
    }

    [Test]
    public void SanitizeInput_WithValidInput_ShouldPreserveContent()
    {
        // Arrange
        var validInput = "This is a normal text without any malicious content";

        // Act
        var sanitized = _validationService.SanitizeInput(validInput);

        // Assert
        Assert.That(sanitized, Is.EqualTo(validInput.Trim()));
    }
}