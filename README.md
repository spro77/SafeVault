# SafeVault - Secure Web Application

A secure ASP.NET Core MVC web application demonstrating best practices for preventing SQL Injection and Cross-Site Scripting (XSS) attacks.

## 📋 Project Overview

SafeVault is designed to manage sensitive user data securely by implementing:
- **Input Validation**: Sanitizes and validates all user inputs
- **Parameterized Queries**: Prevents SQL injection attacks using Entity Framework Core
- **XSS Prevention**: Removes malicious scripts and HTML from user inputs
- **CSRF Protection**: Anti-forgery tokens on all form submissions
- **Comprehensive Testing**: Unit tests simulating real-world attack scenarios

## 🏗️ Architecture
```
SafeVault/
├── src/
│   ├── SafeVault.Core/          # Business logic and data access
│   │   ├── Models/              # Entity models (User)
│   │   ├── Data/                # Database context
│   │   └── Services/            # Business services (validation, user management)
│   └── SafeVault.Web/           # ASP.NET Core MVC application
│       ├── Controllers/         # MVC controllers
│       ├── Views/               # Razor views
│       └── Models/              # View models
└── tests/
    └── SafeVault.Tests/         # Security and unit tests
        └── Security/            # SQL Injection and XSS tests
```

## 🔒 Security Features Implemented

### 1. Input Validation & Sanitization

**Location**: `src/SafeVault.Core/Services/InputValidationService.cs`

The `InputValidationService` implements multiple layers of defense:

- **Pattern Removal**: Detects and removes dangerous patterns like `<script>`, `javascript:`, `onerror=`
- **HTML Tag Stripping**: Removes all HTML tags from input
- **Null Byte Removal**: Prevents null byte injection attacks
- **Regex Validation**: Enforces strict format for usernames (alphanumeric, underscore, hyphen only)
- **Email Validation**: Validates email format and length
- **HTML Encoding**: Encodes output for safe display in web pages

**Example**:
```csharp
var maliciousInput = "<script>alert('XSS')</script>";
var sanitized = _validationService.SanitizeInput(maliciousInput);
// Result: ">alert('XSS')" - script tags removed
```

### 2. SQL Injection Prevention

**Location**: `src/SafeVault.Core/Services/UserService.cs`

All database queries use **Entity Framework Core** with **parameterized queries**:
```csharp
// ✅ SECURE - EF Core automatically parameterizes
public async Task<User?> GetUserByEmailAsync(string email)
{
    var sanitizedEmail = _validationService.SanitizeInput(email);
    return await _context.Users
        .FirstOrDefaultAsync(u => u.Email == sanitizedEmail);
}

// ❌ VULNERABLE (NOT USED) - Raw SQL with string concatenation
// var query = $"SELECT * FROM Users WHERE Email = '{email}'";
```

**Why this is secure**:
- EF Core generates SQL with parameters: `WHERE Email = @p0`
- User input is passed as a parameter value, not concatenated into SQL
- Database treats input as data, not executable code

### 3. CSRF Protection

**Location**: All POST actions in `src/SafeVault.Web/Controllers/UsersController.cs`

Every form submission requires an anti-forgery token:
```csharp
[HttpPost]
[ValidateAntiForgeryToken]  // ← Prevents CSRF attacks
public async Task<IActionResult> Create(UserViewModel model)
{
    // ...
}
```

**How it works**:
- Each form includes a unique, encrypted token
- Token is validated on form submission
- Prevents attackers from submitting forms from external sites

### 4. Model Validation

**Location**: `src/SafeVault.Web/Models/UserViewModel.cs`

Data annotations provide declarative validation:
```csharp
[Required(ErrorMessage = "Username is required")]
[StringLength(100, MinimumLength = 3)]
[RegularExpression(@"^[a-zA-Z0-9_-]+$", 
    ErrorMessage = "Username can only contain letters, numbers, underscore, and hyphen")]
public string Username { get; set; }
```

## 🧪 Security Testing

**Location**: `tests/SafeVault.Tests/Security/`

### SQL Injection Tests

**File**: `SqlInjectionTests.cs`

Tests simulate real SQL injection attacks:

| Test | Attack Pattern | Expected Result |
|------|----------------|-----------------|
| `GetUserByEmail_WithSqlInjectionAttempt` | `' OR '1'='1` | Returns null (no bypass) |
| `CreateUser_WithSqlInjectionInUsername` | `admin'; DROP TABLE Users--` | Throws validation error |
| `ParameterizedQueries_ShouldPreventSqlInjection` | `test@example.com' OR '1'='1` | Returns null |
| `DatabaseIntegrity_AfterSqlInjectionAttempts` | Multiple injection attempts | Database remains intact |

**Results**: ✅ All 7 SQL Injection tests pass

### XSS Tests

**File**: `XssTests.cs`

Tests validate XSS attack prevention:

| Test | Attack Pattern | Expected Result |
|------|----------------|-----------------|
| `SanitizeInput_WithScriptTag` | `<script>alert('XSS')</script>` | Script tags removed |
| `SanitizeInput_WithInlineJavaScript` | `<img onerror=alert('XSS')>` | Event handlers removed |
| `SanitizeInput_WithIframeTag` | `<iframe src='evil.com'>` | Iframe removed |
| `SanitizeInput_WithMixedCase` | `<ScRiPt>` | Detected and removed |
| `IsValidUsername_WithXssAttempt` | `user<script>` | Returns false |

**Results**: ✅ All 9 XSS tests pass

## 🚀 Running the Application

### Prerequisites
- .NET 9.0 SDK
- Git

### Setup Instructions

1. **Clone the repository**:
```bash
git clone https://github.com/YOUR_USERNAME/SafeVault.git
cd SafeVault
```

2. **Build the solution**:
```bash
dotnet build
```

3. **Run the tests**:
```bash
dotnet test
```

Expected output: `Test summary: total: 16, failed: 0, succeeded: 16`

4. **Run the application**:
```bash
dotnet run --project src/SafeVault.Web/SafeVault.Web.csproj
```

5. **Open in browser**:
   Navigate to `https://localhost:5xxx` (check console for exact port)

## 📝 Testing the Security Features

### Manual Testing for SQL Injection

1. Navigate to **Users → Create New User**
2. Try entering these malicious inputs:
    - Username: `admin' OR '1'='1'--`
    - Email: `test@test.com'; DROP TABLE Users--`
3. **Expected**: Form validation rejects the input or data is sanitized

### Manual Testing for XSS

1. Navigate to **Users → Create New User**
2. Try entering:
    - Username: `<script>alert('XSS')</script>`
    - Username: `user<img src=x onerror=alert(1)>`
3. **Expected**: Input is rejected or dangerous content is removed

### Automated Testing

Run the full test suite:
```bash
dotnet test --verbosity normal
```

Run only security tests:
```bash
dotnet test --filter "FullyQualifiedName~Security"
```

## 📊 Test Coverage Summary

| Category | Tests | Status |
|----------|-------|--------|
| SQL Injection Prevention | 7 | ✅ All Pass |
| XSS Prevention | 9 | ✅ All Pass |
| **Total** | **16** | **✅ 100%** |

## 🛡️ Security Best Practices Demonstrated

1. ✅ **Never trust user input** - All inputs are validated and sanitized
2. ✅ **Use parameterized queries** - EF Core prevents SQL injection
3. ✅ **Validate on both client and server** - Defense in depth
4. ✅ **Encode output** - HTML encoding prevents XSS
5. ✅ **Use CSRF tokens** - Prevents cross-site request forgery
6. ✅ **Test security features** - Automated tests verify protection
7. ✅ **Fail securely** - Invalid input results in clear error messages

## 🔧 Technologies Used

- **ASP.NET Core 9.0** - Web framework
- **Entity Framework Core** - ORM with parameterized queries
- **SQLite** - Database (easily replaceable with SQL Server/PostgreSQL)
- **NUnit** - Testing framework
- **Bootstrap 5** - UI framework
- **Razor Pages** - View engine

## 📚 Key Learning Outcomes

This project demonstrates:
1. How to prevent SQL Injection using ORM and parameterized queries
2. How to prevent XSS attacks through input validation and output encoding
3. How to implement CSRF protection in web forms
4. How to write security tests that simulate real attacks
5. How to structure a secure .NET application with separation of concerns

## 📖 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/aspnet/core/security/)

## 👨‍💻 Author

Created as part of .NET Course - Secure Coding Assignment

## 📄 License

This project is for educational purposes.