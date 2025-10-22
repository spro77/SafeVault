using Microsoft.AspNetCore.Mvc;
using SafeVault.Core.Services;
using SafeVault.Web.Models;

namespace SafeVault.Web.Controllers;

public class UsersController : Controller
{
    private readonly IUserService _userService;
    private readonly IInputValidationService _validationService;

    public UsersController(IUserService userService, IInputValidationService validationService)
    {
        _userService = userService;
        _validationService = validationService;
    }

    // GET: /Users
    public async Task<IActionResult> Index()
    {
        var users = await _userService.GetAllUsersAsync();
        return View(users);
    }

    // GET: /Users/Create
    public IActionResult Create()
    {
        return View();
    }

    // POST: /Users/Create
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(UserViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        try
        {
            await _userService.CreateUserAsync(model.Username, model.Email);
            TempData["SuccessMessage"] = "User created successfully!";
            return RedirectToAction(nameof(Index));
        }
        catch (ArgumentException ex)
        {
            ModelState.AddModelError(string.Empty, ex.Message);
            return View(model);
        }
        catch (InvalidOperationException ex)
        {
            ModelState.AddModelError(string.Empty, ex.Message);
            return View(model);
        }
    }

    // GET: /Users/Details/5
    public async Task<IActionResult> Details(int id)
    {
        var user = await _userService.GetUserByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        return View(user);
    }

    // GET: /Users/Edit/5
    public async Task<IActionResult> Edit(int id)
    {
        var user = await _userService.GetUserByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        var model = new UserViewModel
        {
            UserId = user.UserId,
            Username = user.Username,
            Email = user.Email
        };

        return View(model);
    }

    // POST: /Users/Edit/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(int id, UserViewModel model)
    {
        if (id != model.UserId)
        {
            return BadRequest();
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        try
        {
            var success = await _userService.UpdateUserAsync(id, model.Username, model.Email);
            if (!success)
            {
                return NotFound();
            }

            TempData["SuccessMessage"] = "User updated successfully!";
            return RedirectToAction(nameof(Index));
        }
        catch (ArgumentException ex)
        {
            ModelState.AddModelError(string.Empty, ex.Message);
            return View(model);
        }
        catch (InvalidOperationException ex)
        {
            ModelState.AddModelError(string.Empty, ex.Message);
            return View(model);
        }
    }

    // GET: /Users/Delete/5
    public async Task<IActionResult> Delete(int id)
    {
        var user = await _userService.GetUserByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        return View(user);
    }

    // POST: /Users/Delete/5
    [HttpPost, ActionName("Delete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteConfirmed(int id)
    {
        var success = await _userService.DeleteUserAsync(id);
        if (!success)
        {
            return NotFound();
        }

        TempData["SuccessMessage"] = "User deleted successfully!";
        return RedirectToAction(nameof(Index));
    }
}