using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace API.Controllers;
public class AccountController : BaseApiController
{
    private readonly DataContext _dataContext;
    private readonly ITokenService _tokenService;
    public AccountController(DataContext dataContext, ITokenService tokenService)
    {
        _tokenService = tokenService;
        _dataContext = dataContext;

    }

    [HttpPost("register")] //POST: api/account/register
    public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
    {
        if (string.IsNullOrEmpty(registerDto.Username)) return BadRequest("Username is required");
        if (await UserExist(registerDto.Username)) return BadRequest($"User {registerDto.Username} already exists.");
        using var hmac = new HMACSHA512();
        var user = new AppUser
        {
            UserName = registerDto.Username.ToLower(),
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
            PasswordSalt = hmac.Key
        };

        _dataContext.Users.Add(user);
        var result = await _dataContext.SaveChangesAsync();
        if (result == 0) return StatusCode(500, "Internal Server Error");
        return Ok(new UserDto{
            Username = user.UserName,
            Token = _tokenService.CreateToken(user)
        });
    }

    [HttpPost("login")]
    public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
    {
        if (string.IsNullOrEmpty(loginDto.Username)) return BadRequest("Username is required");
        if (string.IsNullOrEmpty(loginDto.Password)) return BadRequest("Password is required");

        var user = await _dataContext.Users.SingleOrDefaultAsync(x => x.UserName == loginDto.Username.ToLower());
        if (user == null) return Unauthorized($"User {loginDto.Username} does not exists!");

        using var hmac = new HMACSHA512(user?.PasswordSalt!);
        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
        for (int i = 0; i < computedHash.Length; i++)
        {
            if (computedHash[i] != user?.PasswordHash![i]) return Unauthorized("Invalid Password.");
        }

        return Ok(new UserDto{
            Username = user?.UserName!,
            Token = _tokenService.CreateToken(user!)
        });
    }

    private async Task<bool> UserExist(string username)
    {
        return await _dataContext.Users.AnyAsync(x => x.UserName == username.ToLower());
    }


}
