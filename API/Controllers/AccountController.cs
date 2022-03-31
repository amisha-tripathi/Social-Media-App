using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using API.Data;
using Microsoft.AspNetCore.Mvc;
using API.Entities;
using System.Security.Cryptography;
using System.Text;
using API.DTOs;
using Microsoft.EntityFrameworkCore;
using API.Interfaces;

namespace API.Controllers
{
    public class AccountController: BaseApiController
    {
        private readonly DataContext _context;

        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService){

            _context = context;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto){
            using var hmac=new HMACSHA512();
            //once done this class is dispossed off.
            if(await UserExists(registerDto.Username)) return BadRequest("Username is taken");

            var user=new AppUser{
                UserName=registerDto.Username.ToLower(),
                PasswordHash=hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt=hmac.Key
            };

            _context.Users.Add(user); //add to db
            await _context.SaveChangesAsync(); //save  changes after saving in db.
            return new UserDto{
                Username=user.UserName,
                Token=_tokenService.CreateToken(user)
            };
        }

         [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto){
            
            var user=await _context.Users
            .SingleOrDefaultAsync(x=> x.UserName == loginDto.Username);

            if(user == null) return Unauthorized("Invalid User");
            //if we find our user in db then take his current entering pwd perform hash and compare 
            //the password that was stored earlier as value of salthash is same as this new hashed pwd.
           

             using var hmac=new HMACSHA512(user.PasswordSalt);
             var computedHash=hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
             for(int i=0; i<computedHash.Length; i++){
                 if(computedHash[i]!=user.PasswordHash[i]) return Unauthorized("Invalid Password");
             }
           
             return new UserDto{
                Username=user.UserName,
                Token=_tokenService.CreateToken(user)
            };
        }
        private async Task<bool> UserExists(string username){
            return await _context.Users.AnyAsync(x => x.UserName ==username.ToLower());
        }
    }
}