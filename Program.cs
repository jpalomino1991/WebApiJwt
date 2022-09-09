using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;
using WebApiJwt.Entities;
using WebApiJwt.Extensions;
using WebApiJwt.Models;
using WebApiJwt.Persistence;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddSqlServer<ApplicationDbContext>(builder.Configuration.GetConnectionString("Default"))
    .AddIdentityCore<User>()
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services
    .AddHttpContextAccessor()
    .AddAuthorization()
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
    });

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerOpenApi();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "V1 Docs");
});

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Hello World!");

app.MapPost("/token", async (AuthenticateRequest request, UserManager<User> userManager) =>
{
    // Verificamos credenciales con Identity
    var user = await userManager.FindByNameAsync(request.UserName);

    if (user is null || !await userManager.CheckPasswordAsync(user, request.Password))
    {
        return Results.Forbid();
    }

    var roles = await userManager.GetRolesAsync(user);

    // Generamos un token según los claims
    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Sid, user.Id),
        new Claim(ClaimTypes.Name, user.UserName),
        new Claim(ClaimTypes.GivenName, $"{user.FirstName} {user.LastName}")
    };

    foreach (var role in roles)
    {
        claims.Add(new Claim(ClaimTypes.Role, role));
    }

    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]));
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
    var tokenDescriptor = new JwtSecurityToken(
        issuer: builder.Configuration["Jwt:Issuer"],
        audience: builder.Configuration["Jwt:Audience"],
        claims: claims,
        expires: DateTime.Now.AddMinutes(720),
        signingCredentials: credentials);

    var jwt = new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);

    return Results.Ok(new
    {
        AccessToken = jwt
    });
}).WithName("GetToken");

app.MapGet("/list", (IHttpContextAccessor contextAccessor) =>
{
    var user = contextAccessor.HttpContext.User;

    return Results.Ok(new
    {
        Claims = user.Claims.Select(s => new
        {
            s.Type,
            s.Value
        }).ToList(),
        user.Identity.Name,
        user.Identity.IsAuthenticated,
        user.Identity.AuthenticationType
    });
})
.RequireAuthorization().WithName("listAll");

app.MapPost("/createUser", [Authorize(Roles = "Admin")] async (NewUser request, UserManager<User> userManager) =>
{
    var newUser = new User
    {
        Email = request.Email,
        FirstName = request.FirstName,
        LastName = request.LastName,
        UserName = $"{request.FirstName}.{request.LastName}"
    };

    var result = await userManager.CreateAsync(newUser, request.Password);

    await userManager.AddToRoleAsync(newUser, request.Role);

    return Results.Ok(new
    {
        User = newUser
    });
}).WithName("NewUser");

app.Run();