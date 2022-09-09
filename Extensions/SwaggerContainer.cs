using Microsoft.OpenApi.Models;
using WebApiJwt.Models;

namespace WebApiJwt.Extensions;

public static class SwaggerContainer
{
    public static void AddSwaggerOpenApi(this IServiceCollection serviceCollection)
    {
        serviceCollection.AddSwaggerGen(setupAction =>
        {
            setupAction.SwaggerDoc(
                "v1",
                new Microsoft.OpenApi.Models.OpenApiInfo()
                {
                    Title = "Minimal API test",
                    Version = "v1",
                    Description = "Test Identity auth in microservice",
                });
            setupAction.ResolveConflictingActions(apiDescriptions => apiDescriptions.First());
            setupAction.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
                Description = $"Input your Bearer token in this format - Bearer token to access this API",
            });
            setupAction.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer",
                            },
                        }, new List<string>()
                    },
                });
        });
    }
}
