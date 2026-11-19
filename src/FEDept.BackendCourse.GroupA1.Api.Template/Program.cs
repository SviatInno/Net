using FEDept.BackendCourse.GroupA1.Api.Template.Data;
using FEDept.BackendCourse.GroupA1.Api.Template.Features.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Features.Registration;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Security;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<DatabaseUnavailableExceptionHandler>();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddApiRateLimiting();
builder.Services.AddFrontendSecurity();

builder.Services.AddDbContext<AppDbContext>((services, options) =>
    options.UseNpgsql(services.GetRequiredService<IConfiguration>().GetConnectionString("Default")));

builder.Services.AddRegistration(builder.Configuration);
builder.Services.AddAuthenticationFeature(builder.Configuration);

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseExceptionHandler();
app.UseStatusCodePages();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}
else
{
    // Auth cookies are Secure: production is HTTPS only.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseFrontendSecurity();   // CORS for the trusted frontend + CSRF check of unsafe requests
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.MapGet("/health", () => Results.Ok())
    .WithName("GetHealth");

app.MapRegistrationEndpoints();
app.MapAuthenticationEndpoints();

app.Run();

public partial class Program;
