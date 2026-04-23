using System.Text;
using KiwiAuth.Data;
using KiwiAuth.Options;
using KiwiAuth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;

namespace KiwiAuth.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddKiwiAuth(
        this IServiceCollection services,
        Action<KiwiAuthOptions> configure)
    {
        var options = new KiwiAuthOptions();
        configure(options);

        ValidateOptions(options);

        // Register options so they can be injected via IOptions<KiwiAuthOptions>.
        services.Configure<KiwiAuthOptions>(o =>
        {
            o.Jwt = options.Jwt;
            o.RefreshToken = options.RefreshToken;
            o.Mfa = options.Mfa;
            o.Google = options.Google;
            o.Frontend = options.Frontend;
            o.Password = options.Password;
            o.Lockout = options.Lockout;
            o.Email = options.Email;
        });

        // ASP.NET Core Identity — using AddIdentityCore to keep full control over
        // authentication schemes (JWT as default, not cookie).
        services.AddIdentityCore<ApplicationUser>(identity =>
        {
            identity.Password.RequireDigit = options.Password.RequireDigit;
            identity.Password.RequiredLength = options.Password.RequiredLength;
            identity.Password.RequireNonAlphanumeric = options.Password.RequireNonAlphanumeric;
            identity.Password.RequireUppercase = options.Password.RequireUppercase;

            identity.User.RequireUniqueEmail = true;

            identity.Lockout.AllowedForNewUsers = options.Lockout.Enabled;
            identity.Lockout.MaxFailedAccessAttempts = options.Lockout.MaxFailedAttempts;
            identity.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(options.Lockout.LockoutMinutes);
        })
        .AddRoles<IdentityRole>()
        .AddEntityFrameworkStores<KiwiDbContext>()
        .AddSignInManager()
        .AddDefaultTokenProviders();

        // Authentication schemes:
        //   - Default authenticate/challenge: JWT Bearer
        //   - Default sign-in: External cookie (used by OAuth providers)
        var authBuilder = services.AddAuthentication(auth =>
        {
            auth.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            auth.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            auth.DefaultSignInScheme = IdentityConstants.ExternalScheme;
        })
        .AddJwtBearer(jwt =>
        {
            jwt.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = options.Jwt.Issuer,
                ValidAudience = options.Jwt.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(options.Jwt.SigningKey)),
                // No grace period — tokens are invalid the moment they expire.
                ClockSkew = TimeSpan.Zero,
            };
        })
        // External cookie is needed to temporarily hold the principal from OAuth providers
        // between the provider's callback and our /auth/google/callback handler.
        .AddCookie(IdentityConstants.ExternalScheme);

        if (options.Google.Enabled)
        {
            authBuilder.AddGoogle(google =>
            {
                google.ClientId = options.Google.ClientId;
                google.ClientSecret = options.Google.ClientSecret;
                // This path must be registered in the Google Cloud Console as an authorized redirect URI.
                google.CallbackPath = "/auth/google/callback-oidc";
                google.SignInScheme = IdentityConstants.ExternalScheme;
            });
        }

        services.AddAuthorizationBuilder();

        services.AddScoped<TokenService>();
        services.AddScoped<AuthService>();
        services.AddScoped<MfaService>();

        // TryAdd so a consumer can register their own IKiwiAuthEventSink
        // before or after calling AddKiwiAuth and it will win.
        services.TryAddSingleton<IKiwiAuthEventSink, NullKiwiAuthEventSink>();

        return services;
    }

    private static void ValidateOptions(KiwiAuthOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.Jwt.SigningKey))
            throw new InvalidOperationException(
                "KiwiAuth: Jwt.SigningKey must not be empty. " +
                "Set it via options or appsettings. Do not hardcode in production.");

        if (options.Jwt.SigningKey.Length < 32)
            throw new InvalidOperationException(
                "KiwiAuth: Jwt.SigningKey must be at least 32 characters for HMAC-SHA256.");
    }
}
