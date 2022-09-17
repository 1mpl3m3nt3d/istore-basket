using Basket.Host.Configurations;
using Basket.Host.Services;
using Basket.Host.Services.Interfaces;

using Infrastructure.Services;

var configuration = GetConfiguration();

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddControllers(options => options.Filters.Add(typeof(HttpGlobalExceptionFilter)))
    .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "eShop - Basket HTTP API",
        Version = "v1",
        Description = "The Basket Service HTTP API",
    });

    var authority = configuration["Authorization:Authority"];

    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.OAuth2,
        Flows = new OpenApiOAuthFlows()
        {
            Implicit = new OpenApiOAuthFlow()
            {
                AuthorizationUrl = new Uri($"{authority}/connect/authorize"),
                TokenUrl = new Uri($"{authority}/connect/token"),
                Scopes = new Dictionary<string, string>()
                {
                    { "basket", "basket" },
                    { "basket.bff", "basket.bff" },
                },
            },
        },
    });

    options.OperationFilter<AuthorizeCheckOperationFilter>();
});

builder.AddConfiguration();

builder.Services.Configure<RedisConfig>(builder.Configuration.GetSection("Redis"));

builder.Services.AddAuthorization(configuration);

builder.Services.AddTransient<IJsonSerializer, JsonSerializer>();
builder.Services.AddTransient<IRedisCacheConnectionService, RedisCacheConnectionService>();
builder.Services.AddTransient<ICacheService, CacheService>();
builder.Services.AddTransient<IBasketService, BasketService>();

builder.Services.AddCors(options => options.AddPolicy(
        "CorsPolicy",
        builder => builder
            .SetIsOriginAllowed((host) => true)
            .WithOrigins(configuration["SpaUrl"], configuration["PathBase"], configuration["GlobalUrl"], configuration["Authorization:Authority"])
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials()));

if (configuration["Nginx:UseNginx"] == "true" || Environment.GetEnvironmentVariable("Nginx__UseNginx") == "true")
{
    try
    {
        if (configuration["Nginx:UseInitFile"] == "true" || Environment.GetEnvironmentVariable("Nginx__UseInitFile") == "true")
        {
            var initFile = configuration["Nginx:InitFilePath"] ?? Environment.GetEnvironmentVariable("Nginx__InitFilePath") ?? "/tmp/app-initialized";

            if (!File.Exists(initFile))
            {
                File.Create(initFile).Close();
            }

            File.SetLastWriteTimeUtc(initFile, DateTime.UtcNow);
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Environment variable <Nginx__UseNginx> is set to 'true', but there was an exception while configuring Initialize File:\n{ex.Message}");
    }

    try
    {
        if (configuration["Nginx:UseUnixSocket"] == "true" || Environment.GetEnvironmentVariable("Nginx__UseUnixSocket") == "true")
        {
            var unixSocket = configuration["Nginx:UnixSocketPath"] ?? Environment.GetEnvironmentVariable("Nginx__UnixSocketPath") ?? "/tmp/nginx.socket";

            builder.WebHost.ConfigureKestrel(kestrel => kestrel.ListenUnixSocket(unixSocket));
        }
        else
        {
            var portParsed = int.TryParse(configuration["PORT"] ?? Environment.GetEnvironmentVariable("PORT"), out var port);

            if (portParsed)
            {
                builder.WebHost.ConfigureKestrel(kestrel => kestrel.ListenAnyIP(port));
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Environment variable <Nginx__UseNginx> is set to 'true', but there was an exception while configuring Kestrel:\n{ex.Message}");
    }
}
else
{
    var portEnv = configuration["PORT"] ?? Environment.GetEnvironmentVariable("PORT");

    try
    {
        if (portEnv != null)
        {
            var portParsed = int.TryParse(portEnv, out var port);

            if (portParsed)
            {
                builder.WebHost.ConfigureKestrel(kestrel => kestrel.ListenAnyIP(port));
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Environment variable <PORT> is set to '{portEnv}', but there was an exception while configuring Kestrel:\n{ex.Message}");
    }
}

var app = builder.Build();

app.UseSwagger()
    .UseSwaggerUI(setup =>
    {
        setup.SwaggerEndpoint($"{configuration["PathBase"]}/swagger/v1/swagger.json", "Basket.API V1");
        setup.OAuthClientId("basketswaggerui");
        setup.OAuthAppName("Basket Swagger UI");
    });

app.UseRouting();

app.UseCors("CorsPolicy");

app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapDefaultControllerRoute();
    endpoints.MapControllers();
});

app.Run();

IConfiguration GetConfiguration()
{
    var builder = new ConfigurationBuilder()
        .SetBasePath(Directory.GetCurrentDirectory())
        .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
        .AddEnvironmentVariables()
        .AddCommandLine(args);

    return builder.Build();
}
