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
            .WithOrigins(configuration["SpaUrl"], configuration["PathBase"], configuration["Authorization:Authority"])
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials()));

if (configuration.GetValue<bool>("HEROKU_NGINX") == true)
{
    try
    {
        var socket = configuration["LinuxSocket"] ?? "/tmp/nginx.socket";

        builder.WebHost.ConfigureKestrel((context, serverOptions) => serverOptions.ListenUnixSocket(socket));
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Environment variable <HEROKU_NGINX> is set to <TRUE>, but there was an exception while configuring Kestrel for Listening Unix Socket:\n{ex.Message}");
    }
}
else
{
    if (Environment.GetEnvironmentVariable("PORT") != null)
    {
        try
        {
            var parsed = int.TryParse(Environment.GetEnvironmentVariable("PORT"), out var port);

            if (parsed)
            {
                builder.WebHost.ConfigureKestrel((context, serverOptions) => serverOptions.ListenAnyIP(port));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Environment variable <PORT> is set, but there was an exception while configuring Kestrel for Listening Port:\n{ex.Message}");
        }
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

if (configuration.GetValue<bool>("HEROKU_NGINX") == true)
{
    try
    {
        var initFile = configuration["InitializedFile"] ?? "/tmp/app-initialized";

        if (!File.Exists(initFile))
        {
            File.Create(initFile).Close();
        }

        File.SetLastWriteTimeUtc(initFile, DateTime.UtcNow);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Environment variable <HEROKU_NGINX> is set to <TRUE>, but there was an exception:\n{ex.Message}");
    }
}

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
