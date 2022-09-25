using Basket.Host.Configurations;
using Basket.Host.Services;
using Basket.Host.Services.Interfaces;

var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;

var configuration = GetConfiguration();

var builder = WebApplication.CreateBuilder(new WebApplicationOptions() { ContentRootPath = baseDirectory });

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

builder.Services.AddCors(
    options => options
        .AddPolicy(
            "CorsPolicy",
            builder => builder
                .SetIsOriginAllowed((host) => true)
                .WithOrigins(
                    configuration["Authorization:Authority"],
                    configuration["GlobalUrl"],
                    configuration["PathBase"],
                    configuration["SpaUrl"])
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials()));

builder.AddNginxConfiguration();

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
        .SetBasePath(baseDirectory)
        .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
        .AddEnvironmentVariables()
        .AddCommandLine(args);

    return builder.Build();
}
