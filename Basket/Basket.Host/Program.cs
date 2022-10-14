using System.Reflection;

using Basket.Host.Configurations;
using Basket.Host.Services;
using Basket.Host.Services.Interfaces;

var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;

var webApplicationOptions = new WebApplicationOptions()
{
    ContentRootPath = baseDirectory,
};

var builder = WebApplication.CreateBuilder(webApplicationOptions);

builder.Host.ConfigureAppConfiguration((hostingContext, config) =>
{
    config.Sources.Clear();

    var env = hostingContext.HostingEnvironment;

    config.SetBasePath(hostingContext.HostingEnvironment.ContentRootPath);

    config.AddInMemoryCollection();

    config.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);
    config.AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true, reloadOnChange: true);

    if (env.IsDevelopment())
    {
        if (!string.IsNullOrEmpty(env.ApplicationName))
        {
            var appAssembly = Assembly.Load(new AssemblyName(env.ApplicationName));
            if (appAssembly != null)
            {
                config.AddUserSecrets(appAssembly, optional: true);
            }
        }
    }

    config.AddEnvironmentVariables(prefix: "ASPNETCORE_");

    config.AddEnvironmentVariables();

    if (args != null)
    {
        config.AddCommandLine(args);
    }
});

builder.AddConfiguration();

// 1st variant how to get desired configuration for WebApplicationBuilder in Program.cs
//var appConfig = new AppConfig();
//builder.Configuration.GetSection(AppConfig.App).Bind(appConfig);

// 2nd variant how to get desired configuration for WebApplicationBuilder in Program.cs
var appConfig = builder.Configuration.GetSection(AppConfig.App).Get<AppConfig>();
var authConfig = builder.Configuration.GetSection(AuthorizationConfig.Authorization).Get<AuthorizationConfig>();

builder.AddHttpLoggingConfiguration();
builder.AddNginxConfiguration();

builder.Services.Configure<RedisConfig>(builder.Configuration.GetSection(RedisConfig.Redis));

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
        ForwardedHeaders.XForwardedFor |
        ForwardedHeaders.XForwardedHost |
        ForwardedHeaders.XForwardedProto;
    options.ForwardLimit = 2;
    options.RequireHeaderSymmetry = false;

    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

builder.Services.AddCertificateForwarding(options => { });

builder.Services.AddHsts(options =>
{
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(60);
    options.Preload = true;
});

builder.Services.AddHttpsRedirection(options =>
{
    options.RedirectStatusCode = (int)HttpStatusCode.TemporaryRedirect;

    var httpsPort = builder.Configuration["HTTPS_PORT"] ?? Environment.GetEnvironmentVariable("HTTPS_PORT");

    var isPortParsed = int.TryParse(httpsPort, out var portParsed);

    if (isPortParsed)
    {
        options.HttpsPort = portParsed;
    }
});

builder.Services.AddCookiePolicy(options =>
{
    options.HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.None;
    options.MinimumSameSitePolicy = SameSiteMode.None;
    options.Secure = CookieSecurePolicy.SameAsRequest;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = false;
    options.Cookie.Expiration = TimeSpan.FromDays(30);
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.ExpireTimeSpan = TimeSpan.FromDays(30);
    options.SlidingExpiration = true;
});

builder.Services.ConfigureExternalCookie(options =>
{
    options.Cookie.HttpOnly = false;
    options.Cookie.Expiration = TimeSpan.FromDays(30);
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.ExpireTimeSpan = TimeSpan.FromDays(30);
    options.SlidingExpiration = true;
});

builder.Services.AddCors(
    options => options
        .AddPolicy(
            "CorsPolicy",
            corsBuilder => corsBuilder
                //.SetIsOriginAllowed((host) => true)
                .WithOrigins(
                    authConfig.Authority,
                    appConfig.BaseUrl,
                    appConfig.GlobalUrl,
                    appConfig.SpaUrl)
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials()));

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

    var authority = authConfig.Authority;

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

builder.AddAuthorization();

builder.Services.AddTransient<IJsonSerializer, JsonSerializer>();
builder.Services.AddTransient<IRedisCacheConnectionService, RedisCacheConnectionService>();
builder.Services.AddTransient<ICacheService, CacheService>();
builder.Services.AddTransient<IBasketService, BasketService>();

var app = builder.Build();

// a variant how to get desired configuration for WebApplication in Program.cs
var webAppConfig = app.Services.GetRequiredService<IOptionsMonitor<AppConfig>>().CurrentValue;

var basePath = webAppConfig.BasePath;

if (!string.IsNullOrEmpty(basePath))
{
    app.UsePathBase(basePath);
}

if (webAppConfig.HttpLogging == "true")
{
    app.UseHttpLogging();

    app.Use(async (ctx, next) =>
    {
        var remoteAddress = ctx.Connection.RemoteIpAddress;
        var remotePort = ctx.Connection.RemotePort;

        app.Logger.LogInformation($"Request Remote: {remoteAddress}:{remotePort}");

        await next(ctx);
    });
}

var forwardedHeadersOptions = new ForwardedHeadersOptions()
{
    ForwardedHeaders =
        ForwardedHeaders.XForwardedFor |
        ForwardedHeaders.XForwardedHost |
        ForwardedHeaders.XForwardedProto,
    ForwardLimit = 2,
    RequireHeaderSymmetry = false,
};

forwardedHeadersOptions.KnownNetworks.Clear();
forwardedHeadersOptions.KnownProxies.Clear();

app.UseForwardedHeaders(forwardedHeadersOptions);

app.UseCertificateForwarding();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");

    // The default HSTS value is 30 days.
    // see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
    app.UseHttpsRedirection();
}

//app.UseDefaultFiles();
//app.UseStaticFiles();

var cookiePolicyOptions = new CookiePolicyOptions()
{
    HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.None,
    MinimumSameSitePolicy = SameSiteMode.None,
    Secure = CookieSecurePolicy.SameAsRequest,
};

app.UseCookiePolicy(cookiePolicyOptions);

app.UseSwagger()
    .UseSwaggerUI(setup =>
    {
        setup.SwaggerEndpoint("v1/swagger.json", "Basket.API V1");
        setup.OAuthClientId("basketswaggerui");
        setup.OAuthAppName("Basket Swagger UI");
    });

app.UseRouting();

//app.UseRequestLocalization();

app.UseCors("CorsPolicy");

app.UseAuthentication();
app.UseAuthorization();

//app.UseSession();
//app.UseResponseCompression();
//app.UseResponseCaching();

//app.MapControllers();
//app.MapDefaultControllerRoute();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
    endpoints.MapDefaultControllerRoute();
});

app.Run();
