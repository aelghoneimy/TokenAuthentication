# TokenAuthentication

## Usage

TokenAuthentication is based on the new Asp.Net Core. In your `Startup.cs` file, insert the following lines:  

```C#
public class Startup
{
  ...
  
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddTokenAuthentication<int, ApplicationUser>(new TokenAuthenticationOptions
        {
            Key = "YOUR_SECRET_KEY",
            UnAuthenticatedFunc = x => Task.FromResult(new JsonResult("UnAuthenticated"))
        });
    
        // Must be Added before the Identity service
    
        services.AddIdentity<ApplicationUser, ApplicationRole>()
            .AddEntityFrameworkStores<ToolsDbContext, int>()
            .AddDefaultTokenProviders();
    }
  
    public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
    {
        app.UseTokenAuthentication<int, ApplicationUser>();
    }
}
```
