JsonWebToken DelegatingHandler for ASP.NET WebAPI.

## Installation

    Install-Package WebApi.JsonWebToken

## Usage

Add the following to your App_Start\WebApiConfig.cs file under the Register method:

~~~csharp
config.MessageHandlers.Add(new WebApi.App_Start.JsonWebTokenValidationHandler
{
    Audience = "..your-client-id..",
    SymmetricKey = "....your-client-secret...."
});
~~~
