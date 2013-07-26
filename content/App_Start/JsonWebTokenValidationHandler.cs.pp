namespace $rootnamespace$.App_Start
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens;
	using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.ServiceModel.Security.Tokens;
    using System.Threading;
    using System.Threading.Tasks;
    
    public class JsonWebTokenValidationHandler : DelegatingHandler
    {
        public string SymmetricKey { get; set; }

        public string Audience { get; set; }
        
        public string Issuer { get; set; }

        private static bool TryRetrieveToken(HttpRequestMessage request, out string token)
        {
            token = null;
            IEnumerable<string> authzHeaders;

            if (!request.Headers.TryGetValues("Authorization", out authzHeaders) || authzHeaders.Count() > 1)
            {
                // Fail if no Authorization header or more than one Authorization headers  
                // are found in the HTTP request  
                return false;
            }

            // Remove the bearer token scheme prefix and return the rest as ACS token  
            var bearerToken = authzHeaders.ElementAt(0);
            token = bearerToken.StartsWith("Bearer ") ? bearerToken.Substring(7) : bearerToken;

            return true;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string token;
            HttpResponseMessage errorResponse = null;

            if (TryRetrieveToken(request, out token))
            {
                try
                {
                    var tokenHandler = new JwtSecurityTokenHandler();
                    var secret = this.SymmetricKey.Replace('-', '+').Replace('_', '/');
                    var validationParameters = new TokenValidationParameters()
                    {
                        AllowedAudience = this.Audience,
                        ValidateIssuer = this.Issuer != null ? true : false,
                        ValidIssuer = this.Issuer,
                        SigningToken = new BinarySecretSecurityToken(Convert.FromBase64String(secret))
                    };

                    Thread.CurrentPrincipal =
                        tokenHandler.ValidateToken(token, validationParameters);
                }
                catch (SecurityTokenValidationException ex)
                {
                    errorResponse = request.CreateErrorResponse(HttpStatusCode.Unauthorized, ex);
                }
                catch (Exception ex)
                {
                    errorResponse = request.CreateErrorResponse(HttpStatusCode.InternalServerError, ex);
                }
            }

            return errorResponse != null ?
                Task.FromResult(errorResponse) :
                base.SendAsync(request, cancellationToken);
        }
    }
}