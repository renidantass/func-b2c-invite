using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using B2CInvite.Domain;
using System.Collections.Generic;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace B2CInvite
{
    public static class B2CInvite
    {
        private static Lazy<X509SigningCredentials> SigningCredentials;
        [FunctionName("B2CInvite")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            ILogger log, ExecutionContext context)
        {
            IConfigurationRoot config = new ConfigurationBuilder()
                .SetBasePath(context.FunctionAppDirectory)
                .AddJsonFile("local.settings.json", optional: false, reloadOnChange: true)
                .AddEnvironmentVariables()
                .Build();

            try
            {
                #region Load certificate
                string certificateThumbprint = config["thumbprint"];

                if (string.IsNullOrEmpty(certificateThumbprint))
                {
                    throw new Exception("Certificate thumbprint is not defined in appsettings");
                }

                SigningCredentials = new Lazy<X509SigningCredentials>(() =>
                {
                    X509Store certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                    certStore.Open(OpenFlags.ReadOnly);
                    X509Certificate2Collection certCollection = certStore.Certificates.Find(
                        X509FindType.FindByThumbprint,
                        certificateThumbprint,
                        false);

                    if (certCollection.Count > 0)
                    {
                        return new X509SigningCredentials(certCollection[0]);
                    }

                    throw new Exception($"Certificate with thumbprint {certificateThumbprint} is not valid, check value in appsettings and certificate in machine");
                });

                #endregion

                #region Get email to invite user
                string body = await new StreamReader(req.Body).ReadToEndAsync();
                UserData userData = JsonConvert.DeserializeObject<UserData>(body);

                if (!userData.IsValid())
                {
                    return new BadRequestObjectResult(new { message = $"Preencha todos os campos corretamente, {typeof(UserData).GetProperties()}" });
                }

                #endregion

                #region Create Id_Token_Hint and Build Url with token
                string timeToExpireInviteInMinutes = config["InviteExpireAfterMinutes"];
                string appRegClientId = config["B2CClientId"];
                HttpRequest request = req;

                string token = B2CInvite.BuildIdToken(appRegClientId, request, userData, int.Parse(timeToExpireInviteInMinutes));
                string url = B2CInvite.BuildUrl(token, config);
                #endregion

                return new OkObjectResult(new { message = $"Token gerado com sucesso, URL: {url}" });
            } catch (Exception ex)
            {
                log.LogError(ex.Message);
                return new BadRequestObjectResult(new { message = $"An error has ocurred [{ex.Message}]" });
            }
        }

        private static string BuildIdToken(string clientId, HttpRequest request, UserData userData, int timeToExpireInviteInMinutes)
        {
            string issuer = $"{request.Scheme}://{request.Host}{request.PathBase.Value}/";

            IList<Claim> claims = new List<Claim>()
            {
                new Claim("displayName", userData.DisplayName, ClaimValueTypes.String, issuer),
                new Claim("firstName", userData.FirstName, ClaimValueTypes.String, issuer),
                new Claim("lastName", userData.LastName, ClaimValueTypes.String, issuer),
                new Claim("email", userData.Email, ClaimValueTypes.String, issuer)
            };

            JwtSecurityToken token = new JwtSecurityToken(
                issuer,
                clientId,
                claims,
                DateTime.Now,
                DateTime.Now.AddMinutes(timeToExpireInviteInMinutes),
                B2CInvite.SigningCredentials.Value);

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

            return handler.WriteToken(token);
        }

        private static string BuildUrl(string token, IConfigurationRoot config)
        {
            string nonce = Guid.NewGuid().ToString("n");

            return string.Format(config["B2CUri"],
                    config["B2CTenant"],
                    config["B2CPolicy"],
                    config["B2CClientId"],
                    Uri.EscapeDataString(config["RedirectUri"]),
                    nonce) + "&id_token_hint=" + token;
        }
    }
}
