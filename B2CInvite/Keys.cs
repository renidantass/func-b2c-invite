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
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using B2CInvite.Domain;

namespace B2CInvite
{
    public static class Keys
    {
        private static Lazy<X509SigningCredentials> SigningCredentials;
        [FunctionName("Keys")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = ".well-known/keys")] HttpRequest req,
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

                #region Return keys
                return new OkObjectResult(JsonConvert.SerializeObject(new JwksModel
                {
                    Keys = new[] { JwksKeyModel.FromSigningCredentials(Keys.SigningCredentials.Value) }
                }));
                #endregion
            }
            catch (Exception ex)
            {
                log.LogError(ex.Message);
                return new BadRequestObjectResult(new { message = $"An error has ocurred [{ex.Message}]" });
            }
        }
    }
}
