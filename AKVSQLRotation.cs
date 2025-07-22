// Default URL for triggering event grid function in the local environment.
// http://localhost:7071/runtime/webhooks/EventGrid?functionName={functionname}
using Azure.Security.KeyVault.Secrets;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;
using System.IO;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Microsoft.KeyVault
{
    public static class AKVSQLRotation
    {

        [FunctionName("AKVSQLRotation")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# Event trigger function processed a request.");

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var eventGridEvents = JsonConvert.DeserializeObject<JArray>(requestBody);

            foreach (var eventGridEvent in eventGridEvents)
            {
                var secretName = eventGridEvent["subject"]?.ToString();
                var secretVersion = Regex.Match(eventGridEvent["data"]?.ToString() ?? "", "Version\":\"([a-z0-9]*)").Groups[1].ToString();
                var keyVaultName = Regex.Match(eventGridEvent["topic"]?.ToString() ?? "", ".vaults.(.*)").Groups[1].ToString();
                
                log.LogInformation($"Key Vault Name: {keyVaultName}");
                log.LogInformation($"Secret Name: {secretName}");
                log.LogInformation($"Secret Version: {secretVersion}");

                SecretRotator.RotateSecret(log, secretName, keyVaultName);
            }

            return new OkResult();
        }
    }
}
