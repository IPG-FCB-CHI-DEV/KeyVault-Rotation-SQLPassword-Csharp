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
using System;

namespace Microsoft.KeyVault
{
    public static class AKVSQLRotation
    {

        [FunctionName("AKVSQLRotation")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            try
            {
                log.LogInformation("C# HTTP trigger function processed a request.");

                string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                log.LogInformation($"Request body: {requestBody}");

                if (string.IsNullOrEmpty(requestBody))
                {
                    return new BadRequestObjectResult("Request body is empty");
                }

                var eventGridEvents = JsonConvert.DeserializeObject<JArray>(requestBody);
                if (eventGridEvents == null || eventGridEvents.Count == 0)
                {
                    return new BadRequestObjectResult("No events found in request");
                }

                foreach (var eventGridEvent in eventGridEvents)
                {
                    try
                    {
                        var secretName = eventGridEvent["subject"]?.ToString();
                        var secretVersion = Regex.Match(eventGridEvent["data"]?.ToString() ?? "", "Version\":\"([a-z0-9]*)").Groups[1].ToString();
                        var keyVaultName = Regex.Match(eventGridEvent["topic"]?.ToString() ?? "", ".vaults.(.*)").Groups[1].ToString();
                        
                        log.LogInformation($"Processing event - Key Vault: {keyVaultName}, Secret: {secretName}, Version: {secretVersion}");

                        if (string.IsNullOrEmpty(keyVaultName) || string.IsNullOrEmpty(secretName))
                        {
                            log.LogWarning("Skipping event - missing Key Vault name or secret name");
                            continue;
                        }

                        await SecretRotator.RotateSecret(log, secretName, keyVaultName);
                        log.LogInformation($"Successfully processed rotation for secret: {secretName}");
                    }
                    catch (Exception eventEx)
                    {
                        log.LogError(eventEx, $"Error processing individual event: {eventEx.Message}");
                        // Continue processing other events
                    }
                }

                return new OkObjectResult("Rotation completed successfully");
            }
            catch (Exception ex)
            {
                log.LogError(ex, $"Fatal error in function execution: {ex.Message}");
                return new StatusCodeResult(500);
            }
        }
    }
}
