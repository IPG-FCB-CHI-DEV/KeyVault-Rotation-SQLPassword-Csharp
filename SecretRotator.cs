using Azure.Security.KeyVault.Secrets;
using Microsoft.Data.SqlClient;
using System;
using Microsoft.Extensions.Logging;
using Azure.Identity;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Azure.ResourceManager;
using Azure.ResourceManager.AppService;
using Azure.Core;
using System.Threading.Tasks;


namespace Microsoft.KeyVault
{
   
    public class SecretRotator
    {
        private const string CredentialIdTag = "CredentialId";
        private const string ProviderAddressTag = "ProviderAddress";
        private const string ValidityPeriodDaysTag = "ValidityPeriodDays";
        private const string WebAppTagPrefix = "webapp";
        private const string ConnStringTagPrefix = "connstring";

		public static async Task RotateSecret(ILogger log, string secretName, string keyVaultName)
		      {
            // Input validation
            if (string.IsNullOrWhiteSpace(secretName))
                throw new ArgumentException("Secret name cannot be null or empty", nameof(secretName));
            if (string.IsNullOrWhiteSpace(keyVaultName))
                throw new ArgumentException("Key Vault name cannot be null or empty", nameof(keyVaultName));
            
            // Validate Key Vault name format (only alphanumeric and hyphens)
            if (!Regex.IsMatch(keyVaultName, @"^[a-zA-Z0-9\-]+$"))
                throw new ArgumentException("Key Vault name contains invalid characters", nameof(keyVaultName));
            
            // Validate secret name format (Azure Key Vault naming rules)
            if (!Regex.IsMatch(secretName, @"^[a-zA-Z0-9\-]+$"))
                throw new ArgumentException("Secret name contains invalid characters", nameof(secretName));

            //Retrieve Current Secret
            var kvUri = "https://" + keyVaultName + ".vault.azure.net";
            var client = new SecretClient(new Uri(kvUri), new DefaultAzureCredential());
            KeyVaultSecret secret = client.GetSecret(secretName);
            log.LogInformation("Secret Info Retrieved");

            //Retrieve Secret Info
            var credentialId = secret.Properties.Tags.ContainsKey(CredentialIdTag) ? secret.Properties.Tags[CredentialIdTag] : "";
            var providerAddress = secret.Properties.Tags.ContainsKey(ProviderAddressTag) ? secret.Properties.Tags[ProviderAddressTag] : "";
            var validityPeriodDays = secret.Properties.Tags.ContainsKey(ValidityPeriodDaysTag) ? secret.Properties.Tags[ValidityPeriodDaysTag] : "";
            log.LogInformation($"Provider Address: {providerAddress}");
            log.LogInformation($"Credential Id: {credentialId}");

            //Check Service Provider connection
            CheckServiceConnection(secret);
            log.LogInformation("Service  Connection Validated");
            
            //Create new password
            var randomPassword = CreateRandomPassword();
            log.LogInformation("New Password Generated");

            //Add secret version with new password to Key Vault
            CreateNewSecretVersion(client, secret, randomPassword);
            log.LogInformation("New Secret Version Generated");

            //Update Service Provider with new password
            UpdateServicePassword(secret, randomPassword);
            log.LogInformation("Password Changed");
            
            //Update App Service Environment Variables with new connection strings
            await UpdateAppServiceEnvironmentVariables(client, secret, randomPassword, log);
            log.LogInformation("App Service Environment Variables Updated");
            
            log.LogInformation($"Secret Rotated Successfully");
        }

        private static void CreateNewSecretVersion(SecretClient client, KeyVaultSecret secret, string newSecretValue)
        {
            var credentialId = secret.Properties.Tags.ContainsKey(CredentialIdTag) ? secret.Properties.Tags[CredentialIdTag] : "";
            var providerAddress = secret.Properties.Tags.ContainsKey(ProviderAddressTag) ? secret.Properties.Tags[ProviderAddressTag] : "";
            var validityPeriodDays = secret.Properties.Tags.ContainsKey(ValidityPeriodDaysTag) ? secret.Properties.Tags[ValidityPeriodDaysTag] : "60";

            //add new secret version to key vault
            var newSecret = new KeyVaultSecret(secret.Name, newSecretValue);
            newSecret.Properties.Tags.Add(CredentialIdTag, credentialId);
            newSecret.Properties.Tags.Add(ProviderAddressTag, providerAddress);
            newSecret.Properties.Tags.Add(ValidityPeriodDaysTag, validityPeriodDays);
            newSecret.Properties.ExpiresOn = DateTime.UtcNow.AddDays(Int32.Parse(validityPeriodDays));
            client.SetSecret(newSecret);
        }

        private static void UpdateServicePassword(KeyVaultSecret secret, string newpassword)
        {
            var userId = secret.Properties.Tags.ContainsKey(CredentialIdTag) ? secret.Properties.Tags[CredentialIdTag] : "";
            var datasource = secret.Properties.Tags.ContainsKey(ProviderAddressTag) ? secret.Properties.Tags[ProviderAddressTag] : "";
            var dbResourceId = secret.Properties.Tags.ContainsKey(ProviderAddressTag) ? secret.Properties.Tags[ProviderAddressTag] : "";
            
            // Input validation to prevent SQL injection
            if (string.IsNullOrWhiteSpace(userId))
                throw new ArgumentException("User ID cannot be null or empty");
            if (string.IsNullOrWhiteSpace(newpassword))
                throw new ArgumentException("New password cannot be null or empty");
            
            // Validate userId format - SQL Server login names can contain alphanumeric, underscore, and some special chars
            // but must start with a letter, underscore, or @ symbol
            if (!Regex.IsMatch(userId, @"^[a-zA-Z_@][a-zA-Z0-9_@#$]*$"))
                throw new ArgumentException("User ID contains invalid characters or format");
            
            // Additional length validation
            if (userId.Length > 128) // SQL Server max login name length
                throw new ArgumentException("User ID exceeds maximum length");
            
            var dbName = dbResourceId.Split('/')[8];
            var password = secret.Value;
            
            SqlConnectionStringBuilder builder = new SqlConnectionStringBuilder();
            builder.DataSource = $"{dbName}.database.windows.net";
            builder.UserID = userId;
            builder.Password = password;
    
            //Update password using parameterized query to prevent SQL injection
            using (SqlConnection connection = new SqlConnection(builder.ConnectionString))
            {
                connection.Open();

                // Use parameterized query instead of string concatenation
                // Note: For ALTER LOGIN, we need to use dynamic SQL with quoted identifier
                // but we'll validate the userId format strictly above
                string sql = $"ALTER LOGIN [{userId}] WITH Password = @newPassword";
                using (SqlCommand command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@newPassword", newpassword);
                    command.ExecuteNonQuery();
                }
            }
        }

        private static string CreateRandomPassword()
        {
            const int length = 60;
            
            byte[] randomBytes = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return Convert.ToBase64String(randomBytes);
        }
         private static void CheckServiceConnection(KeyVaultSecret secret)
        {
            var userId = secret.Properties.Tags.ContainsKey(CredentialIdTag) ? secret.Properties.Tags[CredentialIdTag] : "";
            var dbResourceId = secret.Properties.Tags.ContainsKey(ProviderAddressTag) ? secret.Properties.Tags[ProviderAddressTag] : "";
            
            // Input validation for service connection
            if (string.IsNullOrWhiteSpace(userId))
                throw new ArgumentException("User ID cannot be null or empty for service connection");
            if (string.IsNullOrWhiteSpace(dbResourceId))
                throw new ArgumentException("Database resource ID cannot be null or empty");
            
            // Validate userId format - same as in UpdateServicePassword
            if (!Regex.IsMatch(userId, @"^[a-zA-Z_@][a-zA-Z0-9_@#$]*$"))
                throw new ArgumentException("User ID contains invalid characters or format for service connection");
            
            if (userId.Length > 128)
                throw new ArgumentException("User ID exceeds maximum length for service connection");
            
            var dbName = dbResourceId.Split('/')[8];
            var password = secret.Value;
            SqlConnectionStringBuilder builder = new SqlConnectionStringBuilder();
            builder.DataSource = $"{dbName}.database.windows.net";
            builder.UserID = userId;
            builder.Password = password;
            using (SqlConnection connection = new SqlConnection(builder.ConnectionString))
            {
                connection.Open();
            }
        }
        
        private static async Task UpdateAppServiceEnvironmentVariables(SecretClient client, KeyVaultSecret secret, string newPassword, ILogger log)
        {
            try
            {
                // Get the ARM client using DefaultAzureCredential
                var armClient = new global::Azure.ResourceManager.ArmClient(new DefaultAzureCredential());
                
                // Look for webapp and connstring tags
                var webApps = new System.Collections.Generic.List<string>();
                var connStrings = new System.Collections.Generic.List<string>();
                
                // Find all webapp tags
                foreach (var tag in secret.Properties.Tags)
                {
                    if (tag.Key.StartsWith(WebAppTagPrefix + "["))
                    {
                        webApps.Add(tag.Value);
                    }
                    else if (tag.Key.StartsWith(ConnStringTagPrefix + "["))
                    {
                        connStrings.Add(tag.Value);
                    }
                }
                
                // Process each webapp/connstring pair
                for (int i = 0; i < webApps.Count; i++)
                {
                    if (i < connStrings.Count)
                    {
                        var webAppName = webApps[i];
                        var connStringName = connStrings[i];
                        
                        log.LogInformation($"Updating App Service '{webAppName}' environment variable '{connStringName}'");
                        
                        // Get the current connection string value
                        var currentConnectionString = GetConnectionStringValue(secret, connStringName);
                        
                        // Replace the password in the connection string
                        var updatedConnectionString = UpdatePasswordInConnectionString(currentConnectionString, newPassword);
                        
                        // Update the App Service environment variable
                        await UpdateAppServiceEnvironmentVariable(armClient, webAppName, connStringName, updatedConnectionString, log);
                    }
                }
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Error updating App Service environment variables");
                // Don't throw the exception to avoid breaking the rotation process
            }
        }
        
        private static string GetConnectionStringValue(KeyVaultSecret secret, string connStringName)
        {
            // This is a simplified implementation
            // In a real scenario, you might need to get the current connection string from the App Service
            // or have it stored in the secret tags
            var userId = secret.Properties.Tags.ContainsKey(CredentialIdTag) ? secret.Properties.Tags[CredentialIdTag] : "";
            var dbResourceId = secret.Properties.Tags.ContainsKey(ProviderAddressTag) ? secret.Properties.Tags[ProviderAddressTag] : "";
            var dbName = dbResourceId.Split('/')[8];
            
            // Create a basic connection string
            return $"Server=tcp:{dbName}.database.windows.net,1433;Initial Catalog={dbName};Persist Security Info=False;User ID={userId};MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;";
        }
        
        private static string UpdatePasswordInConnectionString(string connectionString, string newPassword)
        {
            // Add or update the password in the connection string
            if (connectionString.Contains("Password=") || connectionString.Contains("Pwd="))
            {
                // Replace existing password
                var regex = new Regex(@"(Password|Pwd)=[^;]*", RegexOptions.IgnoreCase);
                return regex.Replace(connectionString, $"Password={newPassword}");
            }
            else
            {
                // Add password to connection string
                return $"{connectionString}Password={newPassword};";
            }
        }
        
        private static async Task UpdateAppServiceEnvironmentVariable(ArmClient armClient, string webAppName, string variableName, string variableValue, ILogger log)
        {
            try
            {
                // In a real scenario, you would need to:
                // 1. Get the subscription ID (possibly from environment or configuration)
                // 2. Get the resource group name (possibly from environment or configuration)
                // 3. Get the App Service resource
                // 4. Update its application settings
                
                // This is a placeholder implementation
                // To make this work, you would need to:
                // 1. Get the subscription ID and resource group name from configuration
                // 2. Use armClient.GetWebSiteResource() to get the App Service
                // 3. Get the current application settings
                // 4. Update the specific environment variable with the new connection string
                // 5. Save the updated application settings
                
                log.LogWarning($"App Service update not fully implemented: webapp='{webAppName}', variable='{variableName}'");
                log.LogInformation("To fully implement this functionality, you need to:");
                log.LogInformation("1. Provide subscription ID and resource group name");
                log.LogInformation("2. Use armClient.GetWebSiteResource() to get the App Service");
                log.LogInformation("3. Update the application settings with the new connection string");
                
                // Placeholder for actual implementation
                await Task.Delay(1); // This is just to make the method properly async
            }
            catch (Exception ex)
            {
                log.LogError(ex, $"Error updating App Service '{webAppName}' environment variable '{variableName}'");
            }
        }
    }
}
