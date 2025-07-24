using Azure.Security.KeyVault.Secrets;
using Microsoft.Data.SqlClient;
using System;
using Microsoft.Extensions.Logging;
using Azure.Identity;
using System.Security.Cryptography;
using System.Text.RegularExpressions;


namespace Microsoft.KeyVault
{
   
    public class SecretRotator
    {
		private const string CredentialIdTag = "CredentialId";
		private const string ProviderAddressTag = "ProviderAddress";
		private const string ValidityPeriodDaysTag = "ValidityPeriodDays";

		public static void RotateSecret(ILogger log, string secretName, string keyVaultName)
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
    }
}
