# KeyVault-Rotation-SQLPassword-Csharp

## Key Vault SQL Password Rotation Functions

Functions generates random password, adds password Key Vault as new version of the same secret and updates password in SQL database.

Functions require following information stored in secret as tags:
- $secret.Tags["ValidityPeriodDays"] - number of days, it defines expiration date for new secret
- $secret.Tags["CredentialId"] - SQL admin login
- $secret.Tags["ProviderAddress"] - SQL Server Resource Id

You can create new secret with above tags and SQL Password as value or add those tags to existing secret. For automated rotation expiry date would also be required - it triggers event 30 days before expiry

There are two available functions performing same rotation:
- AKVSQLRotation - event triggered function, performs storage account key rotation triggered by Key Vault events. In this setup Near Expiry event is used which is published 30 days before expiration
- AKVSQLRotationHttp - on-demand function with KeyVaultName and Secret name as parameters

Functions are using Function App identity to access Key Vault and existing secret "CredentialId" tag with sql admin login and value with sql admin password to access SQL server.

## App Service Environment Variable Update

The function now also supports updating Azure App Service environment variables with connection strings. To enable this feature, add the following tags to your secret:

- $secret.Tags["webapp[0]"] - Name of the App Service (e.g., "AppService001")
- $secret.Tags["connstring[0]"] - Name of the connection string environment variable (e.g., "ConnectionStrings__umbracoDbDSN")
- $secret.Tags["webapp[1]"] - Name of another App Service (e.g., "AppService002")
- $secret.Tags["connstring[1]"] - Name of another connection string environment variable (e.g., "ConnectionString")

The function will automatically update the password in the connection strings for each specified App Service.

## Rotation Setup - ARM Templates

There are 3 ARM templates available
- [Initial Setup](https://github.com/jlichwa/KeyVault-Rotation-SQLPassword-Csharp/tree/master/arm-templates#inital-setup)- Creates Key Vault and SQL database if needed. Existing Key Vault and SQL database  can be used instead
- [Function Rotation - Complete Setup](https://github.com/jlichwa/KeyVault-Rotation-SQLPassword-Csharp/tree/master/arm-templates#azure-sql-password-rotation-functions) - It creates and deploys function app and function code, creates necessary permissions, and Key 
Vault event subscription for Near Expiry Event for individual secret (secret name can be provided as parameter)
- [Adding additional secrets to existing function](https://github.com/jlichwa/KeyVault-Rotation-SQLPassword-Csharp/tree/master/arm-templates#add-event-subscription-to-existing-functions) - single function can be used for multiple storage accounts. This template adding new event subscription for secret