# SQL Password Rotation Templates

This template creates below components to help demonstrate Azure SQL password rotation in Key Vault using Function and Event Grid notification.

## Inital Setup

- Key Vault
- Azure SQL Server

[![Deploy to Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.png)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fgithub.com%2FIPG-FCB-CHI-DEV%2FKeyVault-Rotation-SQLPassword-Csharp%2Fedit%2Fdev%2Farm-templates%2FInitial-Setup%2Fazuredeploy.json)
[![Visualize](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/visualizebutton.png)](http://armviz.io/#/?load=https%3A%2F%2Fgithub.com%2FIPG-FCB-CHI-DEV%2FKeyVault-Rotation-SQLPassword-Csharp%2Fedit%2Fdev%2Farm-templates%2FInitial-Setup%2Fazuredeploy.json)

## Azure SQL Password Rotation Functions

- App Service Plan
- Azure SQL Server
- Function App with access to Key Vault and Azure SQL
- Deploy functions to rotate SQL password
- Event Subscription


[![Deploy to Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.png)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fgithub.com%2FIPG-FCB-CHI-DEV%2FKeyVault-Rotation-SQLPassword-Csharp%2Fedit%2Fdev%2Farm-templates%2FFunction%2Fazuredeploy.json)
[![Visualize](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/visualizebutton.png)](http://armviz.io/#/?load=https%3A%2F%2Fgithub.com%2FIPG-FCB-CHI-DEV%2FKeyVault-Rotation-SQLPassword-Csharp%2Fedit%2Fdev%2Farm-templates%2FFunction%2Fazuredeploy.json)

## Add Event Subscription to existing Functions

- Event Subscription

[![Deploy to Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.png)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fgithub.com%2FIPG-FCB-CHI-DEV%2FKeyVault-Rotation-SQLPassword-Csharp%2Fedit%2Fdev%2Farm-templates%2FAdd-Event-Subscriptions%2Fazuredeploy.json)
[![Visualize](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/visualizebutton.png)](http://armviz.io/#/?load=https%3A%2F%2Fgithub.com%2FIPG-FCB-CHI-DEV%2FKeyVault-Rotation-SQLPassword-Csharp%2Fedit%2Fdev%2Farm-templates%2FAdd-Event-Subscriptions%2Fazuredeploy.json)

If you are new to the template development, see:

- [Azure Resource Manager documentation](https://docs.microsoft.com/en-us/azure/azure-resource-manager/)
- [Use Azure Key Vault to pass secure parameter value during deployment](https://docs.microsoft.com/azure/azure-resource-manager/resource-manager-keyvault-parameter)
- [Tutorial: Integrate Azure Key Vault in Resource Manager Template deployment](https://docs.microsoft.com/azure/azure-resource-manager/resource-manager-tutorial-use-key-vault)

Tags: Azure Key Vault, Key Vault, Secrets,Storage Account, Resource Manager, Resource Manager templates, ARM templates
