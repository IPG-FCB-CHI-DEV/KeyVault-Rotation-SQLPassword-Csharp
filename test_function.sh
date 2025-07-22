#!/bin/bash

# Test your Azure Function with proper EventGrid event format
curl -X POST "https://fourfivesixstudios-kvrot-fnapp.azurewebsites.net/api/AKVSQLRotation?code=yQgo8AVL65RXK-4lqyL6n6hmQ-k__xrnvTDyUt9UV8IjAzFuJZDa_w==" \
  -H "Content-Type: application/json" \
  -H "User-Agent: EventGrid/1.0" \
  -d '[
    {
      "id": "test-event-id",
      "eventType": "Microsoft.KeyVault.SecretNearExpiry",
      "subject": "your-secret-name",
      "eventTime": "2025-07-22T12:00:00Z",
      "topic": "/subscriptions/your-sub/resourceGroups/your-rg/providers/Microsoft.KeyVault/vaults/your-keyvault-name",
      "data": {
        "Id": "https://your-keyvault-name.vault.azure.net/secrets/your-secret-name",
        "VaultName": "your-keyvault-name",
        "ObjectType": "Secret",
        "ObjectName": "your-secret-name",
        "Version": "abc123def456",
        "NBF": 1642723200,
        "EXP": 1674259200
      },
      "dataVersion": "1",
      "metadataVersion": "1"
    }
  ]'

echo ""
echo "Replace the following in the test:"
echo "- your-secret-name: actual secret name in your Key Vault"
echo "- your-keyvault-name: actual Key Vault name" 
echo "- your-sub, your-rg: your subscription ID and resource group"
