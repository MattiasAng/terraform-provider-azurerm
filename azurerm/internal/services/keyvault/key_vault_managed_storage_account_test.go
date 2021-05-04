package keyvault_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/acceptance"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/acceptance/check"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/clients"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/services/keyvault/parse"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

type KeyVaultManagedStorageAccountResource struct {
}

func TestAccKeyVaultManagedStorageAccount_basic(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_key_vault_managed_storage_account", "test")
	r := KeyVaultManagedStorageAccountResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.basic(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func TestAccKeyVaultManagedStorageAccount_requiresImport(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_key_vault_managed_storage_account", "test")
	r := KeyVaultManagedStorageAccountResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.basic(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.RequiresImportErrorStep(r.requiresImport),
	})
}

func TestAccKeyVaultManagedStorageAccount_complete(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_key_vault_managed_storage_account", "test")
	r := KeyVaultManagedStorageAccountResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.complete(data, true, "P1D"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
				check.That(data.ResourceName).Key("storage_account_key").HasValue("key1"),
				check.That(data.ResourceName).Key("auto_regenerate_key").HasValue("true"),
				check.That(data.ResourceName).Key("regeneration_period").HasValue("P1D"),
				check.That(data.ResourceName).Key("tags.%").HasValue("1"),
				check.That(data.ResourceName).Key("tags.hello").HasValue("world"),
			),
		},
		data.ImportStep(),
	})
}

func TestAccKeyVaultManagedStorageAccount_update(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_key_vault_managed_storage_account", "test")
	r := KeyVaultManagedStorageAccountResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.complete(data, true, "P1D"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
				check.That(data.ResourceName).Key("storage_account_key").HasValue("key1"),
				check.That(data.ResourceName).Key("auto_regenerate_key").HasValue("true"),
				check.That(data.ResourceName).Key("regeneration_period").HasValue("P1D"),
			),
		},
		data.ImportStep(),
		{
			Config: r.complete(data, false, "P2D"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
				check.That(data.ResourceName).Key("storage_account_key").HasValue("key1"),
				check.That(data.ResourceName).Key("auto_regenerate_key").HasValue("false"),
				check.That(data.ResourceName).Key("regeneration_period").HasValue("P2D"),
			),
		},
		data.ImportStep(),
	})
}

func TestAccKeyVaultManagedStorageAccount_recovery(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_key_vault_managed_storage_account", "test")
	r := KeyVaultManagedStorageAccountResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.softDeleteRecovery(data, false, "1"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
		{
			Config:  r.softDeleteRecovery(data, false, "1"),
			Destroy: true,
		},
		{
			// purge true here to make sure when we end the test there's no soft-deleted items left behind
			Config: r.softDeleteRecovery(data, true, "2"),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
			),
		},
		data.ImportStep(),
	})
}

func (r KeyVaultManagedStorageAccountResource) basic(data acceptance.TestData) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

%s

resource "azurerm_key_vault_managed_storage_account" "test" {
  name                = "acctestKVstorage"
  key_vault_id        = azurerm_key_vault.test.id
  storage_account_id  = azurerm_storage_account.test.id
  storage_account_key = "key1"
  auto_regenerate_key = false
  regeneration_period = "P1D"
}
`, r.template(data))
}

func (r KeyVaultManagedStorageAccountResource) requiresImport(data acceptance.TestData) string {
	return fmt.Sprintf(`
%s

resource "azurerm_key_vault_managed_storage_account" "import" {
  name                = azurerm_key_vault_managed_storage_account.test.name
  key_vault_id        = azurerm_key_vault_managed_storage_account.test.key_vault_id
  storage_account_id  = azurerm_key_vault_managed_storage_account.test.storage_account_id
  storage_account_key = "key2"
  auto_regenerate_key = false
  regeneration_period = "P1D"
}
`, r.basic(data))
}

func (r KeyVaultManagedStorageAccountResource) complete(data acceptance.TestData, autoGenerateKey bool, regenPeriod string) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

%s

resource "azurerm_role_assignment" "test" {
  scope                = azurerm_storage_account.test.id
  role_definition_name = "Storage Account Key Operator Service Role"
  principal_id         = "727055f9-0386-4ccb-bcf1-9237237ee102"
}


resource "azurerm_key_vault_managed_storage_account" "test" {
  name                = "acctestKVstorage"
  key_vault_id        = azurerm_key_vault.test.id
  storage_account_id  = azurerm_storage_account.test.id
  storage_account_key = "key1"
  auto_regenerate_key = %t
  regeneration_period = "%s"

  tags = {
    "hello" = "world"
  }

  depends_on = [azurerm_role_assignment.test]
}
`, r.template(data), autoGenerateKey, regenPeriod)
}

func (r KeyVaultManagedStorageAccountResource) softDeleteRecovery(data acceptance.TestData, purge bool, name string) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = "%t"
      recover_soft_deleted_key_vaults = true
    }
  }
}

%s

resource "azurerm_key_vault_managed_storage_account" "test" {
  name                = "acctestKVstorage%s"
  key_vault_id        = azurerm_key_vault.test.id
  storage_account_id  = azurerm_storage_account.test.id
  storage_account_key = "key1"
  auto_regenerate_key = false
  regeneration_period = "P1D"
}
`, purge, r.template(data), name)
}

func (KeyVaultManagedStorageAccountResource) template(data acceptance.TestData) string {
	return fmt.Sprintf(`
data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "test" {
  name     = "acctest-kv-RG-%d"
  location = "%s"
}

resource "azurerm_storage_account" "test" {
  name                = "unlikely23exst2acct%s"
  resource_group_name = azurerm_resource_group.test.name

  location                 = azurerm_resource_group.test.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_key_vault" "test" {
  name                = "acctestkv-%s"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Get",
      "Delete"
    ]

    storage_permissions = [
      "Get",
      "List",
      "Set",
      "SetSAS",
      "Update",
      "RegenerateKey"
    ]
  }
}
`, data.RandomInteger, data.Locations.Primary, data.RandomString, data.RandomString)
}

func (KeyVaultManagedStorageAccountResource) Exists(ctx context.Context, client *clients.Client, state *terraform.InstanceState) (*bool, error) {
	dataPlaneClient := client.KeyVault.ManagementClient
	keyVaultsClient := client.KeyVault

	id, err := parse.ParseOptionallyVersionedNestedItemID(state.ID)
	if err != nil {
		return nil, err
	}

	keyVaultIdRaw, err := keyVaultsClient.KeyVaultIDFromBaseUrl(ctx, client.Resource, id.KeyVaultBaseUrl)
	if err != nil || keyVaultIdRaw == nil {
		return nil, fmt.Errorf("retrieving the Resource ID the Key Vault at URL %q: %s", id.KeyVaultBaseUrl, err)
	}
	keyVaultId, err := parse.VaultID(*keyVaultIdRaw)
	if err != nil {
		return nil, err
	}

	ok, err := keyVaultsClient.Exists(ctx, *keyVaultId)
	if err != nil || !ok {
		return nil, fmt.Errorf("checking if key vault %q for Managed Storage Account %q in Vault at url %q exists: %v", *keyVaultId, id.Name, id.KeyVaultBaseUrl, err)
	}

	resp, err := dataPlaneClient.GetStorageAccount(ctx, id.KeyVaultBaseUrl, id.Name)
	if err != nil {
		return nil, fmt.Errorf("retrieving Key Vault Managed Storage Account %q: %+v", state.ID, err)
	}

	return utils.Bool(resp.ID != nil), nil
}
