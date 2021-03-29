package apimanagement_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/helpers/azure"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/acceptance"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/acceptance/check"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/internal/clients"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

type ApiManagementCertificateResource struct {
}

func TestAccApiManagementCertificate_basic(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_api_management_certificate", "test")
	r := ApiManagementCertificateResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.basic(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
				check.That(data.ResourceName).Key("expiration").Exists(),
				check.That(data.ResourceName).Key("subject").Exists(),
				check.That(data.ResourceName).Key("thumbprint").Exists(),
			),
		},
		{
			ResourceName:      data.ResourceName,
			ImportState:       true,
			ImportStateVerify: true,
			ImportStateVerifyIgnore: []string{
				// not returned from the API
				"data",
				"password",
			},
		},
	})
}

func TestAccApiManagementCertificate_basicKeyVaultSystemIdentity(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_api_management_certificate", "test")
	r := ApiManagementCertificateResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.basicKeyVaultSystemIdentity(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
				check.That(data.ResourceName).Key("key_vault_secret_id").Exists(),
				check.That(data.ResourceName).Key("expiration").Exists(),
				check.That(data.ResourceName).Key("subject").Exists(),
				check.That(data.ResourceName).Key("thumbprint").Exists(),
			),
		},
		{
			ResourceName: data.ResourceName,
			ImportState:  true,
			ImportStateVerifyIgnore: []string{
				// not returned from the API
				"key_vault_secret_id",
			},
		},
	})
}

func TestAccApiManagementCertificate_basicKeyVaultUserIdentity(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_api_management_certificate", "test")
	r := ApiManagementCertificateResource{}

	data.ResourceTest(t, r, []resource.TestStep{
		{
			Config: r.basicKeyVaultUserIdentity(data),
			Check: resource.ComposeTestCheckFunc(
				check.That(data.ResourceName).ExistsInAzure(r),
				check.That(data.ResourceName).Key("key_vault_secret_id").Exists(),
				check.That(data.ResourceName).Key("key_vault_identity_client_id").Exists(),
				check.That(data.ResourceName).Key("expiration").Exists(),
				check.That(data.ResourceName).Key("subject").Exists(),
				check.That(data.ResourceName).Key("thumbprint").Exists(),
			),
		},
		{
			ResourceName:      data.ResourceName,
			ImportState:       true,
			ImportStateVerify: true,
		},
	})
}

func TestAccApiManagementCertificate_requiresImport(t *testing.T) {
	data := acceptance.BuildTestData(t, "azurerm_api_management_certificate", "test")
	r := ApiManagementCertificateResource{}

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

func (ApiManagementCertificateResource) Exists(ctx context.Context, clients *clients.Client, state *terraform.InstanceState) (*bool, error) {
	id, err := azure.ParseAzureResourceID(state.ID)
	if err != nil {
		return nil, err
	}
	resourceGroup := id.ResourceGroup
	serviceName := id.Path["service"]
	name := id.Path["certificates"]

	resp, err := clients.ApiManagement.CertificatesClient.Get(ctx, resourceGroup, serviceName, name)
	if err != nil {
		return nil, fmt.Errorf("reading ApiManagement Certificate (%s): %+v", id, err)
	}

	return utils.Bool(resp.ID != nil), nil
}

func (ApiManagementCertificateResource) basic(data acceptance.TestData) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "test" {
  name     = "acctestRG-%d"
  location = "%s"
}

resource "azurerm_api_management" "test" {
  name                = "acctestAM-%d"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  publisher_name      = "pub1"
  publisher_email     = "pub1@email.com"
  sku_name            = "Developer_1"
}

resource "azurerm_api_management_certificate" "test" {
  name                = "example-cert"
  api_management_name = azurerm_api_management.test.name
  resource_group_name = azurerm_resource_group.test.name
  data                = filebase64("testdata/keyvaultcert.pfx")
  password            = ""
}
`, data.RandomInteger, data.Locations.Primary, data.RandomInteger)
}

func (ApiManagementCertificateResource) basicKeyVaultSystemIdentity(data acceptance.TestData) string {
	return fmt.Sprintf(`
provider "azurerm" {
  features {}
}

data "azurerm_api_management" "test" {
  name                = "mattiasapitest"
  resource_group_name = "api-test"
}

data "azurerm_client_config" "test" {}

resource "azurerm_resource_group" "test" {
  name     = "acctestwebcert%d"
  location = "%s"
}

resource "azurerm_key_vault" "test" {
  name                = "acct%d"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  soft_delete_enabled = true

  tenant_id = data.azurerm_client_config.test.tenant_id

  sku_name = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.test.tenant_id
    object_id = data.azurerm_client_config.test.object_id

    secret_permissions = [
      "delete",
      "get",
      "purge",
      "set",
    ]

    certificate_permissions = [
      "create",
      "delete",
      "get",
      "purge",
      "import",
    ]
  }

  access_policy {
    tenant_id = data.azurerm_api_management.test.identity.0.tenant_id
    object_id = data.azurerm_api_management.test.identity.0.principal_id

    secret_permissions = [
      "get",
    ]

    certificate_permissions = [
      "get",
    ]
  }
}

resource "azurerm_key_vault_certificate" "test" {
  name         = "acctest%d"
  key_vault_id = azurerm_key_vault.test.id

  certificate {
    contents = filebase64("testdata/api_management_api_test.pfx")
    password = "terraform"
  }

  certificate_policy {
    issuer_parameters {
      name = "Self"
    }

    key_properties {
      exportable = true
      key_size   = 2048
      key_type   = "RSA"
      reuse_key  = false
    }

    secret_properties {
      content_type = "application/x-pkcs12"
    }
  }
}

resource "azurerm_api_management_certificate" "test" {
  name                = "example-cert"
  api_management_name = data.azurerm_api_management.test.name
  resource_group_name = "api-test"

  key_vault_secret_id = azurerm_key_vault_certificate.test.secret_id
}
`, data.RandomInteger, data.Locations.Primary, data.RandomInteger, data.RandomInteger)
}

func (ApiManagementCertificateResource) basicKeyVaultUserIdentity(data acceptance.TestData) string {
	return `
provider "azurerm" {
  features {}
}

data "azurerm_api_management" "test" {
  name                = "mattiasapitest"
  resource_group_name = "api-test"
}

resource "azurerm_api_management_certificate" "test" {
  name                = "example-cert"
  api_management_name = data.azurerm_api_management.test.name
  resource_group_name = "api-test"

  key_vault_secret_id = "https://mattias-keyvault.vault.azure.net/secrets/AKS-Issuing-Cert"
  key_vault_identity_client_id = "391e21d5-2c57-437b-a8f2-bb51f5c5260b"
}
`
}

func (r ApiManagementCertificateResource) requiresImport(data acceptance.TestData) string {
	return fmt.Sprintf(`
%s

resource "azurerm_api_management_certificate" "import" {
  name                = azurerm_api_management_certificate.test.name
  api_management_name = azurerm_api_management_certificate.test.api_management_name
  resource_group_name = azurerm_api_management_certificate.test.resource_group_name
  data                = azurerm_api_management_certificate.test.data
  password            = azurerm_api_management_certificate.test.password
}
`, r.basic(data))
}
