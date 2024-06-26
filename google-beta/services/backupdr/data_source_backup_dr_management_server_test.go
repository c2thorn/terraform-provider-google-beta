// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
package backupdr_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/acctest"
)

func TestAccDataSourceGoogleBackupDRManagementServer_basic(t *testing.T) {
	t.Parallel()

	context := map[string]interface{}{
		"network_name":  acctest.BootstrapSharedServiceNetworkingConnection(t, "backupdr-managementserver-basic"),
		"random_suffix": acctest.RandString(t, 10),
	}

	acctest.VcrTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.AccTestPreCheck(t) },
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories(t),
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceGoogleBackupDRManagementServer_basic(context),
				Check: resource.ComposeTestCheckFunc(
					acctest.CheckDataSourceStateMatchesResourceState("data.google_backup_dr_management_server.foo", "google_backup_dr_management_server.foo"),
				),
			},
		},
	})
}

func testAccDataSourceGoogleBackupDRManagementServer_basic(context map[string]interface{}) string {
	return acctest.Nprintf(`
data "google_compute_network" "default" {
  name = "%{network_name}"
}

resource "google_backup_dr_management_server" "foo" {
 location = "us-central1"
  name     = "tf-test-management-server%{random_suffix}"
  type     = "BACKUP_RESTORE" 
  networks {
    network      = data.google_compute_network.default.id
    peering_mode = "PRIVATE_SERVICE_ACCESS"
  }
}

data "google_backup_dr_management_server" "foo" {
  location =  "us-central1"
  depends_on = [ google_backup_dr_management_server.foo ]
}
`, context)
}
