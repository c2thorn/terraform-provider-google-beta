// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
package sql_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/acctest"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/envvar"
)

func TestAccSqlUserFW_mysql(t *testing.T) {
	// Multiple fine-grained resources
	acctest.SkipIfVcr(t)
	t.Parallel()

	instance := fmt.Sprintf("tf-test-%d", acctest.RandInt(t))
	acctest.VcrTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.AccTestPreCheck(t) },
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories(t),
		CheckDestroy:             testAccSqlUserDestroyProducer(t),
		Steps: []resource.TestStep{
			{
				Config: testGoogleSqlUserFW_mysql(instance, "password"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGoogleSqlUserExists(t, "google_fw_sql_user.user1"),
					testAccCheckGoogleSqlUserExists(t, "google_fw_sql_user.user2"),
				),
			},
			{
				// Update password
				Config: testGoogleSqlUserFW_mysql(instance, "new_password"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckGoogleSqlUserExists(t, "google_fw_sql_user.user1"),
					testAccCheckGoogleSqlUserExists(t, "google_fw_sql_user.user2"),
					testAccCheckGoogleSqlUserExists(t, "google_fw_sql_user.user3"),
				),
			},
			{
				ResourceName:            "google_fw_sql_user.user2",
				ImportStateId:           fmt.Sprintf("%s/%s/gmail.com/admin", envvar.GetTestProjectFromEnv(), instance),
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
			},
			{
				ResourceName:            "google_fw_sql_user.user3",
				ImportStateId:           fmt.Sprintf("%s/%s/10.0.0.0/24/admin", envvar.GetTestProjectFromEnv(), instance),
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
			},
		},
	})
}

func testGoogleSqlUserFW_mysql(instance, password string) string {
	return fmt.Sprintf(`
resource "google_sql_database_instance" "instance" {
  name                = "%s"
  region              = "us-central1"
  database_version    = "MYSQL_5_7"
  deletion_protection = false
  settings {
    tier = "db-f1-micro"
  }
}

resource "google_fw_sql_user" "user1" {
  name     = "admin"
  instance = google_sql_database_instance.instance.name
  host     = "google.com"
  password = "%s"
}

resource "google_fw_sql_user" "user2" {
  name     = "admin"
  instance = google_sql_database_instance.instance.name
  host     = "gmail.com"
  password = "hunter2"
}

resource "google_fw_sql_user" "user3" {
  name     = "admin"
  instance = google_sql_database_instance.instance.name
  host     = "10.0.0.0/24"
  password = "hunter3"
}
`, instance, password)
}
