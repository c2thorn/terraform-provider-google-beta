// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// ----------------------------------------------------------------------------
//
//     ***     AUTO GENERATED CODE    ***    Type: MMv1     ***
//
// ----------------------------------------------------------------------------
//
//     This file is automatically generated by Magic Modules and manual
//     changes will be clobbered when the file is regenerated.
//
//     Please read more about how to change this file in
//     .github/CONTRIBUTING.md.
//
// ----------------------------------------------------------------------------

package chronicle_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-google-beta/google-beta/acctest"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/envvar"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/tpgresource"
	transport_tpg "github.com/hashicorp/terraform-provider-google-beta/google-beta/transport"
)

func TestAccChronicleDataAccessLabel_chronicleDataaccesslabelBasicExample(t *testing.T) {
	t.Parallel()

	context := map[string]interface{}{
		"chronicle_id":  envvar.GetTestChronicleInstanceIdFromEnv(t),
		"random_suffix": acctest.RandString(t, 10),
	}

	acctest.VcrTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.AccTestPreCheck(t) },
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderBetaFactories(t),
		CheckDestroy:             testAccCheckChronicleDataAccessLabelDestroyProducer(t),
		Steps: []resource.TestStep{
			{
				Config: testAccChronicleDataAccessLabel_chronicleDataaccesslabelBasicExample(context),
			},
			{
				ResourceName:            "google_chronicle_data_access_label.example",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"data_access_label_id", "instance", "location"},
			},
		},
	})
}

func testAccChronicleDataAccessLabel_chronicleDataaccesslabelBasicExample(context map[string]interface{}) string {
	return acctest.Nprintf(`
resource "google_chronicle_data_access_label" "example" {
  provider = "google-beta"
  location = "us" 
  instance = "%{chronicle_id}"
  data_access_label_id = "tf-test-label-id%{random_suffix}"
  udm_query = "principal.hostname=\"google.com\""
  description = "tf-test-label-description%{random_suffix}"
}
`, context)
}

func testAccCheckChronicleDataAccessLabelDestroyProducer(t *testing.T) func(s *terraform.State) error {
	return func(s *terraform.State) error {
		for name, rs := range s.RootModule().Resources {
			if rs.Type != "google_chronicle_data_access_label" {
				continue
			}
			if strings.HasPrefix(name, "data.") {
				continue
			}

			config := acctest.GoogleProviderConfig(t)

			url, err := tpgresource.ReplaceVarsForTest(config, rs, "{{ChronicleBasePath}}projects/{{project}}/locations/{{location}}/instances/{{instance}}/dataAccessLabels/{{data_access_label_id}}")
			if err != nil {
				return err
			}

			billingProject := ""

			if config.BillingProject != "" {
				billingProject = config.BillingProject
			}

			_, err = transport_tpg.SendRequest(transport_tpg.SendRequestOptions{
				Config:    config,
				Method:    "GET",
				Project:   billingProject,
				RawURL:    url,
				UserAgent: config.UserAgent,
			})
			if err == nil {
				return fmt.Errorf("ChronicleDataAccessLabel still exists at %s", url)
			}
		}

		return nil
	}
}
