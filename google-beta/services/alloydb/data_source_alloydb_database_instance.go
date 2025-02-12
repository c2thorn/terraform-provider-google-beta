// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
package alloydb

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/tpgresource"
	transport_tpg "github.com/hashicorp/terraform-provider-google-beta/google-beta/transport"
)

func DataSourceAlloydbDatabaseInstance() *schema.Resource {
	// Generate datasource schema from resource
	dsSchema := tpgresource.DatasourceSchemaFromResourceSchema(ResourceAlloydbInstance().Schema)
	// Set custom fields
	dsScema_cluster_id := map[string]*schema.Schema{
		"cluster_id": {
			Type:        schema.TypeString,
			Required:    true,
			Description: `The ID of the alloydb cluster that the instance belongs to.'alloydb_cluster_id'`,
		},
		"project": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Project ID of the project.`,
		},
		"location": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The canonical ID for the location. For example: "us-east1".`,
		},
	}
	tpgresource.AddRequiredFieldsToSchema(dsSchema, "instance_id")

	// Set 'Required' schema elements
	dsSchema_m := tpgresource.MergeSchemas(dsScema_cluster_id, dsSchema)

	return &schema.Resource{
		Read:   dataSourceAlloydbDatabaseInstanceRead,
		Schema: dsSchema_m,
	}
}

func dataSourceAlloydbDatabaseInstanceRead(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*transport_tpg.Config)

	// Get feilds for setting cluster field in resource
	cluster_id := d.Get("cluster_id").(string)

	location, err := tpgresource.GetLocation(d, config)
	if err != nil {
		return err
	}
	project, err := tpgresource.GetProject(d, config)
	if err != nil {
		return err
	}
	// Store the ID now
	id, err := tpgresource.ReplaceVars(d, config, "projects/{{project}}/locations/{{location}}/clusters/{{cluster_id}}/instances/{{instance_id}}")
	if err != nil {
		return fmt.Errorf("Error constructing id: %s", err)
	}
	d.SetId(id)

	// Setting cluster field as this is set as a required field in instance resource
	d.Set("cluster", fmt.Sprintf("projects/%s/locations/%s/clusters/%s", project, location, cluster_id))

	err = resourceAlloydbInstanceRead(d, meta)
	if err != nil {
		return err
	}

	if err := tpgresource.SetDataSourceLabels(d); err != nil {
		return err
	}

	if d.Id() == "" {
		return fmt.Errorf("%s not found", id)
	}
	return nil
}
