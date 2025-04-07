// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pubsublite

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-provider-google/google/fwmodels"
	"github.com/hashicorp/terraform-provider-google/google/fwresource"
	"github.com/hashicorp/terraform-provider-google/google/fwtransport"

	"github.com/hashicorp/terraform-provider-google-beta/google-beta/tpgresource"
	transport_tpg "github.com/hashicorp/terraform-provider-google-beta/google-beta/transport"
)

var (
	_ resource.Resource              = &PubsubLiteReservationFWResource{}
	_ resource.ResourceWithConfigure = &PubsubLiteReservationFWResource{}
)

func NewPubsubLiteReservationFWResource() resource.Resource {
	return &PubsubLiteReservationFWResource{}
}

type PubsubLiteReservationFWResource struct {
	providerConfig *transport_tpg.Config
}

type PubsubLiteReservationFWModel struct {
	Name               types.String `tfsdk:"name"`
	ThroughputCapacity types.Int64  `tfsdk:"throughput_capacity"`
	Region             types.String `tfsdk:"region"`
}

// Metadata returns the resource type name.
func (d *PubsubLiteReservationFWResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fw_pubsub_lite_reservation"
}

func (r *PubsubLiteReservationFWResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	p, ok := req.ProviderData.(*transport_tpg.Config)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *transport_tpg.Config, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.providerConfig = p
}

func (d *PubsubLiteReservationFWResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A resource to represent a SQL User object.",

		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{

					stringplanmodifier.RequiresReplace(),
				},
			},
			"throughput_capacity": schema.Int64Attribute{
				Required: true,
			},
			"region": schema.StringAttribute{
				Optional: true,
			},
			"project": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			// This is included for backwards compatibility with the original, SDK-implemented resource.
			"id": schema.StringAttribute{
				Description:         "Project identifier",
				MarkdownDescription: "Project identifier",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *PubsubLiteReservationFWResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PubsubLiteReservationFWModel
	var metaData *fwmodels.ProviderMetaModel
	// Read Provider meta into the meta model
	resp.Diagnostics.Append(req.ProviderMeta.Get(ctx, &metaData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	project := fwresource.GetProjectFramework(data.Project, types.StringValue(r.providerConfig.Project), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	obj := make(map[string]interface{})
	nameProp, diags := data.Name.ToStringValue(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	obj["name"] = nameProp
	throughputCapacityProp, diags := data.ThroughputCapacity.ToInt64Value(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	obj["throughputCapacity"] = throughputCapacityProp
	regionProp, diags := data.Region.ToStringValue(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	obj["region"] = regionProp

	createTimeout, diags := data.Timeouts.Create(ctx, 20*time.Minute)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url, err := tpgresource.ReplaceVars(d, config, "{{PubsubLiteBasePath}}projects/{{project}}/locations/{{region}}/reservations?reservationId={{name}}")
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Creating new Reservation: %#v", obj)

	headers := make(http.Header)
	res, err := transport_tpg.SendRequest(transport_tpg.SendRequestOptions{
		Config:    config,
		Method:    "POST",
		Project:   billingProject,
		RawURL:    url,
		UserAgent: userAgent,
		Body:      obj,
		Timeout:   createTimeout,
		Headers:   headers,
	})
	if err != nil {
		resp.Diagnostics.AppendError(fmt.Sprintf("Error creating Reservation: %s", err))
		return
	}

	tflog.Trace(ctx, "created Reservation resource")

	data.Id = types.StringValue("projects/{{project}}/locations/{{region}}/reservations/{{name}}")
	data.Project = project

	// read back Reservation
	r.PubsubLiteReservationFWRefresh(ctx, &data, &resp.State, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)

}

func (r *PubsubLiteReservationFWResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PubsubLiteReservationFWModel
	var metaData *fwmodels.ProviderMetaModel

	// Read Provider meta into the meta model
	resp.Diagnostics.Append(req.ProviderMeta.Get(ctx, &metaData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Use provider_meta to set User-Agent
	r.client.UserAgent = fwtransport.GenerateFrameworkUserAgentString(metaData, r.client.UserAgent)

	tflog.Trace(ctx, "read Reservation resource")

	// read back Reservation
	r.PubsubLiteReservationFWRefresh(ctx, &data, &resp.State, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PubsubLiteReservationFWResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var old, new PubsubLiteReservationFWModel
	var metaData *fwmodels.ProviderMetaModel

	resp.Diagnostics.Append(req.State.Get(ctx, &old)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(req.Plan.Get(ctx, &new)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// read back Reservation
	r.PubsubLiteReservationFWRefresh(ctx, &data, &resp.State, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &new)...)
}

func (r *PubsubLiteReservationFWResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PubsubLiteReservationFWModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	deleteTimeout, diags := data.Timeouts.Delete(ctx, 20*time.Minute)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url, err := tpgresource.ReplaceVars(d, config, "{{PubsubLiteBasePath}}projects/{{project}}/locations/{{region}}/reservations/{{name}}")
	if err != nil {
		return err
	}

	headers := make(http.Header)

	log.Printf("[DEBUG] Deleting Reservation %q", d.Id())
	res, err := transport_tpg.SendRequest(transport_tpg.SendRequestOptions{
		Config:    config,
		Method:    "DELETE",
		Project:   billingProject,
		RawURL:    url,
		UserAgent: userAgent,
		Body:      obj,
		Timeout:   deleteTimeout,
		Headers:   headers,
	})
	if err != nil {
		resp.Diagnostics.AppendError(fmt.Sprintf("Error deleting Reservation: %s", err))
		return
	}

	log.Printf("[DEBUG] Finished deleting Reservation %q: %#v", data.Id, res)
}

func (r *PubsubLiteReservationFWResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *PubsubLiteReservationFWResource) PubsubLiteReservationFWRefresh(ctx context.Context, data *PubsubLiteReservationFWModel, state *tfsdk.State, diag *diag.Diagnostics) {
	// TODO refresh
}
