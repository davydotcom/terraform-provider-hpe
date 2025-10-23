// (C) Copyright 2025 Hewlett Packard Enterprise Development LP

// policy provides the package for hpe_morpheus_policy
package policy

import (
	"context"
	"fmt"
	"net/http"

	"github.com/HewlettPackard/hpe-morpheus-go-sdk/oapigen/sdk"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/HPE/terraform-provider-hpe/internal/framework/subproviders/morpheus/configure"
	"github.com/HPE/terraform-provider-hpe/internal/framework/subproviders/morpheus/convert"
	"github.com/HPE/terraform-provider-hpe/internal/framework/subproviders/morpheus/errors"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &Resource{}
	_ resource.ResourceWithImportState = &Resource{}
)

func NewResource() resource.Resource {
	return &Resource{}
}

// Resource defines the resource implementation.
type Resource struct {
	configure.ResourceWithMorpheusConfigure
	resource.Resource
}

func (r *Resource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_morpheus_policy"
}

func (r *Resource) Schema(
	ctx context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = PolicyResourceSchema(ctx)
}

// populate policy resource model with current API values
func getPolicyAsState(
	ctx context.Context,
	id int64,
	client *sdk.APIClient,
) (PolicyModel, diag.Diagnostics) {
	var state PolicyModel
	var diags diag.Diagnostics

	policy, hresp, err := client.PoliciesAPI.GetPolicies(ctx, id).Execute()
	if err != nil || hresp.StatusCode != http.StatusOK || policy == nil {
		diags.AddError(
			"populate policy resource",
			fmt.Sprintf("policy %d GET failed: %s", id, errors.ErrMsg(err, hresp)),
		)
		return state, diags
	}

	if policy.Policy == nil {
		diags.AddError(
			"populate policy resource",
			fmt.Sprintf("policy %d is nil", id),
		)
		return state, diags
	}

	p := policy.Policy

	// Set basic fields
	state.Id = convert.Int64ToType(p.Id)
	state.Name = convert.StrToType(p.Name)

	// Handle nullable fields
	if p.Description.IsSet() {
		state.Description = convert.StrToType(p.Description.Get())
	}

	state.Enabled = convert.BoolToType(p.Enabled)

	if p.EachUser.IsSet() {
		state.EachUser = convert.BoolToType(p.EachUser.Get())
	}

	// Set account IDs
	if p.Accounts != nil {
		accountIDs := make([]int64, 0, len(p.Accounts))
		for _, acc := range p.Accounts {
			if acc.Id != nil {
				accountIDs = append(accountIDs, *acc.Id)
			}
		}
		accountSet, setDiags := types.SetValueFrom(ctx, types.Int64Type, accountIDs)
		if setDiags.HasError() {
			diags.Append(setDiags...)
			return state, diags
		}
		state.Accounts = accountSet
	}

	// Set PolicyType
	if p.PolicyType != nil {
		policyTypeAttrs := map[string]attr.Value{
			"id":   types.Int64Null(),
			"name": types.StringNull(),
			"code": types.StringNull(),
		}
		if p.PolicyType.Id != nil {
			policyTypeAttrs["id"] = types.Int64Value(*p.PolicyType.Id)
		}
		if p.PolicyType.Name != nil {
			policyTypeAttrs["name"] = types.StringValue(*p.PolicyType.Name)
		}
		if p.PolicyType.Code != nil {
			policyTypeAttrs["code"] = types.StringValue(*p.PolicyType.Code)
		}

		policyTypeValue, policyTypeDiags := NewPolicyTypeValue(
			PolicyTypeValue{}.AttributeTypes(ctx), policyTypeAttrs)
		if policyTypeDiags.HasError() {
			diags.Append(policyTypeDiags...)
			return state, diags
		}
		state.PolicyType = policyTypeValue
	}

	// Set Config from API response
	// The config structure is complex and varies by policy type
	// For now, we leave config handling as a TODO since it requires
	// mapping each policy type's config structure from the API response
	// TODO: Implement config mapping from API response to schema based on policy type code
	if p.Config != nil {
		// Config mapping would go here
		// This requires inspecting the policy type and mapping the appropriate
		// config fields from the API response to the schema's ConfigValue structure
		diags.AddWarning(
			"populate policy resource",
			fmt.Sprintf("policy %d: config field reading from API not yet fully implemented", id),
		)
	}

	return state, diags
}

// determinePolicyTypeCodeFromConfig examines the plan's config field to determine
// which policy type configuration is set and returns the corresponding policy type code.
// Only one config type should be set at a time.
func determinePolicyTypeCodeFromConfig(plan *PolicyModel) string {
	config := plan.Config

	if !config.ApprovePolicyTypeConfiguration.IsNull() && !config.ApprovePolicyTypeConfiguration.IsUnknown() {
		// Could be deleteApproval, provisionApproval, reconfigureApproval, or workflowApproval
		// Default to provisionApproval as it's the most common
		return "provisionApproval"
	}
	if !config.BackupCreationPolicyTypeConfiguration.IsNull() && !config.BackupCreationPolicyTypeConfiguration.IsUnknown() {
		return "createBackup"
	}
	if !config.BackupTargetsPolicyTypeConfiguration.IsNull() && !config.BackupTargetsPolicyTypeConfiguration.IsUnknown() {
		return "backupStorage"
	}
	if !config.BudgetPolicyTypeConfiguration.IsNull() && !config.BudgetPolicyTypeConfiguration.IsUnknown() {
		return "maxPrice"
	}
	if !config.ClusterResourceNamePolicyTypeConfiguration.IsNull() && !config.ClusterResourceNamePolicyTypeConfiguration.IsUnknown() {
		return "serverNaming"
	}
	if !config.CypherAccessPolicyTypeConfiguration.IsNull() && !config.CypherAccessPolicyTypeConfiguration.IsUnknown() {
		return "cypher"
	}
	if !config.DelayedDeletePolicyTypeConfiguration.IsNull() && !config.DelayedDeletePolicyTypeConfiguration.IsUnknown() {
		return "delayedRemoval"
	}
	if !config.ExpirationPolicyTypeConfiguration.IsNull() && !config.ExpirationPolicyTypeConfiguration.IsUnknown() {
		return "lifecycle"
	}
	if !config.FileShareStorageQuotaPolicyTypeConfiguration.IsNull() && !config.FileShareStorageQuotaPolicyTypeConfiguration.IsUnknown() {
		return "storageShareQuota"
	}
	if !config.HostnamePolicyTypeConfiguration.IsNull() && !config.HostnamePolicyTypeConfiguration.IsUnknown() {
		return "hostNaming"
	}
	if !config.InstanceNamePolicyTypeConfiguration.IsNull() && !config.InstanceNamePolicyTypeConfiguration.IsUnknown() {
		return "naming"
	}
	if !config.MaxContainersPolicyTypeConfiguration.IsNull() && !config.MaxContainersPolicyTypeConfiguration.IsUnknown() {
		return "maxContainers"
	}
	if !config.MaxCoresPolicyTypeConfiguration.IsNull() && !config.MaxCoresPolicyTypeConfiguration.IsUnknown() {
		return "maxCores"
	}
	if !config.MaxHostsPolicyTypeConfiguration.IsNull() && !config.MaxHostsPolicyTypeConfiguration.IsUnknown() {
		return "maxHosts"
	}
	if !config.MaxLoadBalancerPoolsPolicyTypeConfiguration.IsNull() && !config.MaxLoadBalancerPoolsPolicyTypeConfiguration.IsUnknown() {
		return "maxPools"
	}
	if !config.MaxMemoryPolicyTypeConfiguration.IsNull() && !config.MaxMemoryPolicyTypeConfiguration.IsUnknown() {
		return "maxMemory"
	}
	if !config.MaxPoolMembersPolicyTypeConfiguration.IsNull() && !config.MaxPoolMembersPolicyTypeConfiguration.IsUnknown() {
		return "maxPoolMembers"
	}
	if !config.MaxStorageandObjectStorageQuotaPolicyTypeConfiguration.IsNull() && !config.MaxStorageandObjectStorageQuotaPolicyTypeConfiguration.IsUnknown() {
		return "maxStorage"
	}
	if !config.MaxVirtualServersPolicyTypeConfiguration.IsNull() && !config.MaxVirtualServersPolicyTypeConfiguration.IsUnknown() {
		return "maxVirtualServers"
	}
	if !config.MaxVmsPolicyTypeConfiguration.IsNull() && !config.MaxVmsPolicyTypeConfiguration.IsUnknown() {
		return "maxVms"
	}
	if !config.MessageoftheDayPolicyTypeConfiguration.IsNull() && !config.MessageoftheDayPolicyTypeConfiguration.IsUnknown() {
		return "motd"
	}
	if !config.NetworkQuotaPolicyTypeConfiguration.IsNull() && !config.NetworkQuotaPolicyTypeConfiguration.IsUnknown() {
		return "maxNetworks"
	}
	if !config.PowerSchedulePolicyTypeConfiguration.IsNull() && !config.PowerSchedulePolicyTypeConfiguration.IsUnknown() {
		return "powerSchedule"
	}
	if !config.RouterQuotaPolicyTypeConfiguration.IsNull() && !config.RouterQuotaPolicyTypeConfiguration.IsUnknown() {
		return "maxRouters"
	}
	if !config.ShutdownPolicyTypeConfiguration.IsNull() && !config.ShutdownPolicyTypeConfiguration.IsUnknown() {
		return "shutdown"
	}
	if !config.StorageServerStorageQuotaPolicyTypeConfiguration.IsNull() && !config.StorageServerStorageQuotaPolicyTypeConfiguration.IsUnknown() {
		return "storageServerQuota"
	}
	if !config.TagsPolicyTypeConfiguration.IsNull() && !config.TagsPolicyTypeConfiguration.IsUnknown() {
		return "tags"
	}
	if !config.UserCreationPolicyTypeConfiguration.IsNull() && !config.UserCreationPolicyTypeConfiguration.IsUnknown() {
		return "createUser"
	}
	if !config.UserGroupCreationPolicyTypeConfiguration.IsNull() && !config.UserGroupCreationPolicyTypeConfiguration.IsUnknown() {
		return "createUserGroup"
	}
	if !config.WorkflowPolicyTypeConfiguration.IsNull() && !config.WorkflowPolicyTypeConfiguration.IsUnknown() {
		return "workflow"
	}

	return ""
}

// buildPolicyConfigForCreate maps the schema's Config field to the SDK's AddPoliciesRequestPolicyConfig
func buildPolicyConfigForCreate(ctx context.Context, plan *PolicyModel) (*sdk.AddPoliciesRequestPolicyConfig, diag.Diagnostics) {
	var diags diag.Diagnostics
	config := &sdk.AddPoliciesRequestPolicyConfig{}

	// Only one config type should be set at a time
	planConfig := plan.Config

	// ApprovePolicyTypeConfiguration
	if !planConfig.ApprovePolicyTypeConfiguration.IsNull() && !planConfig.ApprovePolicyTypeConfiguration.IsUnknown() {
		approveConfig, approveDiags := NewApprovePolicyTypeConfigurationValue(
			ApprovePolicyTypeConfigurationValue{}.AttributeTypes(ctx),
			planConfig.ApprovePolicyTypeConfiguration.Attributes(),
		)
		if approveDiags.HasError() {
			diags.Append(approveDiags...)
			return nil, diags
		}

		sdkConfig := &sdk.ApprovePolicyTypeConfiguration{}
		if !approveConfig.AccountIntegrationId.IsNull() && !approveConfig.AccountIntegrationId.IsUnknown() {
			sdkConfig.SetAccountIntegrationId(approveConfig.AccountIntegrationId.ValueString())
		}
		config.ApprovePolicyTypeConfiguration = sdkConfig
		return config, diags
	}

	// BackupCreationPolicyTypeConfiguration
	if !planConfig.BackupCreationPolicyTypeConfiguration.IsNull() && !planConfig.BackupCreationPolicyTypeConfiguration.IsUnknown() {
		backupConfig, backupDiags := NewBackupCreationPolicyTypeConfigurationValue(
			BackupCreationPolicyTypeConfigurationValue{}.AttributeTypes(ctx),
			planConfig.BackupCreationPolicyTypeConfiguration.Attributes(),
		)
		if backupDiags.HasError() {
			diags.Append(backupDiags...)
			return nil, diags
		}

		sdkConfig := &sdk.BackupCreationPolicyTypeConfiguration{}
		if !backupConfig.CreateBackup.IsNull() && !backupConfig.CreateBackup.IsUnknown() {
			sdkConfig.SetCreateBackup(backupConfig.CreateBackup.ValueBool())
		}
		if !backupConfig.CreateBackupType.IsNull() && !backupConfig.CreateBackupType.IsUnknown() {
			sdkConfig.SetCreateBackupType(backupConfig.CreateBackupType.ValueString())
		}
		config.BackupCreationPolicyTypeConfiguration = sdkConfig
		return config, diags
	}

	// BackupTargetsPolicyTypeConfiguration
	if !planConfig.BackupTargetsPolicyTypeConfiguration.IsNull() && !planConfig.BackupTargetsPolicyTypeConfiguration.IsUnknown() {
		backupTargetsConfig, btDiags := NewBackupTargetsPolicyTypeConfigurationValue(
			BackupTargetsPolicyTypeConfigurationValue{}.AttributeTypes(ctx),
			planConfig.BackupTargetsPolicyTypeConfiguration.Attributes(),
		)
		if btDiags.HasError() {
			diags.Append(btDiags...)
			return nil, diags
		}

		sdkConfig := &sdk.BackupTargetsPolicyTypeConfiguration{}
		if !backupTargetsConfig.BackupStorageIds.IsNull() && !backupTargetsConfig.BackupStorageIds.IsUnknown() {
			var storageIds []int64
			elemDiags := backupTargetsConfig.BackupStorageIds.ElementsAs(ctx, &storageIds, false)
			if !elemDiags.HasError() {
				sdkConfig.SetBackupStorageIds(storageIds)
			} else {
				diags.Append(elemDiags...)
			}
		}
		config.BackupTargetsPolicyTypeConfiguration = sdkConfig
		return config, diags
	}

	// BudgetPolicyTypeConfiguration
	if !planConfig.BudgetPolicyTypeConfiguration.IsNull() && !planConfig.BudgetPolicyTypeConfiguration.IsUnknown() {
		budgetConfig, budgetDiags := NewBudgetPolicyTypeConfigurationValue(
			BudgetPolicyTypeConfigurationValue{}.AttributeTypes(ctx),
			planConfig.BudgetPolicyTypeConfiguration.Attributes(),
		)
		if budgetDiags.HasError() {
			diags.Append(budgetDiags...)
			return nil, diags
		}

		sdkConfig := &sdk.BudgetPolicyTypeConfiguration{}
		if !budgetConfig.MaxPrice.IsNull() && !budgetConfig.MaxPrice.IsUnknown() {
			maxPrice, _ := budgetConfig.MaxPrice.ValueBigFloat().Float64()
			sdkConfig.SetMaxPrice(float32(maxPrice))
		}
		if !budgetConfig.MaxPriceCurrency.IsNull() && !budgetConfig.MaxPriceCurrency.IsUnknown() {
			sdkConfig.SetMaxPriceCurrency(budgetConfig.MaxPriceCurrency.ValueString())
		}
		if !budgetConfig.MaxPriceUnit.IsNull() && !budgetConfig.MaxPriceUnit.IsUnknown() {
			sdkConfig.SetMaxPriceUnit(budgetConfig.MaxPriceUnit.ValueString())
		}
		config.BudgetPolicyTypeConfiguration = sdkConfig
		return config, diags
	}

	// MaxMemoryPolicyTypeConfiguration
	if !planConfig.MaxMemoryPolicyTypeConfiguration.IsNull() && !planConfig.MaxMemoryPolicyTypeConfiguration.IsUnknown() {
		maxMemConfig, mmDiags := NewMaxMemoryPolicyTypeConfigurationValue(
			MaxMemoryPolicyTypeConfigurationValue{}.AttributeTypes(ctx),
			planConfig.MaxMemoryPolicyTypeConfiguration.Attributes(),
		)
		if mmDiags.HasError() {
			diags.Append(mmDiags...)
			return nil, diags
		}

		sdkConfig := &sdk.MaxMemoryPolicyTypeConfiguration{}
		if !maxMemConfig.MaxMemory.IsNull() && !maxMemConfig.MaxMemory.IsUnknown() {
			// MaxMemory is a nested object - need to handle it
			// For now, we'll mark this as a TODO for complex nested objects
			diags.AddWarning(
				"build policy config",
				"MaxMemory nested object handling not yet fully implemented",
			)
		}
		if !maxMemConfig.ExcludeContainers.IsNull() && !maxMemConfig.ExcludeContainers.IsUnknown() {
			sdkConfig.SetExcludeContainers(maxMemConfig.ExcludeContainers.ValueString())
		}
		config.MaxMemoryPolicyTypeConfiguration = sdkConfig
		return config, diags
	}

	// MaxStorageandObjectStorageQuotaPolicyTypeConfiguration
	if !planConfig.MaxStorageandObjectStorageQuotaPolicyTypeConfiguration.IsNull() && !planConfig.MaxStorageandObjectStorageQuotaPolicyTypeConfiguration.IsUnknown() {
		maxStorageConfig, msDiags := NewMaxStorageandObjectStorageQuotaPolicyTypeConfigurationValue(
			MaxStorageandObjectStorageQuotaPolicyTypeConfigurationValue{}.AttributeTypes(ctx),
			planConfig.MaxStorageandObjectStorageQuotaPolicyTypeConfiguration.Attributes(),
		)
		if msDiags.HasError() {
			diags.Append(msDiags...)
			return nil, diags
		}

		sdkConfig := &sdk.MaxStorageAndObjectStorageQuotaPolicyTypeConfiguration{}
		if !maxStorageConfig.MaxStorage.IsNull() && !maxStorageConfig.MaxStorage.IsUnknown() {
			sdkConfig.SetMaxStorage(maxStorageConfig.MaxStorage.ValueString())
		}
		config.MaxStorageAndObjectStorageQuotaPolicyTypeConfiguration = sdkConfig
		return config, diags
	}

	// Add more config types as needed...
	// For brevity, returning early if no config is set

	return config, diags
}

func (r *Resource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan PolicyModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := plan.Name.ValueString()
	addPolicy := sdk.NewAddPoliciesRequestPolicyWithDefaults()

	client, err := r.NewClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"create policy resource",
			"policy "+name+": failed to create client: "+err.Error(),
		)

		return
	}

	// Set required fields
	addPolicy.SetName(name)

	// Set optional fields
	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		addPolicy.SetDescription(plan.Description.ValueString())
	}

	if !plan.Enabled.IsNull() && !plan.Enabled.IsUnknown() {
		addPolicy.SetEnabled(plan.Enabled.ValueBool())
	}

	if !plan.EachUser.IsNull() && !plan.EachUser.IsUnknown() {
		addPolicy.SetEachUser(plan.EachUser.ValueBool())
	}

	if !plan.RefId.IsNull() && !plan.RefId.IsUnknown() {
		addPolicy.SetRefId(plan.RefId.ValueInt64())
	}

	// Set account IDs if provided
	if !plan.Accounts.IsNull() && !plan.Accounts.IsUnknown() {
		var accountIDs []int64
		diags := plan.Accounts.ElementsAs(ctx, &accountIDs, false)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		addPolicy.SetAccounts(accountIDs)
	}

	// Set RefType if provided
	if !plan.RefType.IsNull() && !plan.RefType.IsUnknown() {
		if !plan.RefType.Oneof0.IsNull() && !plan.RefType.Oneof0.IsUnknown() {
			addPolicy.SetRefType(plan.RefType.Oneof0.ValueString())
		}
	}

	// Determine and set PolicyType
	policyTypeCode := ""
	if !plan.PolicyType.IsNull() && !plan.PolicyType.IsUnknown() &&
		!plan.PolicyType.Code.IsNull() && !plan.PolicyType.Code.IsUnknown() {
		// Use explicitly provided policy type code
		policyTypeCode = plan.PolicyType.Code.ValueString()
	} else {
		// Auto-determine from config
		policyTypeCode = determinePolicyTypeCodeFromConfig(&plan)
	}

	if policyTypeCode != "" {
		// Look up the policy type ID from the API
		policyTypes, hresp, err := client.PoliciesAPI.ListPolicyTypes(ctx).Execute()
		if err != nil || hresp.StatusCode != http.StatusOK || policyTypes == nil {
			resp.Diagnostics.AddError(
				"create policy resource",
				"policy "+name+": failed to list policy types: "+errors.ErrMsg(err, hresp),
			)
			return
		}

		// Find matching policy type by code
		var matchingPolicyType *sdk.ListPolicyTypes200ResponseAllOfPolicyTypesInner
		for i, pt := range policyTypes.GetPolicyTypes() {
			if pt.Code != nil && *pt.Code == policyTypeCode {
				matchingPolicyType = &policyTypes.GetPolicyTypes()[i]
				break
			}
		}

		if matchingPolicyType == nil {
			resp.Diagnostics.AddError(
				"create policy resource",
				fmt.Sprintf("policy %s: policy type code '%s' not found", name, policyTypeCode),
			)
			return
		}

		if matchingPolicyType.Id == nil {
			resp.Diagnostics.AddError(
				"create policy resource",
				fmt.Sprintf("policy %s: policy type '%s' has no ID", name, policyTypeCode),
			)
			return
		}

		// Set the policy type with code
		policyType := sdk.NewAddPoliciesRequestPolicyPolicyTypeWithDefaults()
		policyType.SetCode(policyTypeCode)
		addPolicy.SetPolicyType(*policyType)
	}

	// Build and set Config
	if !plan.Config.IsNull() && !plan.Config.IsUnknown() {
		config, configDiags := buildPolicyConfigForCreate(ctx, &plan)
		if configDiags.HasError() {
			resp.Diagnostics.Append(configDiags...)
			return
		}
		if config != nil {
			addPolicy.SetConfig(*config)
		}
	}

	addPolicyRequest := sdk.NewAddPoliciesRequest(*addPolicy)

	policy, hresp, err := client.PoliciesAPI.AddPolicies(ctx).AddPoliciesRequest(*addPolicyRequest).Execute()
	if err != nil || hresp.StatusCode != http.StatusOK {
		resp.Diagnostics.AddError(
			"create policy resource",
			"policy "+name+" POST failed: "+errors.ErrMsg(err, hresp),
		)
		return
	}

	if policy.Policy == nil || policy.Policy.Id == nil {
		resp.Diagnostics.AddError(
			"create policy resource",
			"policy "+name+" id is nil",
		)
		return
	}

	id := *policy.Policy.Id
	plan.Id = types.Int64Value(id)

	// write id as soon as possible
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	state, diags := getPolicyAsState(ctx, id, client)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *Resource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var plan PolicyModel

	diags := req.State.Get(ctx, &plan)
	if diags.HasError() {
		return
	}

	client, err := r.NewClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"read policy resource",
			"new client call failed with "+err.Error(),
		)
		return
	}

	id := plan.Id.ValueInt64()

	// Check if the policy still exists
	policy, hresp, err := client.PoliciesAPI.GetPolicies(ctx, id).Execute()
	if hresp != nil && hresp.StatusCode == http.StatusNotFound {
		// Policy has been deleted outside of Terraform
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil || hresp.StatusCode != http.StatusOK || policy == nil {
		resp.Diagnostics.AddError(
			"read policy resource",
			fmt.Sprintf("policy %d GET failed: %s", id, errors.ErrMsg(err, hresp)),
		)
		return
	}

	state, diags := getPolicyAsState(ctx, id, client)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *Resource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var data PolicyModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := data.Id.ValueInt64()

	client, err := r.NewClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"delete policy resource",
			fmt.Sprintf("policy %d: failed to create client: %s", id, err.Error()),
		)
		return
	}

	_, hresp, err := client.PoliciesAPI.RemovePolicies(ctx, id).Execute()
	if err != nil || hresp.StatusCode != http.StatusOK {
		resp.Diagnostics.AddError(
			"delete policy resource",
			fmt.Sprintf("policy %d: DELETE failed: %s", id, errors.ErrMsg(err, hresp)),
		)
		return
	}
}
