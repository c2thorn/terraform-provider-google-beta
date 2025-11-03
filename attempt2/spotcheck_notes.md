## Detector Dictionary
- **Representation**: `tpgresource.CompareSelfLinkOrResourceName`, `tpgresource.CompareSelfLinkRelativePaths`, `tpgresource.CompareResourceNames`, `rrdatasDnsDiffSuppress`, `lbTypeNoneDiffSuppress`, `LastSlashDiffSuppress`, `authHeaderDiffSuppress`, `compareSelfLinkOrResourceNameWithMultipleParts`, `iamMemberCaseDiffSuppress`, `tpgresource.CaseDiffSuppress`, `jsonPolicyDiffSuppress`, `structure.NormalizeJsonString`, `canonicalizeInstanceRef`, `gcRulesDiffSuppress`.
- **NullEmpty**: `tpgresource.EmptyOrDefaultStringSuppress("180s")`.
- **Ordering**: `tpgresource.NestedUrlSetHashFunc`, `schema.HashString(canonicalizeInstanceRef)`, `schema.HashString(strings.ToLower)`.
- **CustomizeDiff**: `tpgresource.DefaultProviderProject`, `tpgresource.DefaultProviderRegion`, `tpgresource.SetLabelsDiff`, `validateAuthHeaders`, `resourceBigtableGCPolicyCustomizeDiff`.
- **NestedBlock pattern**: any `TypeList` / `TypeSet` with `Elem: &schema.Resource{…}` or helper functions returning `*schema.Resource` (e.g., `computePacketMirroringMirroredResourcesInstancesSchema`, `healthCheckedTargetSchema`, `geoPolicySchema`).

## Attribute Path & Class Quirks
- Nested schemas are frequently factored into helper functions or shared globals. To locate flags (`Required`, `Optional`, `Computed`) we must resolve those call sites (e.g., `Elem: computePacketMirroringMirroredResourcesInstancesSchema()`; `healthCheckedTargetSchema` reused in several paths).
- IAM resources share central schemas under `tpgiamresource/`; per-resource wrappers add parent-specific fields, so detector attribution needs to merge base + parent schema data.
- Some blocks are `Optional` and `Computed` simultaneously (e.g., `cloudfunctions.event_trigger`), so attr_class should be `Optional+Computed`. We also saw pure `Computed` nested blocks only in read-only structures (none in the sample, but helpers hint they exist elsewhere).
- Resource-level `CustomizeDiff` hooks lack a direct attribute; we defaulted attr_class to `Optional` and noted that convention in the hits.
- Several diff suppressors live on nested blocks rather than scalar attributes (e.g., `http_target.oauth_token`), so attribute paths must include the block name to stay unambiguous.

## AST vs Regex
- AST (or Go/types) is preferable: schemas span multi-line literals, helper function calls, and shared variables. Traversing the Go AST lets us resolve `Elem` call expressions back to their definitions and capture flag values without brittle regexes.
- Regex may help for lightweight detector enumeration (e.g., locating `DiffSuppressFunc:` occurrences), but joining back to attribute metadata still requires structural parsing.
- For IAM resources, AST-based module graphing helps tie `tpgiamresource.ResourceIam*` calls back to their base schema without re-implementing schema merges manually.

## Edge Cases Observed
- Resources such as `cloud_scheduler_job` apply diff suppressors at block level (`authHeaderDiffSuppress` on an entire nested list) and mix multiple `CustomizeDiff` functions, so detection must keep order and scope.
- Shared helper schemas (`healthCheckedTargetSchema`, `geoPolicySchema`) produce repeated nested-block hits across different attribute paths; deduping must respect the full path, not just the helper name.
- JSON canonicalisation shows up both in state funcs (`structure.NormalizeJsonString`) and diff suppressors (`gcRulesDiffSuppress`)—weighting should consider them separately but within the Representation family.
- IAM bindings/policies rely on set hash functions with closures (`schema.HashString(strings.ToLower)`), so extraction logic should capture inline function literals as detector names.
