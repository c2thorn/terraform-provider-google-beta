## Method v1 Overview

1. **Resource registry + sampling**
   - Load `attempt2/resource_registry.csv`.
   - Build an index of all Go files under `google-beta/services/**` and `google-beta/tpgiamresource/**` mapping function/variable identifiers → file paths (skipping tests, vendor, third_party).
   - Select ~20 pilot resources stratified by provenance (Generated ≈10, Handwritten ≈5, HandwrittenIAM ≈5) and shuffled across products.

2. **AST-driven schema extraction**
   - Parse each resource function with `go/parser` and locate the returned `*schema.Resource` literal (handling both direct `return &schema.Resource{}` and temporary variables).
   - Traverse the struct literal:
     - Resolve `Schema:` definitions expressed as map literals, helper functions, variables, or `tpgresource.MergeSchemas(...)`.
     - Recursively resolve nested blocks: inline `&schema.Resource{}`, helper functions returning `*schema.Resource`, or package-level variables.
     - For each attribute, capture flags (`Required`, `Optional`, `Computed`), type, file/line, and construct `attr_class` (`Required`, `Optional`, `Optional+Computed`, `Computed-only`).
   - Persist attribute metadata in `schema_inventory.csv`.

3. **Detector identification**
   - Inspect field assignments per attribute:
     - `DiffSuppressFunc`, `StateFunc`, `Set` → record detector hits with expression string, file location, and attribute path.
   - Tag block fields (`TypeList`/`TypeSet` with `Elem: &schema.Resource{...}`) as `NestedBlock` detectors.
   - Capture resource-level `CustomizeDiff` by deconstructing `customdiff.All(...)`.
   - Normalise detector names (base identifier via AST pretty-printing) and classify into families using heuristics + `detector_dictionary.json` (augmented during the run). Inline `func` hashes default to Ordering; MergeSchemas arguments are unpacked so IAM base schemas are analysed.

4. **Hit scoring & outputs**
   - Join hits with attr classes (from inventory) to compute weights: `weight = base_family_weight[family] × class_multiplier[family][attr_class]`.
   - Emit `pilot_hits.csv` under the mandated data contract.
   - Aggregate per-resource family/class counts for `pilot_heatmap.csv` and `pilot_class_heatmap.csv`.
   - Calculate scores per resource, percentiles (P50/P75/P90), nested-block critical count P75, and assign tiers per spec to `tiers_pilot.csv` (with LikelyBreaking computed from nested critical hits).
   - Generate `detector_dictionary.json` capturing all detected base identifiers → family to reuse in later runs.

5. **Quality checks**
   - Produce `pilot_qc_report.txt` summarising:
     - Coverage (% of sampled resources with ≥1 hit),
     - Detector-kind counts,
     - Verification that excluded families (Intent/State, Timestamp) are absent,
     - Attr-class Unknown rate (<5% threshold).
   - Current pilot: coverage 95% (19/20), 0 unknown attr classes, no excluded-family hits.

6. **File layout**
   - All deliverables and tooling for method v1 live under `attempt2/` (e.g., `tools/methodv1/main.go`, `pilot_*.csv`, `schema_inventory.csv`, `detector_dictionary.json`).
