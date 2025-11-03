# Methods

- Run mode: Full scan across all resources.
- Families evaluated: Representation, NullEmpty, Ordering, CustomizeDiff, NestedBlock.
- Excluded families: Intent/State, Timestamp (none emitted).
- Attribute class determination: Required/Optional/Computed flags from schema; default Optional when unspecified (tracked as "unclear").
- Nested blocks detected via TypeList/TypeSet with Elem &schema.Resource{} (including helper functions and MergeSchemas).
- Detectors captured from DiffSuppressFunc, StateFunc, Set hashing, CustomizeDiff hooks, and nested block declarations.
- Weight matrix:
  - Base weights: Representation/NullEmpty/Ordering=1.0, CustomizeDiff=1.5, NestedBlock=2.0.
  - Class multipliers: Required=1.2, Optional=1.0, Optional+Computed=1.1 (Ordering 1.2); CustomizeDiff Required=1.6, Optional=1.5; NestedBlock Required=0.0, Optional=0.0, Optional+Computed=1.0, Computed-only=1.0.
- Outputs include schema inventory, per-hit CSV, heatmaps, tiering, top resources, and product/provenance summaries.
- Detector dictionary updated with all observed helper functions.
