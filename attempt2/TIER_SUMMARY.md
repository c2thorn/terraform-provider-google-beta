# Tier Summary
- Score percentiles: P50=2.25, P75=8.50, P90=16.50.
- Nested block threshold: P75=5.00 → override X=5 nested critical blocks.
- Tier counts: A=340, B=129, C=239, D=525.
- LikelyBreaking resources (nested block with mutable attrs): 898.
- Tiering rule: Tier A if score ≥ P90 or nested blocks ≥ X; Tier B ≥ P75; Tier C ≥ P50; Tier D otherwise.
