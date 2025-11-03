package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"log"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const outputDir = "attempt2"

var (
	baseFamilyWeights = map[string]float64{
		"Representation": 1.0,
		"NullEmpty":      1.0,
		"Ordering":       1.0,
		"CustomizeDiff":  1.5,
		"NestedBlock":    2.0,
	}
	classMultipliers = map[string]map[string]float64{
		"Representation": {"Required": 1.2, "Optional": 1.0, "Optional+Computed": 1.1, "Computed-only": 0.0},
		"NullEmpty":      {"Required": 1.1, "Optional": 1.0, "Optional+Computed": 1.1, "Computed-only": 0.0},
		"Ordering":       {"Required": 1.1, "Optional": 1.0, "Optional+Computed": 1.2, "Computed-only": 0.0},
		"CustomizeDiff":  {"Required": 1.6, "Optional": 1.5, "Optional+Computed": 1.5, "Computed-only": 0.0},
		"NestedBlock":    {"Required": 0.0, "Optional": 0.0, "Optional+Computed": 1.0, "Computed-only": 1.0},
	}
	families       = []string{"Representation", "NullEmpty", "Ordering", "CustomizeDiff", "NestedBlock"}
	attrClassOrder = []string{"Required", "Optional", "Optional+Computed", "Computed-only"}
	excludedFamily = map[string]struct{}{
		"Intent":    {},
		"State":     {},
		"Timestamp": {},
	}
)

type RunConfig struct {
	Pilot  bool
	Prefix string
}

type RegistryEntry struct {
	Resource     string
	Provenance   string
	Product      string
	IsIAM        bool
	SchemaCallee string
	FileLine     string
}

type ParsedFile struct {
	Fset *token.FileSet
	File *ast.File
}

type SchemaAttr struct {
	Path       []string
	Type       string
	Required   bool
	Optional   bool
	Computed   bool
	IsBlock    bool
	BlockKind  string
	AttrClass  string
	Unclear    bool
	FileLine   string
	Children   []*SchemaAttr
	ElemOrigin string
	Detectors  []Detector
}

type Detector struct {
	Kind     string
	Name     string
	Family   string
	BaseName string
	Path     []string
	FileLine string
	Notes    string
}

type Hit struct {
	Resource        string
	AttributePath   string
	DetectorKind    string
	DetectorName    string
	Family          string
	AttrClass       string
	BaseWeight      float64
	ClassMultiplier float64
	Weight          float64
	NestedWeight    float64
	NonNestedWeight float64
	Provenance      string
	Product         string
	IsIAM           bool
	FileLine        string
	Notes           string
}

type SchemaRecord struct {
	Resource      string
	AttributePath string
	Type          string
	Required      bool
	Optional      bool
	Computed      bool
	AttrClass     string
	IsBlock       bool
	BlockKind     string
	FileLine      string
}

type ResourceResult struct {
	Hits          []Hit
	SchemaRecords []SchemaRecord
	AttrMap       map[string]*SchemaAttr
}

type resourceStats struct {
	Entry          RegistryEntry
	Score          float64
	NestedTotal    float64
	NonNestedTotal float64
	FamilyHits     map[string]float64
	ClassHits      map[string]float64
	NestedCritical float64
}

type TierResult struct {
	Resource        string
	Score           float64
	NestedWeight    float64
	NonNestedWeight float64
	Tier            string
	LikelyBreaking  bool
	Stats           *resourceStats
}

type TierThresholds struct {
	P50             float64
	P75             float64
	P90             float64
	NestedThreshold float64
	NestedP75       float64
}

type Analyzer struct {
	registryMap map[string]RegistryEntry
	funcIndex   map[string]string
	varIndex    map[string]string
	fileCache   map[string]*ParsedFile
	detectorMap map[string]string
}

type resourceContext struct {
	analyzer   *Analyzer
	entry      RegistryEntry
	filePath   string
	pf         *ParsedFile
	attrMap    map[string]*SchemaAttr
	hits       []Hit
	schemaRecs []SchemaRecord
}

func main() {
	pilotFlag := flag.Bool("pilot", false, "run pilot sample instead of full scan")
	flag.Parse()

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", outputDir, err)
	}

	registry, err := loadRegistry(filepath.Join(outputDir, "resource_registry.csv"))
	if err != nil {
		log.Fatalf("load registry: %v", err)
	}
	registryMap := make(map[string]RegistryEntry, len(registry))
	for _, entry := range registry {
		registryMap[entry.Resource] = entry
	}

	config := RunConfig{Pilot: *pilotFlag}
	if config.Pilot {
		config.Prefix = "pilot_"
	}

	analyzer := &Analyzer{
		registryMap: registryMap,
		funcIndex:   map[string]string{},
		varIndex:    map[string]string{},
		fileCache:   map[string]*ParsedFile{},
		detectorMap: map[string]string{},
	}

	if err := analyzer.loadDetectorDictionary(); err != nil {
		log.Printf("[INFO] starting detector dictionary from scratch: %v", err)
	}

	if err := analyzer.buildIndex(); err != nil {
		log.Fatalf("build index: %v", err)
	}

	var resources []RegistryEntry
	if config.Pilot {
		resources = selectPilotSample(registry)
		log.Printf("Pilot sample size: %d", len(resources))
	} else {
		resources = registry
		log.Printf("Full scan on %d resources", len(resources))
	}

	var allHits []Hit
	var allSchemaRecords []SchemaRecord
	attrMaps := make(map[string]map[string]*SchemaAttr)

	for _, entry := range resources {
		result, err := analyzer.processResource(entry)
		if err != nil {
			log.Printf("[WARN] skipping resource %s: %v", entry.Resource, err)
			continue
		}
		allHits = append(allHits, result.Hits...)
		allSchemaRecords = append(allSchemaRecords, result.SchemaRecords...)
		attrMaps[entry.Resource] = result.AttrMap
	}

	if len(allHits) == 0 {
		log.Fatal("no hits collected")
	}

	if err := writeSchemaInventory(filepath.Join(outputDir, config.Prefix+"schema_inventory.csv"), allSchemaRecords); err != nil {
		log.Fatalf("write schema inventory: %v", err)
	}

	if err := writeHits(filepath.Join(outputDir, config.Prefix+"detector_hits.csv"), allHits); err != nil {
		log.Fatalf("write hits: %v", err)
	}

	stats := computeResourceStats(allHits, resources)

	if err := writeHeatmap(filepath.Join(outputDir, config.Prefix+"heatmap.csv"), stats); err != nil {
		log.Fatalf("write heatmap: %v", err)
	}
	if err := writeClassHeatmap(filepath.Join(outputDir, config.Prefix+"class_heatmap.csv"), stats); err != nil {
		log.Fatalf("write class heatmap: %v", err)
	}

	tierResults, thresholds, err := writeTiers(filepath.Join(outputDir, config.Prefix+"tiers.csv"), stats)
	if err != nil {
		log.Fatalf("write tiers: %v", err)
	}

	if err := writeTop20(filepath.Join(outputDir, config.Prefix+"top20.csv"), tierResults); err != nil {
		log.Fatalf("write top20: %v", err)
	}
	if err := writeProductHeatmap(filepath.Join(outputDir, config.Prefix+"product_heatmap.csv"), stats); err != nil {
		log.Fatalf("write product heatmap: %v", err)
	}
	if err := writeProvenanceHeatmap(filepath.Join(outputDir, config.Prefix+"provenance_heatmap.csv"), stats); err != nil {
		log.Fatalf("write provenance heatmap: %v", err)
	}
	if err := writeProductSummary(filepath.Join(outputDir, config.Prefix+"product_summary.csv"), stats, tierResults); err != nil {
		log.Fatalf("write product summary: %v", err)
	}
	if err := writeProductTop(filepath.Join(outputDir, config.Prefix+"product_top.csv"), stats, tierResults); err != nil {
		log.Fatalf("write product top: %v", err)
	}
	if err := writeProvenanceSummary(filepath.Join(outputDir, config.Prefix+"provenance_summary.csv"), stats, tierResults); err != nil {
		log.Fatalf("write provenance summary: %v", err)
	}
	if err := writeIamSummary(filepath.Join(outputDir, config.Prefix+"iam_summary.csv"), stats, tierResults); err != nil {
		log.Fatalf("write IAM summary: %v", err)
	}

	if err := analyzer.saveDetectorDictionary(); err != nil {
		log.Fatalf("write detector dictionary: %v", err)
	}

	if err := runQC(allHits, attrMaps, analyzer.registryMap); err != nil {
		log.Fatalf("QC failed: %v", err)
	}

	if err := writeMethods(filepath.Join(outputDir, config.Prefix+"METHODS.md"), config); err != nil {
		log.Fatalf("write METHODS.md: %v", err)
	}
	if err := writeTierSummary(filepath.Join(outputDir, config.Prefix+"TIER_SUMMARY.md"), thresholds, tierResults); err != nil {
		log.Fatalf("write TIER_SUMMARY.md: %v", err)
	}

	printFinalSummary(allHits, stats, tierResults)
}

func loadRegistry(path string) ([]RegistryEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("registry empty")
	}
	header := map[string]int{}
	for i, h := range rows[0] {
		header[h] = i
	}
	var entries []RegistryEntry
	for _, row := range rows[1:] {
		entry := RegistryEntry{
			Resource:     row[header["resource"]],
			Provenance:   row[header["provenance"]],
			Product:      row[header["product"]],
			IsIAM:        strings.EqualFold(row[header["is_iam"]], "true"),
			SchemaCallee: row[header["schema_callee"]],
			FileLine:     row[header["file_path:line"]],
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func selectPilotSample(registry []RegistryEntry) []RegistryEntry {
	var generated, handwritten, iam []RegistryEntry
	for _, entry := range registry {
		switch entry.Provenance {
		case "Generated":
			generated = append(generated, entry)
		case "Handwritten":
			handwritten = append(handwritten, entry)
		case "HandwrittenIAM":
			iam = append(iam, entry)
		}
	}

	shuffle := func(list []RegistryEntry) {
		rand.Seed(42)
		rand.Shuffle(len(list), func(i, j int) { list[i], list[j] = list[j], list[i] })
	}
	shuffle(generated)
	shuffle(handwritten)
	shuffle(iam)

	type bucket struct {
		entries []RegistryEntry
		target  int
	}
	buckets := []bucket{
		{generated, 10},
		{handwritten, 5},
		{iam, 5},
	}

	var sample []RegistryEntry
	for _, b := range buckets {
		if len(b.entries) < b.target {
			b.target = len(b.entries)
		}
		selected := selectByProduct(b.entries, b.target)
		sample = append(sample, selected...)
	}
	return sample
}

func selectByProduct(entries []RegistryEntry, target int) []RegistryEntry {
	if len(entries) <= target {
		return entries
	}
	productMap := map[string][]RegistryEntry{}
	for _, e := range entries {
		productMap[e.Product] = append(productMap[e.Product], e)
	}
	products := make([]string, 0, len(productMap))
	for p := range productMap {
		products = append(products, p)
	}
	rand.Seed(42)
	rand.Shuffle(len(products), func(i, j int) { products[i], products[j] = products[j], products[i] })
	var selected []RegistryEntry
	for len(selected) < target {
		for _, product := range products {
			if len(selected) >= target {
				break
			}
			list := productMap[product]
			if len(list) == 0 {
				continue
			}
			selected = append(selected, list[0])
			productMap[product] = list[1:]
		}
	}
	return selected
}

func (a *Analyzer) buildIndex() error {
	if err := filepath.Walk(filepath.Join("google-beta", "services"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if strings.Contains(path, "vendor") || strings.Contains(path, "third_party") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		return a.indexFile(path)
	}); err != nil {
		return err
	}
	if err := filepath.Walk(filepath.Join("google-beta", "tpgiamresource"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		return a.indexFile(path)
	}); err != nil {
		return err
	}
	return nil
}

func (a *Analyzer) indexFile(path string) error {
	pf, err := a.parseFile(path)
	if err != nil {
		return err
	}
	for _, decl := range pf.File.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Name != nil {
				a.funcIndex[d.Name.Name] = path
			}
		case *ast.GenDecl:
			if d.Tok != token.VAR {
				continue
			}
			for _, spec := range d.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for _, name := range vs.Names {
						a.varIndex[name.Name] = path
					}
				}
			}
		}
	}
	return nil
}

func (a *Analyzer) parseFile(path string) (*ParsedFile, error) {
	if cached, ok := a.fileCache[path]; ok {
		return cached, nil
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	pf := &ParsedFile{Fset: fset, File: file}
	a.fileCache[path] = pf
	return pf, nil
}

func (a *Analyzer) processResource(entry RegistryEntry) (ResourceResult, error) {
	funcName := extractFuncName(entry.SchemaCallee)
	filePath, ok := a.funcIndex[funcName]
	if !ok {
		return ResourceResult{}, fmt.Errorf("function %s not indexed", funcName)
	}
	pf, err := a.parseFile(filePath)
	if err != nil {
		return ResourceResult{}, err
	}
	fn := findFuncDecl(pf.File, funcName)
	if fn == nil {
		return ResourceResult{}, fmt.Errorf("function %s not found in %s", funcName, filePath)
	}
	resourceLit := findResourceComposite(pf.Fset, fn)
	if resourceLit == nil {
		return ResourceResult{}, fmt.Errorf("resource literal missing for %s", entry.Resource)
	}

	ctx := &resourceContext{
		analyzer:   a,
		entry:      entry,
		filePath:   filePath,
		pf:         pf,
		attrMap:    map[string]*SchemaAttr{},
		hits:       []Hit{},
		schemaRecs: []SchemaRecord{},
	}

	if err := ctx.extract(resourceLit); err != nil {
		return ResourceResult{}, err
	}

	return ResourceResult{
		Hits:          ctx.hits,
		SchemaRecords: ctx.schemaRecs,
		AttrMap:       ctx.attrMap,
	}, nil
}

func (a *Analyzer) loadDetectorDictionary() error {
	path := filepath.Join(outputDir, "detector_dictionary.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &a.detectorMap); err != nil {
		return err
	}
	delete(a.detectorMap, "func")
	return nil
}

func (a *Analyzer) saveDetectorDictionary() error {
	path := filepath.Join(outputDir, "detector_dictionary.json")
	type kv struct {
		Key string
		Val string
	}
	var list []kv
	for k, v := range a.detectorMap {
		if strings.TrimSpace(k) == "" {
			continue
		}
		if k == "func" {
			continue
		}
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Key < list[j].Key })
	ordered := map[string]string{}
	for _, item := range list {
		ordered[item.Key] = item.Val
	}
	data, err := json.MarshalIndent(ordered, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func extractFuncName(callee string) string {
	if idx := strings.LastIndex(callee, "."); idx >= 0 {
		return callee[idx+1:]
	}
	return callee
}

func findFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name != nil && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

func findResourceComposite(fset *token.FileSet, fn *ast.FuncDecl) *ast.CompositeLit {
	if fn.Body == nil {
		return nil
	}
	for _, stmt := range fn.Body.List {
		switch s := stmt.(type) {
		case *ast.AssignStmt:
			for i, lhs := range s.Lhs {
				if _, ok := lhs.(*ast.Ident); !ok {
					continue
				}
				if i >= len(s.Rhs) {
					continue
				}
				if comp := toCompositeResource(s.Rhs[i]); comp != nil {
					return comp
				}
				if ident, ok := s.Rhs[i].(*ast.Ident); ok {
					if comp := findCompositeAssigned(fn.Body, ident.Name); comp != nil {
						return comp
					}
				}
			}
		case *ast.ReturnStmt:
			if len(s.Results) == 0 {
				continue
			}
			if comp := toCompositeResource(s.Results[0]); comp != nil {
				return comp
			}
			if ident, ok := s.Results[0].(*ast.Ident); ok {
				if comp := findCompositeAssigned(fn.Body, ident.Name); comp != nil {
					return comp
				}
			}
		}
	}
	return nil
}

func toCompositeResource(expr ast.Expr) *ast.CompositeLit {
	switch v := expr.(type) {
	case *ast.UnaryExpr:
		if v.Op == token.AND {
			if comp, ok := v.X.(*ast.CompositeLit); ok {
				return comp
			}
		}
	case *ast.CompositeLit:
		return v
	}
	return nil
}

func findCompositeAssigned(body *ast.BlockStmt, name string) *ast.CompositeLit {
	if body == nil {
		return nil
	}
	for _, stmt := range body.List {
		switch s := stmt.(type) {
		case *ast.AssignStmt:
			for i, lhs := range s.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok || ident.Name != name {
					continue
				}
				if i >= len(s.Rhs) {
					continue
				}
				if comp := toCompositeResource(s.Rhs[i]); comp != nil {
					return comp
				}
			}
		case *ast.DeclStmt:
			if decl, ok := s.Decl.(*ast.GenDecl); ok {
				for _, spec := range decl.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok {
						for i, ident := range vs.Names {
							if ident.Name != name {
								continue
							}
							if i >= len(vs.Values) {
								continue
							}
							if comp := toCompositeResource(vs.Values[i]); comp != nil {
								return comp
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func (rc *resourceContext) extract(lit *ast.CompositeLit) error {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key := exprString(rc.pf.Fset, kv.Key)
		switch key {
		case "Schema":
			if err := rc.processSchemaMap(kv.Value); err != nil {
				return err
			}
		case "CustomizeDiff":
			rc.processCustomizeDiff(kv.Value)
		}
	}
	return nil
}

func (rc *resourceContext) processSchemaMap(expr ast.Expr) error {
	switch v := expr.(type) {
	case *ast.CompositeLit:
		return rc.processSchemaComposite(v, nil)
	case *ast.CallExpr:
		return rc.processSchemaFromFunction(v, nil)
	case *ast.Ident:
		return rc.processSchemaFromIdent(v, nil)
	default:
		return fmt.Errorf("schema unsupported expression %T", expr)
	}
}

func (rc *resourceContext) parseSchemaAttr(path []string, expr ast.Expr) (*SchemaAttr, error) {
	switch v := expr.(type) {
	case *ast.UnaryExpr:
		if v.Op == token.AND {
			if comp, ok := v.X.(*ast.CompositeLit); ok {
				return rc.parseSchemaAttrFromComposite(path, comp)
			}
		}
	case *ast.CompositeLit:
		return rc.parseSchemaAttrFromComposite(path, v)
	case *ast.CallExpr:
		return rc.resolveSchemaAttrCall(path, v)
	case *ast.Ident:
		return rc.resolveSchemaAttrIdent(path, v.Name)
	}
	return nil, fmt.Errorf("unexpected schema attr expression %T", expr)
}

func (rc *resourceContext) parseSchemaAttrFromComposite(path []string, comp *ast.CompositeLit) (*SchemaAttr, error) {
	attr := &SchemaAttr{Path: append([]string{}, path...)}

	for _, elt := range comp.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key := exprString(rc.pf.Fset, kv.Key)
		switch key {
		case "Type":
			attr.Type = exprString(rc.pf.Fset, kv.Value)
		case "Required":
			attr.Required = boolLiteral(kv.Value)
		case "Optional":
			attr.Optional = boolLiteral(kv.Value)
		case "Computed":
			attr.Computed = boolLiteral(kv.Value)
		case "DiffSuppressFunc":
			det := rc.makeDetector("DiffSuppressFunc", path, kv.Value)
			attr.Detectors = append(attr.Detectors, det)
		case "StateFunc":
			det := rc.makeDetector("StateFunc", path, kv.Value)
			attr.Detectors = append(attr.Detectors, det)
		case "Set":
			det := rc.makeDetector("SetHash", path, kv.Value)
			attr.Detectors = append(attr.Detectors, det)
		case "Elem":
			if childAttr, err := rc.handleElem(path, kv.Value); err == nil && childAttr != nil {
				attr.IsBlock = true
				attr.BlockKind = attr.Type
				attr.Children = append(attr.Children, childAttr.Children...)
			}
		}
	}

	attr.AttrClass = classifyAttr(attr.Required, attr.Optional, attr.Computed)
	attr.Unclear = !attr.Required && !attr.Optional && !attr.Computed
	attr.FileLine = rc.fileLine(comp.Pos())
	return attr, nil
}

func (rc *resourceContext) handleElem(path []string, expr ast.Expr) (*SchemaAttr, error) {
	switch v := expr.(type) {
	case *ast.UnaryExpr:
		if v.Op == token.AND {
			if comp, ok := v.X.(*ast.CompositeLit); ok {
				return rc.parseNestedResource(path, comp)
			}
		}
	case *ast.CompositeLit:
		return rc.parseNestedResource(path, v)
	case *ast.CallExpr:
		name := exprString(rc.pf.Fset, v.Fun)
		return rc.resolveElemCall(path, name, v)
	case *ast.Ident:
		return rc.resolveElemIdent(path, v.Name)
	}
	return nil, nil
}

func (rc *resourceContext) parseNestedResource(path []string, comp *ast.CompositeLit) (*SchemaAttr, error) {
	var nested SchemaAttr
	for _, elt := range comp.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key := exprString(rc.pf.Fset, kv.Key)
		if key != "Schema" {
			continue
		}
		cl, ok := kv.Value.(*ast.CompositeLit)
		if !ok {
			continue
		}
		for _, e := range cl.Elts {
			kv2, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			name := stringLiteral(kv2.Key)
			if name == "" {
				continue
			}
			childPath := append(path, name)
			childAttr, err := rc.parseSchemaAttr(childPath, kv2.Value)
			if err != nil {
				log.Printf("[WARN] nested attr %s: %v", strings.Join(childPath, "."), err)
				continue
			}
			rc.registerAttr(childAttr)
			rc.emitAttr(childAttr)
			rc.traverseAttr(childAttr)
			nested.Children = append(nested.Children, childAttr)
		}
		break
	}
	return &nested, nil
}

func (rc *resourceContext) resolveElemCall(path []string, name string, call *ast.CallExpr) (*SchemaAttr, error) {
	base := baseName(name)
	filePath, ok := rc.analyzer.funcIndex[base]
	if !ok {
		return nil, fmt.Errorf("elem function %s not indexed", base)
	}
	pf, err := rc.analyzer.parseFile(filePath)
	if err != nil {
		return nil, err
	}
	fn := findFuncDecl(pf.File, base)
	if fn == nil {
		return nil, fmt.Errorf("elem function %s not found", base)
	}
	resourceLit := findResourceComposite(pf.Fset, fn)
	if resourceLit == nil {
		return nil, fmt.Errorf("elem resource literal missing for %s", base)
	}
	sub := rc.subContext(filePath, pf)
	subAttr, err := sub.parseNestedResource(path, resourceLit)
	if err != nil {
		return nil, err
	}
	rc.absorb(sub)
	if subAttr != nil {
		subAttr.ElemOrigin = name
	}
	return subAttr, nil
}

func (rc *resourceContext) resolveElemIdent(path []string, name string) (*SchemaAttr, error) {
	filePath, ok := rc.analyzer.varIndex[name]
	if !ok {
		return nil, fmt.Errorf("elem ident %s not indexed", name)
	}
	pf, err := rc.analyzer.parseFile(filePath)
	if err != nil {
		return nil, err
	}
	comp := findResourceVariable(pf, name)
	if comp == nil {
		return nil, fmt.Errorf("elem variable %s not resource", name)
	}
	sub := rc.subContext(filePath, pf)
	subAttr, err := sub.parseNestedResource(path, comp)
	if err != nil {
		return nil, err
	}
	rc.absorb(sub)
	if subAttr != nil {
		subAttr.ElemOrigin = name
	}
	return subAttr, nil
}

func (rc *resourceContext) resolveSchemaAttrCall(path []string, call *ast.CallExpr) (*SchemaAttr, error) {
	name := exprString(rc.pf.Fset, call.Fun)
	base := baseName(name)
	filePath, ok := rc.analyzer.funcIndex[base]
	if !ok {
		return nil, fmt.Errorf("schema attr func %s not indexed", base)
	}
	pf, err := rc.analyzer.parseFile(filePath)
	if err != nil {
		return nil, err
	}
	fn := findFuncDecl(pf.File, base)
	if fn == nil {
		return nil, fmt.Errorf("schema attr func %s not found", base)
	}
	comp := findSchemaComposite(fn)
	if comp == nil {
		return nil, fmt.Errorf("schema attr func %s missing schema literal", base)
	}
	sub := rc.subContext(filePath, pf)
	attr, err := sub.parseSchemaAttrFromComposite(path, comp)
	if err != nil {
		return nil, err
	}
	rc.absorb(sub)
	return attr, nil
}

func (rc *resourceContext) resolveSchemaAttrIdent(path []string, name string) (*SchemaAttr, error) {
	filePath, ok := rc.analyzer.varIndex[name]
	if !ok {
		return nil, fmt.Errorf("schema ident %s not indexed", name)
	}
	pf, err := rc.analyzer.parseFile(filePath)
	if err != nil {
		return nil, err
	}
	comp := findSchemaVariable(pf, name)
	if comp == nil {
		return nil, fmt.Errorf("schema ident %s missing schema literal", name)
	}
	sub := rc.subContext(filePath, pf)
	attr, err := sub.parseSchemaAttrFromComposite(path, comp)
	if err != nil {
		return nil, err
	}
	rc.absorb(sub)
	return attr, nil
}

func findResourceVariable(pf *ParsedFile, name string) *ast.CompositeLit {
	for _, decl := range pf.File.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if ident.Name != name {
					continue
				}
				if i >= len(vs.Values) {
					continue
				}
				if comp := toCompositeResource(vs.Values[i]); comp != nil {
					return comp
				}
			}
		}
	}
	return nil
}

func findSchemaComposite(fn *ast.FuncDecl) *ast.CompositeLit {
	if fn.Body == nil {
		return nil
	}
	for _, stmt := range fn.Body.List {
		switch s := stmt.(type) {
		case *ast.ReturnStmt:
			if len(s.Results) == 0 {
				continue
			}
			if comp := toCompositeSchema(s.Results[0]); comp != nil {
				return comp
			}
			if ident, ok := s.Results[0].(*ast.Ident); ok {
				if comp := findSchemaAssigned(fn.Body, ident.Name); comp != nil {
					return comp
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range s.Lhs {
				if _, ok := lhs.(*ast.Ident); !ok {
					continue
				}
				if i >= len(s.Rhs) {
					continue
				}
				if comp := toCompositeSchema(s.Rhs[i]); comp != nil {
					return comp
				}
				if ident, ok := s.Rhs[i].(*ast.Ident); ok {
					if comp := findSchemaAssigned(fn.Body, ident.Name); comp != nil {
						return comp
					}
				}
			}
		}
	}
	return nil
}

func toCompositeSchema(expr ast.Expr) *ast.CompositeLit {
	switch v := expr.(type) {
	case *ast.UnaryExpr:
		if v.Op == token.AND {
			if comp, ok := v.X.(*ast.CompositeLit); ok {
				return comp
			}
		}
	case *ast.CompositeLit:
		return v
	}
	return nil
}

func findSchemaAssigned(body *ast.BlockStmt, name string) *ast.CompositeLit {
	if body == nil {
		return nil
	}
	for _, stmt := range body.List {
		switch s := stmt.(type) {
		case *ast.AssignStmt:
			for i, lhs := range s.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok || ident.Name != name {
					continue
				}
				if i >= len(s.Rhs) {
					continue
				}
				if comp := toCompositeSchema(s.Rhs[i]); comp != nil {
					return comp
				}
			}
		case *ast.DeclStmt:
			if decl, ok := s.Decl.(*ast.GenDecl); ok {
				for _, spec := range decl.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok {
						for i, ident := range vs.Names {
							if ident.Name != name {
								continue
							}
							if i >= len(vs.Values) {
								continue
							}
							if comp := toCompositeSchema(vs.Values[i]); comp != nil {
								return comp
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func findSchemaVariable(pf *ParsedFile, name string) *ast.CompositeLit {
	for _, decl := range pf.File.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if ident.Name != name {
					continue
				}
				if i >= len(vs.Values) {
					continue
				}
				if comp := toCompositeSchema(vs.Values[i]); comp != nil {
					return comp
				}
			}
		}
	}
	return nil
}

func (rc *resourceContext) processSchemaComposite(comp *ast.CompositeLit, prefix []string) error {
	for _, elt := range comp.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		name := stringLiteral(kv.Key)
		if name == "" {
			continue
		}
		path := append(append([]string{}, prefix...), name)
		attr, err := rc.parseSchemaAttr(path, kv.Value)
		if err != nil {
			log.Printf("[WARN] attr %s: %v", strings.Join(path, "."), err)
			continue
		}
		rc.registerAttr(attr)
		rc.emitAttr(attr)
		rc.traverseAttr(attr)
	}
	return nil
}

func (rc *resourceContext) processSchemaFromFunction(call *ast.CallExpr, prefix []string) error {
	name := exprString(rc.pf.Fset, call.Fun)
	base := baseName(name)
	baseLower := strings.ToLower(base)
	if strings.Contains(baseLower, "mergeschemas") {
		for _, arg := range call.Args {
			switch a := arg.(type) {
			case *ast.CompositeLit:
				if err := rc.processSchemaComposite(a, prefix); err != nil {
					log.Printf("[WARN] merge schema composite: %v", err)
				}
			case *ast.CallExpr:
				if err := rc.processSchemaFromFunction(a, prefix); err != nil {
					log.Printf("[WARN] merge schema call: %v", err)
				}
			case *ast.Ident:
				if err := rc.processSchemaFromIdent(a, prefix); err != nil {
					log.Printf("[WARN] merge schema ident %s: %v", a.Name, err)
				}
			default:
				log.Printf("[WARN] unhandled MergeSchemas arg %T", a)
			}
		}
		return nil
	}
	filePath, ok := rc.analyzer.funcIndex[base]
	if !ok {
		return fmt.Errorf("schema function %s not indexed", base)
	}
	pf, err := rc.analyzer.parseFile(filePath)
	if err != nil {
		return err
	}
	fn := findFuncDecl(pf.File, base)
	if fn == nil {
		return fmt.Errorf("schema function %s not found in %s", base, filePath)
	}
	comp := findSchemaComposite(fn)
	if comp == nil {
		return fmt.Errorf("schema function %s missing schema literal", base)
	}
	sub := rc.subContext(filePath, pf)
	if err := sub.processSchemaComposite(comp, prefix); err != nil {
		return err
	}
	rc.absorb(sub)
	return nil
}

func (rc *resourceContext) processSchemaFromIdent(ident *ast.Ident, prefix []string) error {
	filePath, ok := rc.analyzer.varIndex[ident.Name]
	if !ok {
		return nil
	}
	pf, err := rc.analyzer.parseFile(filePath)
	if err != nil {
		return err
	}
	comp := findSchemaVariable(pf, ident.Name)
	if comp == nil {
		return fmt.Errorf("schema variable %s missing schema literal", ident.Name)
	}
	sub := rc.subContext(filePath, pf)
	if err := sub.processSchemaComposite(comp, prefix); err != nil {
		return err
	}
	rc.absorb(sub)
	return nil
}

func (rc *resourceContext) registerAttr(attr *SchemaAttr) {
	key := strings.Join(attr.Path, ".")
	rc.attrMap[key] = attr
}

func (rc *resourceContext) emitAttr(attr *SchemaAttr) {
	record := SchemaRecord{
		Resource:      rc.entry.Resource,
		AttributePath: strings.Join(attr.Path, "."),
		Type:          attr.Type,
		Required:      attr.Required,
		Optional:      attr.Optional,
		Computed:      attr.Computed,
		AttrClass:     attr.AttrClass,
		IsBlock:       attr.IsBlock,
		BlockKind:     attr.BlockKind,
		FileLine:      attr.FileLine,
	}
	rc.schemaRecs = append(rc.schemaRecs, record)
}

func classifyAttr(required, optional, computed bool) string {
	switch {
	case required:
		return "Required"
	case optional && computed:
		return "Optional+Computed"
	case optional:
		return "Optional"
	case computed:
		return "Computed-only"
	default:
		return "Optional"
	}
}

func (rc *resourceContext) traverseAttr(attr *SchemaAttr) {
	for _, det := range attr.Detectors {
		rc.emitDetector(attr, det)
	}
	if attr.IsBlock {
		det := Detector{
			Kind:     "NestedBlock",
			Name:     attr.Type,
			Family:   "NestedBlock",
			Path:     attr.Path,
			FileLine: attr.FileLine,
		}
		rc.emitDetector(attr, det)
	}
	for _, child := range attr.Children {
		rc.traverseAttr(child)
	}
}

func (rc *resourceContext) makeDetector(kind string, path []string, expr ast.Expr) Detector {
	name := exprString(rc.pf.Fset, expr)
	base := detectorBaseName(name)
	family := classifyDetector(kind, base, name, rc.analyzer.detectorMap)
	if base != "func" {
		rc.analyzer.detectorMap[base] = family
	}
	return Detector{
		Kind:     kind,
		Name:     name,
		Family:   family,
		BaseName: base,
		Path:     append([]string{}, path...),
		FileLine: rc.fileLine(expr.Pos()),
	}
}

func classifyDetector(kind, base, full string, dict map[string]string) string {
	if base != "func" {
		if family, ok := dict[base]; ok && family != "" {
			return family
		}
	}
	baseLower := strings.ToLower(base)
	for pattern, fam := range detectorHeuristics {
		if strings.Contains(baseLower, pattern) {
			return fam
		}
	}
	switch kind {
	case "SetHash":
		return "Ordering"
	case "CustomizeDiff":
		return "CustomizeDiff"
	case "NestedBlock":
		return "NestedBlock"
	default:
		return "Representation"
	}
}

var detectorHeuristics = map[string]string{
	"compare":             "Representation",
	"diffsuppress":        "Representation",
	"normalize":           "Representation",
	"case":                "Representation",
	"lower":               "Representation",
	"emptyordefault":      "NullEmpty",
	"emptyornull":         "NullEmpty",
	"emptyorfalse":        "NullEmpty",
	"setfunc":             "Ordering",
	"sethash":             "Ordering",
	"hashresource":        "Ordering",
	"hashstring":          "Ordering",
	"nestedurlsethash":    "Ordering",
	"defaultproviderproj": "CustomizeDiff",
	"defaultproviderreg":  "CustomizeDiff",
	"defaultproviderzon":  "CustomizeDiff",
	"setlabelsdiff":       "CustomizeDiff",
	"validateauthheader":  "CustomizeDiff",
	"customdiff":          "CustomizeDiff",
	"gcrulesdiff":         "Representation",
}

func detectorBaseName(name string) string {
	n := name
	if idx := strings.Index(n, "("); idx >= 0 {
		n = n[:idx]
	}
	return strings.TrimSpace(n)
}

func (rc *resourceContext) emitDetector(attr *SchemaAttr, det Detector) {
	if det.Family == "" {
		det.Family = classifyDetector(det.Kind, det.BaseName, det.Name, rc.analyzer.detectorMap)
	}
	attrClass := attr.AttrClass
	if attrClass == "" {
		attrClass = "Optional"
	}
	baseWeight := baseFamilyWeights[det.Family]
	classMultiplier := classMultipliers[det.Family][attrClass]
	weight := baseWeight * classMultiplier
	var nestedWeight, nonNestedWeight float64
	if det.Family == "NestedBlock" {
		nestedWeight = weight
	} else {
		nonNestedWeight = weight
	}
	hit := Hit{
		Resource:        rc.entry.Resource,
		AttributePath:   strings.Join(det.Path, "."),
		DetectorKind:    det.Kind,
		DetectorName:    det.Name,
		Family:          det.Family,
		AttrClass:       attrClass,
		BaseWeight:      baseWeight,
		ClassMultiplier: classMultiplier,
		Weight:          weight,
		NestedWeight:    nestedWeight,
		NonNestedWeight: nonNestedWeight,
		Provenance:      rc.entry.Provenance,
		Product:         rc.entry.Product,
		IsIAM:           rc.entry.IsIAM,
		FileLine:        det.FileLine,
		Notes:           det.Notes,
	}
	rc.hits = append(rc.hits, hit)
}

func (rc *resourceContext) processCustomizeDiff(expr ast.Expr) {
	switch v := expr.(type) {
	case *ast.CallExpr:
		name := exprString(rc.pf.Fset, v.Fun)
		if strings.Contains(name, "customdiff.All") {
			for _, arg := range v.Args {
				rc.emitCustomizeExpr(arg)
			}
			return
		}
	}
	rc.emitCustomizeExpr(expr)
}

func (rc *resourceContext) emitCustomizeExpr(expr ast.Expr) {
	name := exprString(rc.pf.Fset, expr)
	base := detectorBaseName(name)
	family := classifyDetector("CustomizeDiff", base, name, rc.analyzer.detectorMap)
	if base != "func" {
		rc.analyzer.detectorMap[base] = family
	}
	attrClass := "Optional"
	baseWeight := baseFamilyWeights["CustomizeDiff"]
	classMultiplier := classMultipliers["CustomizeDiff"][attrClass]
	weight := baseWeight * classMultiplier
	var nestedWeight, nonNestedWeight float64
	if family == "NestedBlock" {
		nestedWeight = weight
	} else {
		nonNestedWeight = weight
	}
	hit := Hit{
		Resource:        rc.entry.Resource,
		AttributePath:   "CustomizeDiff",
		DetectorKind:    "CustomizeDiff",
		DetectorName:    name,
		Family:          family,
		AttrClass:       attrClass,
		BaseWeight:      baseWeight,
		ClassMultiplier: classMultiplier,
		Weight:          weight,
		NestedWeight:    nestedWeight,
		NonNestedWeight: nonNestedWeight,
		Provenance:      rc.entry.Provenance,
		Product:         rc.entry.Product,
		IsIAM:           rc.entry.IsIAM,
		FileLine:        rc.fileLine(expr.Pos()),
	}
	rc.hits = append(rc.hits, hit)
}

func exprString(fset *token.FileSet, expr ast.Expr) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, expr); err != nil {
		return ""
	}
	return buf.String()
}

func stringLiteral(expr ast.Expr) string {
	if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		val, err := strconvUnquote(lit.Value)
		if err == nil {
			return val
		}
	}
	return ""
}

func boolLiteral(expr ast.Expr) bool {
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name == "true"
	}
	return false
}

func (rc *resourceContext) fileLine(pos token.Pos) string {
	position := rc.pf.Fset.Position(pos)
	return fmt.Sprintf("%s:%d", filepath.ToSlash(rc.filePath), position.Line)
}

func (rc *resourceContext) subContext(path string, pf *ParsedFile) *resourceContext {
	return &resourceContext{
		analyzer:   rc.analyzer,
		entry:      rc.entry,
		filePath:   path,
		pf:         pf,
		attrMap:    rc.attrMap,
		hits:       rc.hits,
		schemaRecs: rc.schemaRecs,
	}
}

func (rc *resourceContext) absorb(sub *resourceContext) {
	rc.hits = sub.hits
	rc.schemaRecs = sub.schemaRecs
}

func strconvUnquote(value string) (string, error) {
	if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '`' && value[len(value)-1] == '`')) {
		return value[1 : len(value)-1], nil
	}
	return value, nil
}

func writeSchemaInventory(path string, records []SchemaRecord) error {
	sort.Slice(records, func(i, j int) bool {
		if records[i].Resource == records[j].Resource {
			return records[i].AttributePath < records[j].AttributePath
		}
		return records[i].Resource < records[j].Resource
	})
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	header := []string{"resource", "attribute_path", "type", "required", "optional", "computed", "attr_class", "is_block", "block_kind", "file_path:line"}
	if err := w.Write(header); err != nil {
		return err
	}
	for _, rec := range records {
		row := []string{
			rec.Resource,
			rec.AttributePath,
			rec.Type,
			fmt.Sprintf("%t", rec.Required),
			fmt.Sprintf("%t", rec.Optional),
			fmt.Sprintf("%t", rec.Computed),
			rec.AttrClass,
			fmt.Sprintf("%t", rec.IsBlock),
			rec.BlockKind,
			rec.FileLine,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func writeHits(path string, hits []Hit) error {
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Resource == hits[j].Resource {
			if hits[i].AttributePath == hits[j].AttributePath {
				if hits[i].Family == hits[j].Family {
					return hits[i].DetectorName < hits[j].DetectorName
				}
				return hits[i].Family < hits[j].Family
			}
			return hits[i].AttributePath < hits[j].AttributePath
		}
		return hits[i].Resource < hits[j].Resource
	})
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	header := []string{"resource", "attribute_path", "detector_kind", "detector_name", "family", "attr_class", "base_weight", "class_multiplier", "weight", "nested_weight", "non_nested_weight", "provenance", "product", "is_iam", "file_path:line", "notes"}
	if err := w.Write(header); err != nil {
		return err
	}
	for _, hit := range hits {
		row := []string{
			hit.Resource,
			hit.AttributePath,
			hit.DetectorKind,
			hit.DetectorName,
			hit.Family,
			hit.AttrClass,
			fmt.Sprintf("%.2f", hit.BaseWeight),
			fmt.Sprintf("%.2f", hit.ClassMultiplier),
			fmt.Sprintf("%.2f", hit.Weight),
			fmt.Sprintf("%.2f", hit.NestedWeight),
			fmt.Sprintf("%.2f", hit.NonNestedWeight),
			hit.Provenance,
			hit.Product,
			fmt.Sprintf("%t", hit.IsIAM),
			hit.FileLine,
			hit.Notes,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func computeResourceStats(hits []Hit, resources []RegistryEntry) map[string]*resourceStats {
	stats := map[string]*resourceStats{}
	for _, entry := range resources {
		stats[entry.Resource] = &resourceStats{
			Entry:          entry,
			Score:          0,
			NestedTotal:    0,
			NonNestedTotal: 0,
			FamilyHits:     make(map[string]float64),
			ClassHits:      make(map[string]float64),
		}
	}
	for _, hit := range hits {
		stat := stats[hit.Resource]
		if stat == nil {
			continue
		}
		stat.Score += hit.Weight
		stat.NestedTotal += hit.NestedWeight
		stat.NonNestedTotal += hit.NonNestedWeight
		stat.FamilyHits[hit.Family] += 1
		stat.ClassHits[hit.AttrClass] += 1
		if hit.Family == "NestedBlock" && (hit.AttrClass == "Required" || hit.AttrClass == "Optional" || hit.AttrClass == "Optional+Computed") {
			stat.NestedCritical += 1
		}
	}
	return stats
}

func writeHeatmap(path string, stats map[string]*resourceStats) error {
	resources := sortedKeys(stats)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	header := append([]string{"resource"}, families...)
	if err := w.Write(header); err != nil {
		return err
	}
	for _, resource := range resources {
		stat := stats[resource]
		row := []string{resource}
		for _, fam := range families {
			row = append(row, fmt.Sprintf("%.0f", stat.FamilyHits[fam]))
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func writeClassHeatmap(path string, stats map[string]*resourceStats) error {
	resources := sortedKeys(stats)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	header := append([]string{"resource"}, attrClassOrder...)
	if err := w.Write(header); err != nil {
		return err
	}
	for _, resource := range resources {
		stat := stats[resource]
		row := []string{resource}
		for _, cls := range attrClassOrder {
			row = append(row, fmt.Sprintf("%.0f", stat.ClassHits[cls]))
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func writeTiers(path string, stats map[string]*resourceStats) (map[string]*TierResult, TierThresholds, error) {
	var scores []float64
	var nested []float64
	for _, stat := range stats {
		scores = append(scores, stat.Score)
		nested = append(nested, stat.NestedCritical)
	}
	sort.Float64s(scores)
	sort.Float64s(nested)
	p50 := percentile(scores, 50)
	p75 := percentile(scores, 75)
	p90 := percentile(scores, 90)
	nestedP75 := percentile(nested, 75)
	nestedThreshold := math.Max(2, math.Round(nestedP75))

	results := map[string]*TierResult{}

	f, err := os.Create(path)
	if err != nil {
		return nil, TierThresholds{}, err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	header := []string{"resource", "score", "nested_weight", "non_nested_weight", "tier", "LikelyBreaking", "provenance", "product", "is_iam"}
	for _, fam := range families {
		header = append(header, fam)
	}
	for _, cls := range attrClassOrder {
		header = append(header, cls)
	}
	if err := w.Write(header); err != nil {
		return nil, TierThresholds{}, err
	}

	resources := sortedKeys(stats)
	for _, resource := range resources {
		stat := stats[resource]
		tier := determineTier(stat.Score, stat.NestedCritical, p50, p75, p90, nestedThreshold)
		likelyBreaking := stat.NestedCritical >= 1
		row := []string{
			resource,
			fmt.Sprintf("%.2f", stat.Score),
			fmt.Sprintf("%.2f", stat.NestedTotal),
			fmt.Sprintf("%.2f", stat.NonNestedTotal),
			tier,
			fmt.Sprintf("%t", likelyBreaking),
			stat.Entry.Provenance,
			stat.Entry.Product,
			fmt.Sprintf("%t", stat.Entry.IsIAM),
		}
		for _, fam := range families {
			row = append(row, fmt.Sprintf("%.0f", stat.FamilyHits[fam]))
		}
		for _, cls := range attrClassOrder {
			row = append(row, fmt.Sprintf("%.0f", stat.ClassHits[cls]))
		}
		if err := w.Write(row); err != nil {
			return nil, TierThresholds{}, err
		}
		results[resource] = &TierResult{
			Resource:        resource,
			Score:           stat.Score,
			NestedWeight:    stat.NestedTotal,
			NonNestedWeight: stat.NonNestedTotal,
			Tier:            tier,
			LikelyBreaking:  likelyBreaking,
			Stats:           stat,
		}
	}

	thresholds := TierThresholds{
		P50:             p50,
		P75:             p75,
		P90:             p90,
		NestedP75:       nestedP75,
		NestedThreshold: nestedThreshold,
	}
	return results, thresholds, nil
}

func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	if len(values) == 1 {
		return values[0]
	}
	rank := (p / 100) * float64(len(values)-1)
	lower := int(math.Floor(rank))
	upper := int(math.Ceil(rank))
	if lower == upper {
		return values[lower]
	}
	fraction := rank - float64(lower)
	return values[lower] + fraction*(values[upper]-values[lower])
}

func determineTier(score, nested, p50, p75, p90, nestedThreshold float64) string {
	switch {
	case score >= p90 || nested >= nestedThreshold:
		return "A"
	case score >= p75:
		return "B"
	case score >= p50:
		return "C"
	default:
		return "D"
	}
}

func writeTop20(path string, tiers map[string]*TierResult) error {
	list := make([]*TierResult, 0, len(tiers))
	for _, res := range tiers {
		list = append(list, res)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Score == list[j].Score {
			return list[i].Resource < list[j].Resource
		}
		return list[i].Score > list[j].Score
	})
	if len(list) > 20 {
		list = list[:20]
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	header := []string{"resource", "score", "nested_weight", "non_nested_weight", "tier", "LikelyBreaking", "provenance", "product", "is_iam"}
	if err := w.Write(header); err != nil {
		return err
	}
	for _, item := range list {
		row := []string{
			item.Resource,
			fmt.Sprintf("%.2f", item.Score),
			fmt.Sprintf("%.2f", item.NestedWeight),
			fmt.Sprintf("%.2f", item.NonNestedWeight),
			item.Tier,
			fmt.Sprintf("%t", item.LikelyBreaking),
			item.Stats.Entry.Provenance,
			item.Stats.Entry.Product,
			fmt.Sprintf("%t", item.Stats.Entry.IsIAM),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func writeProductHeatmap(path string, stats map[string]*resourceStats) error {
	productTotals := map[string]map[string]float64{}
	for _, stat := range stats {
		if _, ok := productTotals[stat.Entry.Product]; !ok {
			productTotals[stat.Entry.Product] = map[string]float64{}
		}
		for _, fam := range families {
			productTotals[stat.Entry.Product][fam] += stat.FamilyHits[fam]
		}
	}
	products := sortedKeysMapFloat(productTotals)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	header := append([]string{"product"}, families...)
	if err := w.Write(header); err != nil {
		return err
	}
	for _, product := range products {
		row := []string{product}
		for _, fam := range families {
			row = append(row, fmt.Sprintf("%.0f", productTotals[product][fam]))
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func writeProvenanceHeatmap(path string, stats map[string]*resourceStats) error {
	provTotals := map[string]map[string]float64{}
	for _, stat := range stats {
		if _, ok := provTotals[stat.Entry.Provenance]; !ok {
			provTotals[stat.Entry.Provenance] = map[string]float64{}
		}
		for _, fam := range families {
			provTotals[stat.Entry.Provenance][fam] += stat.FamilyHits[fam]
		}
	}
	provs := sortedKeysMapFloat(provTotals)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	header := append([]string{"provenance"}, families...)
	if err := w.Write(header); err != nil {
		return err
	}
	for _, prov := range provs {
		row := []string{prov}
		for _, fam := range families {
			row = append(row, fmt.Sprintf("%.0f", provTotals[prov][fam]))
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func writeProductSummary(path string, stats map[string]*resourceStats, tiers map[string]*TierResult) error {
	type summary struct {
		Product        string
		FamilyCounts   map[string]float64
		TotalScore     float64
		TotalNested    float64
		TotalNonNested float64
		ResourceCnt    int
		IamCnt         int
	}
	summaries := map[string]*summary{}
	for _, stat := range stats {
		sum := summaries[stat.Entry.Product]
		if sum == nil {
			sum = &summary{
				Product:      stat.Entry.Product,
				FamilyCounts: map[string]float64{},
			}
			summaries[stat.Entry.Product] = sum
		}
		sum.TotalScore += stat.Score
		sum.TotalNested += stat.NestedTotal
		sum.TotalNonNested += stat.NonNestedTotal
		sum.ResourceCnt++
		if stat.Entry.IsIAM {
			sum.IamCnt++
		}
		for _, fam := range families {
			sum.FamilyCounts[fam] += stat.FamilyHits[fam]
		}
	}
	products := sortedKeysGeneric(summaries)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	header := []string{"product"}
	header = append(header, families...)
	header = append(header, "TotalScore", "TotalNestedWeight", "TotalNonNestedWeight", "ResourceCount", "AverageScore", "PercentIAM")
	if err := w.Write(header); err != nil {
		return err
	}
	for _, product := range products {
		sum := summaries[product]
		row := []string{product}
		for _, fam := range families {
			row = append(row, fmt.Sprintf("%.0f", sum.FamilyCounts[fam]))
		}
		avg := 0.0
		if sum.ResourceCnt > 0 {
			avg = sum.TotalScore / float64(sum.ResourceCnt)
		}
		percentIAM := 0.0
		if sum.ResourceCnt > 0 {
			percentIAM = (float64(sum.IamCnt) / float64(sum.ResourceCnt)) * 100
		}
		row = append(row,
			fmt.Sprintf("%.2f", sum.TotalScore),
			fmt.Sprintf("%.2f", sum.TotalNested),
			fmt.Sprintf("%.2f", sum.TotalNonNested),
			fmt.Sprintf("%d", sum.ResourceCnt),
			fmt.Sprintf("%.2f", avg),
			fmt.Sprintf("%.1f", percentIAM),
		)
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func writeProductTop(path string, stats map[string]*resourceStats, tiers map[string]*TierResult) error {
	type entry struct {
		Product string
		Tier    *TierResult
	}
	top := map[string]*TierResult{}
	for resource, tier := range tiers {
		product := stats[resource].Entry.Product
		current := top[product]
		if current == nil || tier.Score > current.Score {
			top[product] = tier
		}
	}
	products := sortedKeysGeneric(top)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"product", "resource", "score", "nested_weight", "non_nested_weight", "tier", "LikelyBreaking", "provenance", "is_iam"}); err != nil {
		return err
	}
	for _, product := range products {
		tier := top[product]
		stat := stats[tier.Resource]
		row := []string{
			product,
			tier.Resource,
			fmt.Sprintf("%.2f", tier.Score),
			fmt.Sprintf("%.2f", tier.NestedWeight),
			fmt.Sprintf("%.2f", tier.NonNestedWeight),
			tier.Tier,
			fmt.Sprintf("%t", tier.LikelyBreaking),
			stat.Entry.Provenance,
			fmt.Sprintf("%t", stat.Entry.IsIAM),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func writeProvenanceSummary(path string, stats map[string]*resourceStats, tiers map[string]*TierResult) error {
	type summary struct {
		Provenance     string
		Score          float64
		NestedTotal    float64
		NonNestedTotal float64
		Resources      int
		WithHits       int
		FamilyCount    map[string]float64
	}
	summaries := map[string]*summary{}
	for _, stat := range stats {
		sum := summaries[stat.Entry.Provenance]
		if sum == nil {
			sum = &summary{
				Provenance:  stat.Entry.Provenance,
				FamilyCount: map[string]float64{},
			}
			summaries[stat.Entry.Provenance] = sum
		}
		sum.Resources++
		if stat.Score > 0 {
			sum.WithHits++
		}
		sum.Score += stat.Score
		sum.NestedTotal += stat.NestedTotal
		sum.NonNestedTotal += stat.NonNestedTotal
		for _, fam := range families {
			sum.FamilyCount[fam] += stat.FamilyHits[fam]
		}
	}
	provs := sortedKeysGeneric(summaries)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	header := []string{"provenance", "resource_count", "with_hits", "coverage_percent", "total_score", "total_nested_weight", "total_non_nested_weight"}
	header = append(header, families...)
	if err := w.Write(header); err != nil {
		return err
	}
	for _, prov := range provs {
		sum := summaries[prov]
		coverage := 0.0
		if sum.Resources > 0 {
			coverage = float64(sum.WithHits) / float64(sum.Resources) * 100
		}
		row := []string{
			prov,
			fmt.Sprintf("%d", sum.Resources),
			fmt.Sprintf("%d", sum.WithHits),
			fmt.Sprintf("%.1f", coverage),
			fmt.Sprintf("%.2f", sum.Score),
			fmt.Sprintf("%.2f", sum.NestedTotal),
			fmt.Sprintf("%.2f", sum.NonNestedTotal),
		}
		for _, fam := range families {
			row = append(row, fmt.Sprintf("%.0f", sum.FamilyCount[fam]))
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func writeIamSummary(path string, stats map[string]*resourceStats, tiers map[string]*TierResult) error {
	type summary struct {
		Label          string
		Score          float64
		NestedTotal    float64
		NonNestedTotal float64
		Resources      int
		WithHits       int
		FamilyHits     map[string]float64
	}
	group := map[string]*summary{
		"IAM":    {Label: "IAM", FamilyHits: map[string]float64{}},
		"nonIAM": {Label: "nonIAM", FamilyHits: map[string]float64{}},
	}
	for _, stat := range stats {
		key := "nonIAM"
		if stat.Entry.IsIAM {
			key = "IAM"
		}
		sum := group[key]
		sum.Resources++
		if stat.Score > 0 {
			sum.WithHits++
		}
		sum.Score += stat.Score
		sum.NestedTotal += stat.NestedTotal
		sum.NonNestedTotal += stat.NonNestedTotal
		for _, fam := range families {
			sum.FamilyHits[fam] += stat.FamilyHits[fam]
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	header := []string{"group", "resource_count", "with_hits", "coverage_percent", "total_score", "total_nested_weight", "total_non_nested_weight"}
	header = append(header, families...)
	if err := w.Write(header); err != nil {
		return err
	}
	for _, key := range []string{"IAM", "nonIAM"} {
		sum := group[key]
		coverage := 0.0
		if sum.Resources > 0 {
			coverage = float64(sum.WithHits) / float64(sum.Resources) * 100
		}
		row := []string{
			sum.Label,
			fmt.Sprintf("%d", sum.Resources),
			fmt.Sprintf("%d", sum.WithHits),
			fmt.Sprintf("%.1f", coverage),
			fmt.Sprintf("%.2f", sum.Score),
			fmt.Sprintf("%.2f", sum.NestedTotal),
			fmt.Sprintf("%.2f", sum.NonNestedTotal),
		}
		for _, fam := range families {
			row = append(row, fmt.Sprintf("%.0f", sum.FamilyHits[fam]))
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func runQC(hits []Hit, attrMaps map[string]map[string]*SchemaAttr, registry map[string]RegistryEntry) error {
	total := float64(len(hits))
	if total == 0 {
		return errors.New("no hits for QC")
	}
	unclearOptional := 0
	for _, hit := range hits {
		if _, ok := excludedFamily[hit.Family]; ok {
			return fmt.Errorf("excluded family detected in hits: %s", hit.Family)
		}
		if _, ok := registry[hit.Resource]; !ok {
			return fmt.Errorf("resource %s not found in registry", hit.Resource)
		}
		if hit.AttributePath == "" || hit.AttributePath == "CustomizeDiff" {
			continue
		}
		if attr := attrMaps[hit.Resource][hit.AttributePath]; attr != nil && attr.Unclear && hit.AttrClass == "Optional" {
			unclearOptional++
		}
	}
	if (float64(unclearOptional)/total)*100 > 5 {
		return fmt.Errorf("attr_class Optional due to unclear flags exceeds 5%% (%d/%d)", unclearOptional, len(hits))
	}
	return nil
}

func writeMethods(path string, config RunConfig) error {
	mode := "Full scan across all resources"
	if config.Pilot {
		mode = "Pilot sample (~20 resources stratified by provenance/product)"
	}
	lines := []string{
		"# Methods",
		"",
		fmt.Sprintf("- Run mode: %s.", mode),
		"- Families evaluated: Representation, NullEmpty, Ordering, CustomizeDiff, NestedBlock.",
		"- Excluded families: Intent/State, Timestamp (none emitted).",
		"- Attribute class determination: Required/Optional/Computed flags from schema; default Optional when unspecified (tracked as \"unclear\").",
		"- Nested blocks detected via TypeList/TypeSet with Elem &schema.Resource{} (including helper functions and MergeSchemas).",
		"- Detectors captured from DiffSuppressFunc, StateFunc, Set hashing, CustomizeDiff hooks, and nested block declarations.",
		"- Weight matrix:",
		"  - Base weights: Representation/NullEmpty/Ordering=1.0, CustomizeDiff=1.5, NestedBlock=2.0.",
		"  - Class multipliers: Required=1.2, Optional=1.0, Optional+Computed=1.1 (Ordering 1.2); CustomizeDiff Required=1.6, Optional=1.5; NestedBlock Required=0.0, Optional=0.0, Optional+Computed=1.0, Computed-only=1.0.",
		"- Outputs include schema inventory, per-hit CSV, heatmaps, tiering, top resources, and product/provenance summaries.",
		"- Detector dictionary updated with all observed helper functions.",
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func writeTierSummary(path string, thresholds TierThresholds, tiers map[string]*TierResult) error {
	counts := map[string]int{"A": 0, "B": 0, "C": 0, "D": 0}
	likelyBreaking := 0
	for _, tier := range tiers {
		counts[tier.Tier]++
		if tier.LikelyBreaking {
			likelyBreaking++
		}
	}
	lines := []string{
		"# Tier Summary",
		fmt.Sprintf("- Score percentiles: P50=%.2f, P75=%.2f, P90=%.2f.", thresholds.P50, thresholds.P75, thresholds.P90),
		fmt.Sprintf("- Nested block threshold: P75=%.2f → override X=%.0f nested critical blocks.", thresholds.NestedP75, thresholds.NestedThreshold),
		fmt.Sprintf("- Tier counts: A=%d, B=%d, C=%d, D=%d.", counts["A"], counts["B"], counts["C"], counts["D"]),
		fmt.Sprintf("- LikelyBreaking resources (nested block with mutable attrs): %d.", likelyBreaking),
		"- Tiering rule: Tier A if score ≥ P90 or nested blocks ≥ X; Tier B ≥ P75; Tier C ≥ P50; Tier D otherwise.",
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func printFinalSummary(hits []Hit, stats map[string]*resourceStats, tiers map[string]*TierResult) {
	// Hits by family and attr class
	familyCounts := map[string]int{}
	classCounts := map[string]int{}
	totalNestedWeight := 0.0
	totalNonNestedWeight := 0.0
	detectorByFamily := map[string]map[string]int{}
	for _, hit := range hits {
		familyCounts[hit.Family]++
		classCounts[hit.AttrClass]++
		if _, ok := detectorByFamily[hit.Family]; !ok {
			detectorByFamily[hit.Family] = map[string]int{}
		}
		base := detectorBaseName(hit.DetectorName)
		detectorByFamily[hit.Family][base]++
		totalNestedWeight += hit.NestedWeight
		totalNonNestedWeight += hit.NonNestedWeight
	}

	fmt.Println("=== Final Summary ===")
	fmt.Println("Hits by family:")
	famKeys := sortedKeysInt(familyCounts)
	for _, fam := range famKeys {
		fmt.Printf("  %s: %d\n", fam, familyCounts[fam])
	}
	fmt.Println("Hits by attr_class:")
	classKeys := sortedKeysInt(classCounts)
	for _, cls := range classKeys {
		fmt.Printf("  %s: %d\n", cls, classCounts[cls])
	}

	// Coverage by provenance
	provTotal := map[string]int{}
	provWithHits := map[string]int{}
	prodTotal := map[string]int{}
	prodWithHits := map[string]int{}
	for _, stat := range stats {
		provTotal[stat.Entry.Provenance]++
		prodTotal[stat.Entry.Product]++
		if stat.Score > 0 {
			provWithHits[stat.Entry.Provenance]++
			prodWithHits[stat.Entry.Product]++
		}
	}
	fmt.Printf("Total nested weight: %.2f\n", totalNestedWeight)
	fmt.Printf("Total non-nested weight: %.2f\n", totalNonNestedWeight)

	fmt.Println("Coverage by provenance:")
	for _, prov := range sortedKeysGeneric(provTotal) {
		t := provTotal[prov]
		h := provWithHits[prov]
		coverage := 0.0
		if t > 0 {
			coverage = float64(h) / float64(t) * 100
		}
		fmt.Printf("  %s: %d/%d (%.1f%%)\n", prov, h, t, coverage)
	}

	// Top products by average score
	type prodScore struct {
		Product string
		Score   float64
		Count   int
	}
	var prodList []prodScore
	for product, total := range prodTotal {
		score := 0.0
		for _, stat := range stats {
			if stat.Entry.Product == product {
				score += stat.Score
			}
		}
		prodList = append(prodList, prodScore{Product: product, Score: score, Count: total})
	}
	sort.Slice(prodList, func(i, j int) bool {
		avgI := 0.0
		if prodList[i].Count > 0 {
			avgI = prodList[i].Score / float64(prodList[i].Count)
		}
		avgJ := 0.0
		if prodList[j].Count > 0 {
			avgJ = prodList[j].Score / float64(prodList[j].Count)
		}
		if avgI == avgJ {
			return prodList[i].Product < prodList[j].Product
		}
		return avgI > avgJ
	})
	if len(prodList) > 5 {
		prodList = prodList[:5]
	}
	fmt.Println("Top products by average score:")
	for _, item := range prodList {
		avg := 0.0
		if item.Count > 0 {
			avg = item.Score / float64(item.Count)
		}
		fmt.Printf("  %s: avg %.2f across %d resources\n", item.Product, avg, item.Count)
	}

	fmt.Println("Top detector functions per family:")
	famList := make([]string, 0, len(detectorByFamily))
	for fam := range detectorByFamily {
		famList = append(famList, fam)
	}
	sort.Strings(famList)
	for _, fam := range famList {
		counts := detectorByFamily[fam]
		var list []struct {
			Name  string
			Count int
		}
		for name, count := range counts {
			list = append(list, struct {
				Name  string
				Count int
			}{name, count})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Count == list[j].Count {
				return list[i].Name < list[j].Name
			}
			return list[i].Count > list[j].Count
		})
		if len(list) > 5 {
			list = list[:5]
		}
		fmt.Printf("  %s:\n", fam)
		for _, item := range list {
			fmt.Printf("    %s (%d)\n", item.Name, item.Count)
		}
	}
}

func sortedKeys(stats map[string]*resourceStats) []string {
	keys := make([]string, 0, len(stats))
	for k := range stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysMapFloat(m map[string]map[string]float64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysInt(m map[string]int) []string {
	return sortedKeysGeneric(m)
}

func sortedKeysGeneric[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func baseName(name string) string {
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		return name[idx+1:]
	}
	return name
}
