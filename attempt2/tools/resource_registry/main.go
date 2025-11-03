package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

type entry struct {
	Resource     string
	Provenance   string
	Product      string
	IsIAM        bool
	SchemaCallee string
	FileLine     string
}

func main() {
	const relPath = "google-beta/provider/provider_mmv1_resources.go"

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, relPath, nil, parser.ParseComments)
	if err != nil {
		log.Fatalf("parse %s: %v", relPath, err)
	}

	var entries []entry
	ast.Inspect(file, func(n ast.Node) bool {
		genDecl, ok := n.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.VAR {
			return true
		}

		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok || len(valueSpec.Names) == 0 {
				continue
			}

			name := valueSpec.Names[0].Name
			provenance := provenanceFor(name)
			if provenance == "" {
				continue
			}

			if len(valueSpec.Values) != 1 {
				log.Printf("skipping %s: unexpected value count %d", name, len(valueSpec.Values))
				continue
			}

			compLit, ok := valueSpec.Values[0].(*ast.CompositeLit)
			if !ok {
				log.Printf("skipping %s: value is %T not *ast.CompositeLit", name, valueSpec.Values[0])
				continue
			}

			for _, elt := range compLit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				resourceName := extractResourceName(kv.Key)
				if resourceName == "" {
					continue
				}

				callExpr, ok := kv.Value.(*ast.CallExpr)
				if !ok {
					log.Printf("skipping resource %s: value is %T not *ast.CallExpr", resourceName, kv.Value)
					continue
				}

				schemaCallee := exprToString(fset, callExpr.Fun)
				product, isIAM := inferProduct(callExpr, name)
				fileLine := formatFileLine(relPath, fset.Position(kv.Key.Pos()).Line)

				entries = append(entries, entry{
					Resource:     resourceName,
					Provenance:   provenance,
					Product:      product,
					IsIAM:        isIAM,
					SchemaCallee: schemaCallee,
					FileLine:     fileLine,
				})
			}
		}

		return true
	})

	if len(entries) == 0 {
		log.Fatal("no entries collected")
	}

	writeCSV(entries)
	printSummaries(entries)
}

func provenanceFor(name string) string {
	switch name {
	case "generatedResources":
		return "Generated"
	case "handwrittenResources":
		return "Handwritten"
	case "handwrittenIAMResources":
		return "HandwrittenIAM"
	default:
		return ""
	}
}

func extractResourceName(expr ast.Expr) string {
	basic, ok := expr.(*ast.BasicLit)
	if !ok || basic.Kind != token.STRING {
		return ""
	}
	resource, err := strconv.Unquote(basic.Value)
	if err != nil {
		return ""
	}
	return resource
}

func exprToString(fset *token.FileSet, expr ast.Expr) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, expr); err != nil {
		return ""
	}
	return buf.String()
}

func inferProduct(call *ast.CallExpr, mapName string) (string, bool) {
	isIAM := mapName == "handwrittenIAMResources"
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "tpgiamresource" {
			isIAM = true
			if len(call.Args) > 0 {
				if product := packageFromExpr(call.Args[0]); product != "" {
					return product, isIAM
				}
			}
			return "unknown", isIAM
		}
		if ident, ok := sel.X.(*ast.Ident); ok {
			return ident.Name, isIAM
		}
		if product := packageFromExpr(sel.X); product != "" {
			return product, isIAM
		}
	}

	if isIAM && len(call.Args) > 0 {
		if product := packageFromExpr(call.Args[0]); product != "" {
			return product, isIAM
		}
	}

	return "unknown", isIAM
}

func packageFromExpr(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.SelectorExpr:
		return leftMostIdent(v.X)
	case *ast.Ident:
		return v.Name
	case *ast.UnaryExpr:
		return packageFromExpr(v.X)
	case *ast.CallExpr:
		return packageFromExpr(v.Fun)
	case *ast.CompositeLit:
		return packageFromExpr(v.Type)
	default:
		return ""
	}
}

func leftMostIdent(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return leftMostIdent(v.X)
	default:
		return ""
	}
}

func formatFileLine(path string, line int) string {
	return fmt.Sprintf("%s:%d", filepath.ToSlash(path), line)
}

func writeCSV(entries []entry) {
	f, err := os.Create("resource_registry.csv")
	if err != nil {
		log.Fatalf("create resource_registry.csv: %v", err)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	if err := writer.Write([]string{"resource", "provenance", "product", "is_iam", "schema_callee", "file_path:line"}); err != nil {
		log.Fatalf("write header: %v", err)
	}

	for _, e := range entries {
		record := []string{
			e.Resource,
			e.Provenance,
			e.Product,
			strconv.FormatBool(e.IsIAM),
			e.SchemaCallee,
			e.FileLine,
		}
		if err := writer.Write(record); err != nil {
			log.Fatalf("write record for %s: %v", e.Resource, err)
		}
	}
}

func printSummaries(entries []entry) {
	provCounts := make(map[string]int)
	productCounts := make(map[string]int)

	for _, e := range entries {
		provCounts[e.Provenance]++
		productCounts[e.Product]++
	}

	fmt.Println("Provenance counts:")
	for _, prov := range sortedKeys(provCounts) {
		fmt.Printf("  %s: %d\n", prov, provCounts[prov])
	}

	type kv struct {
		Key   string
		Count int
	}
	var products []kv
	for k, v := range productCounts {
		products = append(products, kv{k, v})
	}
	sort.Slice(products, func(i, j int) bool {
		if products[i].Count == products[j].Count {
			return products[i].Key < products[j].Key
		}
		return products[i].Count > products[j].Count
	})

	fmt.Println("\nTop products:")
	limit := 10
	if len(products) < limit {
		limit = len(products)
	}
	for i := 0; i < limit; i++ {
		fmt.Printf("  %s: %d\n", products[i].Key, products[i].Count)
	}
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
