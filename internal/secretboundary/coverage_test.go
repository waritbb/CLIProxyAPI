package secretboundary

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/MoeForge/moego/regexp"
)

func TestSecretTagCoverage(t *testing.T) {
	names := regexp.MustCompile("(?i)(key|token|secret|password|credential|cookie)$")
	files := token.NewFileSet()
	err := filepath.WalkDir("../..", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "vendor") {
			return fs.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(files, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			field, ok := node.(*ast.Field)
			if !ok || field.Tag == nil || !secretFieldType(field.Type) {
				return true
			}
			raw, _ := strconv.Unquote(field.Tag.Value)
			tag := reflect.StructTag(raw)
			for _, encoding := range []string{"yaml", "json"} {
				name, _, _ := strings.Cut(tag.Get(encoding), ",")
				if names.MatchString(name) {
					switch tag.Get("secret") {
					case "value", "sensitive-header-values", "url-userinfo", "public":
					default:
						t.Errorf("%s: %s needs a secret tag", files.Position(field.Pos()), name)
					}
					break
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func secretFieldType(expr ast.Expr) bool {
	switch typ := expr.(type) {
	case *ast.Ident:
		return typ.Name == "string"
	case *ast.ArrayType:
		elem, ok := typ.Elt.(*ast.Ident)
		return typ.Len == nil && ok && elem.Name == "string"
	case *ast.MapType:
		key, keyOK := typ.Key.(*ast.Ident)
		value, valueOK := typ.Value.(*ast.Ident)
		return keyOK && valueOK && key.Name == "string" && value.Name == "string"
	case *ast.StarExpr:
		return secretFieldType(typ.X)
	default:
		return false
	}
}
