package secretboundary_test

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

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretboundary"
	"gopkg.in/yaml.v3"
)

func TestSecretTagCoverage(t *testing.T) {
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
				if secretboundary.SensitiveName(name) {
					switch tag.Get("secret") {
					case "value", "sensitive-header-values", "url-userinfo", "public", "walk", "plugin-config":
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

func TestConfigSecretTagCoverage(t *testing.T) {
	var walk func(reflect.Type, string)
	seen := map[reflect.Type]bool{}
	walk = func(typ reflect.Type, path string) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array || typ.Kind() == reflect.Map {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		for field := range typ.Fields() {
			if !field.IsExported() {
				continue
			}
			name := path + "." + field.Name
			ft := field.Type
			for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice || ft.Kind() == reflect.Array {
				ft = ft.Elem()
			}
			tag := field.Tag.Get("secret")
			dynamic := ft == reflect.TypeFor[yaml.Node]()
			if ft.Kind() == reflect.Map {
				elem := ft.Elem()
				for elem.Kind() == reflect.Pointer || elem.Kind() == reflect.Slice || elem.Kind() == reflect.Array {
					elem = elem.Elem()
				}
				dynamic = elem.Kind() == reflect.Struct || elem.Kind() == reflect.Interface || elem.Kind() == reflect.Map
			}
			if dynamic && tag == "" {
				t.Errorf("%s needs a secret tag for dynamic config", name)
			}
			if ft.Kind() == reflect.String || ft == reflect.TypeFor[map[string]string]() {
				for _, encoding := range []string{"yaml", "json"} {
					fieldName, _, _ := strings.Cut(field.Tag.Get(encoding), ",")
					if fieldName == "" {
						fieldName = field.Name
					}
					if secretboundary.SensitiveName(fieldName) && tag == "" {
						t.Errorf("%s needs a secret tag for %s name", name, encoding)
						break
					}
				}
			}
			if tag != "public" && ft != reflect.TypeFor[yaml.Node]() {
				walk(ft, name)
			}
		}
	}
	walk(reflect.TypeFor[config.Config](), "Config")
}
