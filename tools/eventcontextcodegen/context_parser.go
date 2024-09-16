package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
)

type targetContextField struct {
	fieldType fieldType
	name      string
	source    string
}

type targetContextDefinition struct {
	fields []targetContextField
}

func parseEventContextFile(filePath string, src string) (targetContextDefinition, error) {
	// Parse the Go source file
	fset := token.NewFileSet() // positions are relative to fset
	node, err := parser.ParseFile(fset, filePath, src, parser.ParseComments)
	if err != nil {
		return targetContextDefinition{}, fmt.Errorf("cannot parse file: %w", err)
	}
	for _, decl := range node.Decls {
		structType, ok := isDefinition(decl, "EventContext")
		if !ok {
			continue
		}

		return parseTargetEventContextDefinition(structType)
	}

	return targetContextDefinition{}, errors.New("could not find target event context definition!")
}

func parseTargetEventContextDefinition(n *ast.StructType) (targetContextDefinition, error) {
	if n.Fields.NumFields() == 0 {
		return targetContextDefinition{}, nil
	}

	fields, err := parseTargetContextStructFields(nil, n)
	if err != nil {
		return targetContextDefinition{}, err
	}

	return targetContextDefinition{
		fields: fields,
	}, nil
}

func parseTargetContextStructFields(path []string, n *ast.StructType) ([]targetContextField, error) {
	var result []targetContextField

	for i, f := range n.Fields.List {
		switch field := f.Type.(type) {
		case *ast.StructType:
			fmt.Printf("unsupported struct type for field no %d in target\n", i)
			continue

		case *ast.ArrayType:
			elemType, ok := field.Elt.(*ast.Ident)
			if !ok {
				return nil, fmt.Errorf("unsupported array element type: %T", elemType)
			}

			parsedElemType, _, err := parseSimpleFieldType(elemType.Name)
			if err != nil {
				return nil, err
			}

			arrLen, err := extractArrayLen(field)
			if err != nil {
				return nil, err
			}

			contextField := targetContextField{
				fieldType: arrayFieldType{
					size:        arrLen,
					elementType: parsedElemType,
				},
			}

			if len(f.Names) != 1 || f.Names[0].Name == "_" {
				continue
			}
			contextField.name = strings.Join(append(path, f.Names[0].Name), ".")

			var tagVal string

			if f.Tag != nil {
				tag := reflect.StructTag(f.Tag.Value[1 : len(f.Tag.Value)-1])
				tagVal = tag.Get("sourceField")
			}
			if tagVal == "" {
				contextField.source = contextField.name
			} else {
				contextField.source = tagVal
			}

			result = append(result, contextField)

		case *ast.Ident, *ast.SelectorExpr:
			var fieldName string

			switch t := field.(type) {
			case *ast.Ident:
				fieldName = t.Name
			case *ast.SelectorExpr:
				expr, ok := t.X.(*ast.Ident)
				if !ok {
					return nil, fmt.Errorf("unsupported selector type: %T", t.X)
				}

				fieldName = fmt.Sprintf("%s.%s", expr.Name, t.Sel.Name)
			}

			parsed, _, err := parseDefinitionFieldType(fieldName)
			if err != nil {
				return nil, err
			}

			contextField := targetContextField{
				fieldType: parsed,
			}

			if len(f.Names) != 1 || f.Names[0].Name == "_" {
				continue
			}
			contextField.name = strings.Join(append(path, f.Names[0].Name), ".")

			var tagVal string

			if f.Tag != nil {
				tag := reflect.StructTag(f.Tag.Value[1 : len(f.Tag.Value)-1])
				tagVal = tag.Get("sourceField")
			}
			if tagVal == "" {
				contextField.source = contextField.name
			} else {
				contextField.source = tagVal
			}

			result = append(result, contextField)
		}
	}

	return result, nil
}

func parseDefinitionFieldType(name string) (fieldType, bool, error) {
	switch name {
	case "events.ID":
		return eventIDType, true, nil
	}

	return parseSimpleFieldType(name)
}

func isDefinition(n ast.Node, name string) (*ast.StructType, bool) {
	if n, ok := n.(*ast.GenDecl); ok {
		if len(n.Specs) != 1 {
			return nil, false
		}

		t, ok := n.Specs[0].(*ast.TypeSpec)
		if !ok {
			return nil, false
		}

		if t.Name.Name == name {
			if st, ok := t.Type.(*ast.StructType); ok {
				return st, true
			}
		}
	}

	return nil, false
}
