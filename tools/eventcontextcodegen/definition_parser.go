package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
)

type contextField struct {
	name      string
	fieldType fieldType
}

type eventContextDefinition struct {
	fields []contextField
}

func (e eventContextDefinition) totalSize() uint64 {
	var result uint64

	for _, f := range e.fields {
		result += f.fieldType.sizeInBytes()
	}

	return result
}

type structDefinition struct {
	name       string
	definition *ast.StructType
}

type definitionCollector struct {
	definitions       map[string]structDefinition
	parsedDefinitions map[string]eventContextDefinition
	inProgressParsing []string
}

func (d *definitionCollector) getParsedContext(name string) (eventContextDefinition, error) {
	if parsed, found := d.parsedDefinitions[name]; found {
		return parsed, nil
	}

	if slices.Contains(d.inProgressParsing, name) {
		return eventContextDefinition{}, fmt.Errorf("cyclic dependency detected! (path: [%s], current: %s)", strings.Join(d.inProgressParsing, ","), name)
	}

	// NOTE(patrick.pichler): Since go doesn't allow for circular struct dependencies, instead of recursion, we could
	// simply order the definitions by dependencies. As of right now, the recursive solutions is good enough though.
	d.inProgressParsing = append(d.inProgressParsing, name)
	defer func() {
		d.inProgressParsing = d.inProgressParsing[0 : len(d.inProgressParsing)-1]
	}()

	if raw, found := d.definitions[name]; found {
		fields, err := d.parseGeneratedContextStructFields(nil, raw.definition)
		if err != nil {
			return eventContextDefinition{}, err
		}

		return eventContextDefinition{
			fields: fields,
		}, nil
	}

	return eventContextDefinition{}, fmt.Errorf("no definition found for %s", name)
}

func (d *definitionCollector) parseGeneratedContextStructFields(path []string, n *ast.StructType) ([]contextField, error) {
	var result []contextField

	for i, f := range n.Fields.List {
		switch field := f.Type.(type) {
		case *ast.StructType:
			if len(f.Names) != 1 {
				fmt.Printf("skipping field no %d, len names: %d, value: %v", i, len(f.Names), f.Names)
				continue
			}

			// Append is fine here, as we do not do anything in parallel.
			subFields, err := d.parseGeneratedContextStructFields(append(path, f.Names[0].Name), field)
			if err != nil {
				return nil, err
			}

			result = append(result, subFields...)

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

			contextField := contextField{
				fieldType: arrayFieldType{
					size:        arrLen,
					elementType: parsedElemType,
				},
			}

			if len(f.Names) == 1 {
				// Once again, append is fine here, as there is no concurrent processing going on.
				contextField.name = strings.Join(append(path, f.Names[0].Name), ".")
			}

			result = append(result, contextField)
		case *ast.Ident:
			parsed, found, err := parseSimpleFieldType(field.Name)
			if found && err != nil {
				return nil, err
			}

			contextField := contextField{
				fieldType: parsed,
			}

			if len(f.Names) == 1 {
				// Once again, append is fine here, as there is no concurrent processing going on.
				contextField.name = strings.Join(append(path, f.Names[0].Name), ".")
			}

			if !found {
				defintion, err := d.getParsedContext(field.Name)
				if err != nil {
					return nil, err
				}

				for _, cf := range defintion.fields {
					field := cf
					field.name = strings.Join(append(path, []string{contextField.name, cf.name}...), ".")
					result = append(result, field)
				}
				continue
			}

			result = append(result, contextField)
		}
	}

	return result, nil
}

func parseEventDefinitionSetForFile(filePath string, src string) (eventContextDefinition, error) {
	// Parse the Go source file
	fset := token.NewFileSet() // positions are relative to fset
	node, err := parser.ParseFile(fset, filePath, src, parser.ParseComments)
	if err != nil {
		return eventContextDefinition{}, fmt.Errorf("cannot parse file: %w", err)
	}

	definitionCollector := definitionCollector{
		definitions:       map[string]structDefinition{},
		parsedDefinitions: map[string]eventContextDefinition{},
		inProgressParsing: []string{},
	}

	for _, decl := range node.Decls {
		name, d, ok := tryExtractDeclaration(decl)
		if !ok {
			continue
		}

		definitionCollector.definitions[name] = structDefinition{
			name:       name,
			definition: d,
		}
	}

	return definitionCollector.getParsedContext("tracerEventContextT")
}

func tryExtractDeclaration(n ast.Node) (string, *ast.StructType, bool) {
	if n, ok := n.(*ast.GenDecl); ok {
		if len(n.Specs) != 1 {
			return "", nil, false
		}

		t, ok := n.Specs[0].(*ast.TypeSpec)
		if !ok {
			return "", nil, false
		}

		if st, ok := t.Type.(*ast.StructType); ok {
			return t.Name.Name, st, true
		}
	}

	return "", nil, false
}
