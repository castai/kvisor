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

var (
	errNotFound                      = errors.New("not found")
	errNotAllKeysFound               = errors.New("not all required keys found")
	errWrongType                     = errors.New("wrong type")
	errParamsNotFound                = errors.New("params not found")
	errUnhandledType                 = errors.New("unhandled type")
	errEventTypeNotFromEventsPackage = errors.New("event type not from events package")
)

func parseEventDefinitionSetForFile(filePath string, src string) ([]eventDefinition, error) {
	// Parse the Go source file
	fset := token.NewFileSet() // positions are relative to fset
	node, err := parser.ParseFile(fset, filePath, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("cannot parse file: %w", err)
	}

	for _, decl := range node.Decls {
		if !isEventsDefinitionSetFunction(decl) {
			continue
		}

		if funcDecl, ok := decl.(*ast.FuncDecl); ok {
			result, err := parseEventDefinitionSetFunction(funcDecl)
			if err != nil {
				return nil, err
			}

			return result, nil
		} else {
			return nil, fmt.Errorf("found `newEventsDefinitionSet` function, but is not a FuncDecl")
		}
	}

	return nil, fmt.Errorf("no event definitions found in given file")
}

func isEventsDefinitionSetFunction(n ast.Node) bool {
	if f, ok := n.(*ast.FuncDecl); !ok || f.Name.Name != "newEventsDefinitionSet" {
		return false
	}

	return true
}

func parseEventDefinitionSetFunction(fNode *ast.FuncDecl) ([]eventDefinition, error) {
	mapComposite, err := getEventDefinitionMapComposite(fNode)
	if err != nil {
		return nil, err
	}

	var result []eventDefinition

	// Print information about the map's key and value types
	for _, elt := range mapComposite.Elts {
		kvExpr, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return nil, fmt.Errorf("cannot extract event definition set: %w", errWrongType)
		}

		name, err := extractEventKeyName(kvExpr)
		if err != nil {
			return nil, fmt.Errorf("failed to extract key name: %w", err)
		}

		params, err := extractParams(kvExpr)
		if err != nil {
			return nil, fmt.Errorf("failed to extract params for %s: %w", name, err)
		}

		result = append(result, eventDefinition{
			event:  name,
			params: params,
		})
	}

	return result, nil
}

func extractParams(kvExpr *ast.KeyValueExpr) ([]param, error) {
	body, ok := kvExpr.Value.(*ast.CompositeLit)
	if !ok {
		return nil, errUnhandledType
	}

	for i, elt := range body.Elts {
		kvExpr, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return nil, errUnhandledType
		}

		name, err := extractKeyName(kvExpr)
		if err != nil {
			return nil, fmt.Errorf("failed to extract param key name (index %d): %w", i, err)
		}

		// We only care about the Params value.
		if name != "params" {
			continue
		}

		paramsMap, ok := kvExpr.Value.(*ast.CompositeLit)
		if !ok {
			return nil, fmt.Errorf("failed to extract params map: %w", errUnhandledType)
		}

		return transformParams(paramsMap)
	}

	// If we do not find a `params` key, this means there are no params for that event.
	return nil, nil
}

func transformParams(n *ast.CompositeLit) ([]param, error) {
	var result []param

	for _, elt := range n.Elts {
		definitions, ok := elt.(*ast.CompositeLit)
		if !ok {
			return nil, fmt.Errorf("failed to extract params: %w", errUnhandledType)
		}

		var paramName, paramType string

		for _, e := range definitions.Elts {
			kvExpr, ok := e.(*ast.KeyValueExpr)
			if !ok {
				return nil, fmt.Errorf("failed to extract params: %w", errUnhandledType)
			}

			paramKeyName, err := extractKeyName(kvExpr)
			if err != nil {
				return nil, fmt.Errorf("failed to extract param key name: %w", err)
			}

			paramKeyValue, err := extractStringValue(kvExpr)
			if err != nil {
				return nil, fmt.Errorf("failed to extract param value: %w", err)
			}

			switch paramKeyName {
			case "Name":
				paramName = paramKeyValue

			case "Type":
				paramType = paramKeyValue

			}
		}

		if paramName == "" || paramType == "" {
			return nil, errNotAllKeysFound
		}

		result = append(result, param{
			name:      paramName,
			paramType: getParamType(paramType),
		})
	}

	return result, nil
}

func extractStringValue(kvExpr *ast.KeyValueExpr) (string, error) {
	switch k := kvExpr.Value.(type) {
	case *ast.BasicLit:
		// We need to trim the `"` from the value, as we get the raw literal (as in `"hello"`)
		return strings.TrimPrefix(strings.TrimSuffix(k.Value, "\""), "\""), nil
	}

	return "", errUnhandledType
}

func extractEventKeyName(kvExpr *ast.KeyValueExpr) (string, error) {
	switch k := kvExpr.Key.(type) {
	case *ast.SelectorExpr:
		if ident, ok := k.X.(*ast.Ident); ok {
			if ident.Name != "events" {
				return "", errEventTypeNotFromEventsPackage
			}

			return k.Sel.Name, nil
		}
	}

	tokenType := reflect.TypeOf(kvExpr.Key).String()

	return "", fmt.Errorf("cannot parse key name of node type `%s`: %w", tokenType, errUnhandledType)
}

func extractKeyName(kvExpr *ast.KeyValueExpr) (string, error) {
	switch k := kvExpr.Key.(type) {
	case *ast.Ident:
		return k.Name, nil
	}

	tokenType := reflect.TypeOf(kvExpr.Key).String()

	return "", fmt.Errorf("cannot parse key name of node type `%s`: %w", tokenType, errUnhandledType)
}

func getEventDefinitionMapComposite(f *ast.FuncDecl) (*ast.CompositeLit, error) {
	var result *ast.CompositeLit

	ast.Inspect(f.Body, func(n ast.Node) bool {
		if composite, ok := n.(*ast.CompositeLit); ok {
			result = composite
			return false
		}
		return true
	})

	if result == nil {
		return nil, errNotFound
	}

	return result, nil
}

func getParamType(paramType string) ArgType {
	switch paramType {
	case "int", "pid_t", "uid_t", "gid_t", "mqd_t", "clockid_t", "const clockid_t", "key_t", "key_serial_t", "timer_t":
		return intT
	case "unsigned int", "u32":
		return uintT
	case "long":
		return longT
	case "unsigned long", "u64":
		return ulongT
	case "bool":
		return boolT
	case "off_t", "loff_t":
		return offT
	case "mode_t":
		return modeT
	case "dev_t":
		return devT
	case "size_t":
		return sizeT
	case "void*", "const void*":
		return pointerT
	case "char*", "const char*":
		return strT
	case "const char*const*": // used by execve(at) argv and env
		return strArrT
	case "const char**": // used by sched_process_exec argv and envp
		return argsArrT
	case "const struct sockaddr*", "struct sockaddr*":
		return sockAddrT
	case "bytes":
		return bytesT
	case "int[2]":
		return intArr2T
	case "slim_cred_t":
		return credT
	case "umode_t":
		return u16T
	case "u8":
		return u8T
	case "u16":
		return u16T
	case "unsigned long[]", "[]HookedSymbolData":
		return uint64ArrT
	case "struct timespec*", "const struct timespec*":
		return timespecT
	case "tuple":
		return tupleT
	case "proto.DNS":
		return protoDNST
	case "proto.SSH":
		return protoSSHT
	default:
		// Default to pointer (printed as hex) for unsupported types
		return pointerT
	}
}
