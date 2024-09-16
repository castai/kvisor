package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"reflect"
	"strconv"
)

var (
	uint16Type  = uint16FieldType{}
	uint32Type  = uint32FieldType{}
	uint64Type  = uint64FieldType{}
	int32Type   = int32FieldType{}
	int64Type   = int64FieldType{}
	int8Type    = int8FieldType{}
	eventIDType = eventIDFieldType{}
)

type fieldType interface {
	sizeInBytes() uint64
	String() string
}

type eventIDFieldType struct{}

func (eventIDFieldType) String() string {
	return "events.ID"
}

func (eventIDFieldType) sizeInBytes() uint64 {
	return 4
}

type uint16FieldType struct{}

func (uint16FieldType) String() string {
	return "uint16"
}

func (uint16FieldType) sizeInBytes() uint64 {
	return 2
}

type uint32FieldType struct{}

func (uint32FieldType) String() string {
	return "uint32"
}

func (uint32FieldType) sizeInBytes() uint64 {
	return 4
}

type uint64FieldType struct{}

func (u uint64FieldType) String() string {
	return "uint64"
}

func (uint64FieldType) sizeInBytes() uint64 {
	return 8
}

type int32FieldType struct{}

func (i int32FieldType) String() string {
	return "int32"
}

func (int32FieldType) sizeInBytes() uint64 {
	return 4
}

type int64FieldType struct{}

func (i int64FieldType) String() string {
	return "int64"
}

func (int64FieldType) sizeInBytes() uint64 {
	return 8
}

type int8FieldType struct{}

func (i int8FieldType) String() string {
	return "int8"
}

func (int8FieldType) sizeInBytes() uint64 {
	return 1
}

type arrayFieldType struct {
	size        uint64
	elementType fieldType
}

func (a arrayFieldType) String() string {
	return fmt.Sprintf("[%d]%s", a.size, a.elementType.String())
}

func (a arrayFieldType) sizeInBytes() uint64 {
	return a.size * a.elementType.sizeInBytes()
}

func extractArrayLen(a *ast.ArrayType) (uint64, error) {
	lit, ok := a.Len.(*ast.BasicLit)
	if !ok {
		return 0, fmt.Errorf("unsupported array len type: %s", reflect.TypeOf(a.Len).String())
	}

	if lit.Kind != token.INT {
		return 0, fmt.Errorf("unsupported array len token: %s", lit.Kind.String())
	}

	return strconv.ParseUint(lit.Value, 10, 64)
}

func parseSimpleFieldType(n string) (fieldType, bool, error) {
	switch n {
	case "int32":
		return int32Type, true, nil
	case "int64":
		return int64Type, true, nil
	case "uint16":
		return uint16Type, true, nil
	case "uint32":
		return uint32Type, true, nil
	case "uint64":
		return uint64Type, true, nil
	case "int8", "byte":
    // Byte and Int8 are the same and are always represented as int8.
		return int8Type, true, nil
	}

	return nil, false, fmt.Errorf("unsupported field type: %s", n)
}
