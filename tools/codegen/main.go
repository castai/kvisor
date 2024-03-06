package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Println("Unexpected number of arguments:", len(os.Args)-1)
		fmt.Println("Usage: <input file> <types target file> <generator target file> <generator package>")
		os.Exit(1)
	}

	inputFile := os.Args[1]
	typesTargetFile := os.Args[2]
	generatorTargetFile := os.Args[3]
	targetPackage := os.Args[4]

	absTypesTargetFile, err := filepath.Abs(typesTargetFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	absGeneratorTargetFile, err := filepath.Abs(generatorTargetFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("writing generators to", absGeneratorTargetFile)
	fmt.Println("writing types to", absTypesTargetFile)

	err = run(inputFile, typesTargetFile, generatorTargetFile, targetPackage)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(inputFile string, typesTargetFile string, generatorTargetFile string, targetPackage string) error {
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	events, err := parseEventDefinitionSetForFile(inputFile, string(data))
	if err != nil {
		return err
	}

	typesCode, err := generateTypes(events)
	if err != nil {
		return err
	}

	generatorCode, err := generateParsers(targetPackage, events)
	if err != nil {
		return err
	}

	err = os.WriteFile(typesTargetFile, []byte(typesCode), 0644)
	if err != nil {
		return err
	}

	err = os.WriteFile(generatorTargetFile, []byte(generatorCode), 0644)
	if err != nil {
		return err
	}

	return nil
}
