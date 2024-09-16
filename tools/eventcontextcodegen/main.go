package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 4 && len(os.Args) != 5 {
		fmt.Println("Unexpected number of arguments:", len(os.Args)-1)
		fmt.Println("Usage: <file containing generated context> <file containing target context> <target file> [<arch>]")
		os.Exit(1)
	}

	generatedInputFile := os.Args[1]
	targetContextInputFile := os.Args[2]
	targetFile := os.Args[3]
	var arch string

	if len(os.Args) == 5 {
		arch = os.Args[4]
	}

	absGenInputFile, err := filepath.Abs(generatedInputFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	absContextInputFile, err := filepath.Abs(targetContextInputFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	absParserTargetFile, err := filepath.Abs(targetFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("reading %s + %s and writing parser to %s\n", absGenInputFile, absContextInputFile, absParserTargetFile)
	err = run(generatedInputFile, absContextInputFile, targetFile, arch)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
func run(inputFile string, contextInputFile string, targetFile string, arch string) error {
	generatedInputData, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	definition, err := parseEventDefinitionSetForFile(inputFile, string(generatedInputData))
	if err != nil {
		return err
	}

	contextInputData, err := os.ReadFile(contextInputFile)
	if err != nil {
		return err
	}

	target, err := parseEventContextFile(contextInputFile, string(contextInputData))
	if err != nil {
		return err
	}

	return generateParserCode(definition, target, targetFile, arch)
}
