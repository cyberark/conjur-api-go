package main

import (
	"fmt"
	"os"
	"github.com/conjurinc/api-go"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("A variable name must be given as the first and only argument!")
		os.Exit(-1)
	}

	variableName := os.Args[1]

	config := conjurapi.Config{
		Account:      os.Getenv("CONJUR_ACCOUNT"),
		APIKey:       os.Getenv("CONJUR_API_KEY"),
		ApplianceUrl: os.Getenv("CONJUR_APPLIANCE_URL"),
		Username:     os.Getenv("CONJUR_LOGIN"),
	}
	conjur := conjurapi.NewClient(config)

	variableValue, err := conjur.RetrieveVariable(variableName)
	if err != nil {
		printAndExit(err)
	}

	fmt.Printf("Operating as %s.\n", config.Username)
	fmt.Printf("Retrieved the following:"+
		"\n\n"+
		"%s = %s\n", variableName, variableValue)
}

func printAndExit(err error) {
	os.Stderr.Write([]byte(err.Error()))
	os.Exit(1)
}
