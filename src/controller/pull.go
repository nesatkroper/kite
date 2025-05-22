package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"kite/src/helper"
)

func PullCollection(collectionName, schemaName string) error {
	dir := filepath.Join("..", "db")
	if schemaName != "" {
		dir = filepath.Join("..", "db", schemaName)
	}

	collectionPath := filepath.Join(dir, collectionName+".txt")
	keyPath := filepath.Join(dir, collectionName+".key")

	encryptedData, err := os.ReadFile(collectionPath)
	if err != nil {
		return fmt.Errorf("failed to read collection file: %v", err)
	}

	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %v", err)
	}

	decrypted, err := helper.Decrypt(string(encryptedData), key)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %v", err)
	}

	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, decrypted, "", "  "); err != nil {
		return fmt.Errorf("failed to format JSON: %v", err)
	}

	fmt.Printf("Collection %s contents:\n%s\n", collectionName, prettyJSON.String())
	return nil
}