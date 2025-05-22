package controller

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"kite/src/helper"
	"kite/src/types"

	"github.com/google/uuid"
)

func AddCollection(collectionName, schemaName, jsonData string) error {
	dir := filepath.Join("..", "db")
	if schemaName != "" {
		dir = filepath.Join("..", "db", schemaName)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("failed to set permissions on %s: %v", dir, err)
	}

	collectionPath := filepath.Join(dir, collectionName+".txt")
	if _, err := os.Stat(collectionPath); err == nil {
		return fmt.Errorf("collection %s already exists in %s", collectionName, dir)
	}

	key, err := helper.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	var dataToEncrypt []byte
	if jsonData == "" {
		dataToEncrypt = []byte("[]")
	} else {
		cleanedJSON := strings.Trim(jsonData, "'\"")
		var inputData map[string]interface{}
		if err := json.Unmarshal([]byte(cleanedJSON), &inputData); err != nil {
			return fmt.Errorf("failed to parse JSON data: %v", err)
		}

		now := time.Now().UTC().Format(time.RFC3339)
		record := types.Record{
			"_id":       uuid.New().String(),
			"createdAt": now,
			"updatedAt": now,
			"_version":  float64(0),
		}
		for k, v := range inputData {
			if k != "_id" && k != "createdAt" && k != "updatedAt" && k != "_version" {
				record[k] = v
			}
		}

		dataArray := []types.Record{record}
		dataToEncrypt, err = json.Marshal(dataArray)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON data: %v", err)
		}
	}

	encrypted, err := helper.Encrypt(dataToEncrypt, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	if err := os.WriteFile(collectionPath, []byte(encrypted), 0600); err != nil {
		return fmt.Errorf("failed to write collection file: %v", err)
	}

	keyPath := filepath.Join(dir, collectionName+".key")
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %v", err)
	}

	fmt.Printf("Created collection %s at %s\n", collectionName, collectionPath)
	return nil
}