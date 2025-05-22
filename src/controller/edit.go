package controller

import (
	"encoding/json"
	"fmt"
	"kite/src/types"
	"kite/src/helper"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func EditCollection(collectionName, id, jsonData, schemaName string) error {
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

	var records []types.Record
	if err := json.Unmarshal(decrypted, &records); err != nil {
		return fmt.Errorf("failed to parse collection JSON: %v", err)
	}

	// Trim single quotes for Windows compatibility
	cleanedJSON := strings.Trim(jsonData, "'\"")
	var inputData map[string]interface{}
	if err := json.Unmarshal([]byte(cleanedJSON), &inputData); err != nil {
		return fmt.Errorf("failed to parse JSON data: %v", err)
	}

	found := false
	now := time.Now().UTC().Format(time.RFC3339)
	for i, record := range records {
		if record["_id"] == id {
			newRecord := types.Record{
				"_id":       id,
				"createdAt": record["createdAt"],
				"updatedAt": now,
				"_version":  record["_version"].(float64) + 1,
			}
			for k, v := range inputData {
				if k != "_id" && k != "createdAt" && k != "updatedAt" && k != "_version" {
					newRecord[k] = v
				}
			}
			records[i] = newRecord
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("record with _id %s not found", id)
	}

	dataToEncrypt, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON data: %v", err)
	}

	encrypted, err := helper.Encrypt(dataToEncrypt, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	if err := os.WriteFile(collectionPath, []byte(encrypted), 0600); err != nil {
		return fmt.Errorf("failed to write collection file: %v", err)
	}

	fmt.Printf("Updated record %s in collection %s\n", id, collectionName)
	return nil
}