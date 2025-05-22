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


func InsertRecord(collectionName, jsonData, schemaName string) error {
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
	keyPath := filepath.Join(dir, collectionName+".key")

	if _, err := os.Stat(collectionPath); os.IsNotExist(err) {
		return AddCollection(collectionName, schemaName, jsonData)
	}

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

	now := time.Now().UTC().Format(time.RFC3339)
	newRecord := types.Record{
		"_id":       uuid.New().String(),
		"createdAt": now,
		"updatedAt": now,
		"_version":  float64(0),
	}
	for k, v := range inputData {
		if k != "_id" && k != "createdAt" && k != "updatedAt" && k != "_version" {
			newRecord[k] = v
		}
	}

	records = append(records, newRecord)
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

	fmt.Printf("Inserted record into collection %s\n", collectionName)
	return nil
}