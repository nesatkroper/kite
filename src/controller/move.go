package controller

import (
	"encoding/json"
	"fmt"
	"kite/src/types"
	"kite/src/helper"
	"os"
	"path/filepath"
)

func MoveRecord(collectionName, id, schemaName string) error {
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

	found := false
	newRecords := []types.Record{}
	for _, record := range records {
		if record["_id"] != id {
			newRecords = append(newRecords, record)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("record with _id %s not found", id)
	}

	dataToEncrypt, err := json.Marshal(newRecords)
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

	fmt.Printf("Removed record %s from collection %s\n", id, collectionName)
	return nil
}