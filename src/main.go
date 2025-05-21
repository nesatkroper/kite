package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// DBConfig holds connection details
type DBConfig struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Host       string `json:"host"`
	Port       string `json:"port"`
	SchemaName string `json:"schema_name"`
}

// Record represents the JSON structure
type Record map[string]interface{}

// loadConfig reads config.json or creates default
func loadConfig() (DBConfig, error) {
	configPath := filepath.Join("..", "config.json")
	defaultConfig := DBConfig{
		Username:   "kite",
		Password:   "kite",
		Host:       "localhost",
		Port:       "4141",
		SchemaName: "public",
	}

	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		data, err := json.MarshalIndent(defaultConfig, "", "  ")
		if err != nil {
			return DBConfig{}, fmt.Errorf("failed to marshal default config: %v", err)
		}
		if err := os.WriteFile(configPath, data, 0600); err != nil {
			return DBConfig{}, fmt.Errorf("failed to write default config: %v", err)
		}
		return defaultConfig, nil
	}
	if err != nil {
		return DBConfig{}, fmt.Errorf("failed to read config: %v", err)
	}

	var config DBConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return DBConfig{}, fmt.Errorf("failed to parse config: %v", err)
	}
	return config, nil
}

// generateKey creates a 32-byte key for AES-256
func generateKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// encrypt encrypts data using AES-GCM
func encrypt(data, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts base64-encoded ciphertext
func decrypt(encryptedData string, key []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// validateConnection checks DBConfig credentials
func validateConnection(config DBConfig) error {
	if config.Username == "" || config.Password == "" {
		return fmt.Errorf("username and password are required")
	}
	if config.Host == "" {
		return fmt.Errorf("host is required")
	}
	if config.Port == "" {
		return fmt.Errorf("port is required")
	}
	if config.SchemaName == "" {
		return fmt.Errorf("schema_name is required")
	}
	return nil
}

// ensureSchema creates schema directory
func ensureSchema(schemaName string) error {
	dir := filepath.Join("..", "db", schemaName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create schema directory %s: %v", dir, err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("failed to set permissions on %s: %v", dir, err)
	}
	return nil
}

// addCollection creates a collection
func addCollection(collectionName, schemaName, jsonData string) error {
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

	key, err := generateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	var dataToEncrypt []byte
	if jsonData == "" {
		dataToEncrypt = []byte("[]")
	} else {
		// Trim single quotes for Windows compatibility
		cleanedJSON := strings.Trim(jsonData, "'\"")
		var inputData map[string]interface{}
		if err := json.Unmarshal([]byte(cleanedJSON), &inputData); err != nil {
			return fmt.Errorf("failed to parse JSON data: %v", err)
		}

		now := time.Now().UTC().Format(time.RFC3339)
		record := Record{
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

		dataArray := []Record{record}
		dataToEncrypt, err = json.Marshal(dataArray)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON data: %v", err)
		}
	}

	encrypted, err := encrypt(dataToEncrypt, key)
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

// insertRecord adds a record
func insertRecord(collectionName, jsonData, schemaName string) error {
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
		return addCollection(collectionName, schemaName, jsonData)
	}

	encryptedData, err := os.ReadFile(collectionPath)
	if err != nil {
		return fmt.Errorf("failed to read collection file: %v", err)
	}

	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %v", err)
	}

	decrypted, err := decrypt(string(encryptedData), key)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %v", err)
	}

	var records []Record
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
	newRecord := Record{
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

	encrypted, err := encrypt(dataToEncrypt, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	if err := os.WriteFile(collectionPath, []byte(encrypted), 0600); err != nil {
		return fmt.Errorf("failed to write collection file: %v", err)
	}

	fmt.Printf("Inserted record into collection %s\n", collectionName)
	return nil
}

// readCollection reads for CLI
func readCollection(collectionName, schemaName string) error {
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

	decrypted, err := decrypt(string(encryptedData), key)
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

// readCollectionAPI reads for API and web
func readCollectionAPI(collectionName, schemaName string) ([]Record, error) {
	dir := filepath.Join("..", "db")
	if schemaName != "" {
		dir = filepath.Join("..", "db", schemaName)
	}

	collectionPath := filepath.Join(dir, collectionName+".txt")
	keyPath := filepath.Join(dir, collectionName+".key")

	encryptedData, err := os.ReadFile(collectionPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read collection file: %v", err)
	}

	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	decrypted, err := decrypt(string(encryptedData), key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	var records []Record
	if err := json.Unmarshal(decrypted, &records); err != nil {
		return nil, fmt.Errorf("failed to parse collection JSON: %v", err)
	}

	return records, nil
}

// editCollection updates a record
func editCollection(collectionName, id, jsonData, schemaName string) error {
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

	decrypted, err := decrypt(string(encryptedData), key)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %v", err)
	}

	var records []Record
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
			newRecord := Record{
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

	encrypted, err := encrypt(dataToEncrypt, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	if err := os.WriteFile(collectionPath, []byte(encrypted), 0600); err != nil {
		return fmt.Errorf("failed to write collection file: %v", err)
	}

	fmt.Printf("Updated record %s in collection %s\n", id, collectionName)
	return nil
}

// removeRecord removes a record
func removeRecord(collectionName, id, schemaName string) error {
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

	decrypted, err := decrypt(string(encryptedData), key)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %v", err)
	}

	var records []Record
	if err := json.Unmarshal(decrypted, &records); err != nil {
		return fmt.Errorf("failed to parse collection JSON: %v", err)
	}

	found := false
	newRecords := []Record{}
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

	encrypted, err := encrypt(dataToEncrypt, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	if err := os.WriteFile(collectionPath, []byte(encrypted), 0600); err != nil {
		return fmt.Errorf("failed to write collection file: %v", err)
	}

	fmt.Printf("Removed record %s from collection %s\n", id, collectionName)
	return nil
}

// dropCollection deletes a collection
func dropCollection(collectionName, schemaName string) error {
	dir := filepath.Join("..", "db")
	if schemaName != "" {
		dir = filepath.Join("..", "db", schemaName)
	}

	collectionPath := filepath.Join(dir, collectionName+".txt")
	keyPath := filepath.Join(dir, collectionName+".key")

	if _, err := os.Stat(collectionPath); os.IsNotExist(err) {
		return fmt.Errorf("collection %s does not exist in %s", collectionName, dir)
	}

	if err := os.Remove(collectionPath); err != nil {
		return fmt.Errorf("failed to delete collection file: %v", err)
	}

	if err := os.Remove(keyPath); err != nil {
		return fmt.Errorf("failed to delete key file: %v", err)
	}

	fmt.Printf("Dropped collection %s from %s\n", collectionName, dir)
	return nil
}

// listCollections returns collections in a schema
func listCollections(schemaName string) ([]string, error) {
	dir := filepath.Join("..", "db")
	if schemaName != "" {
		dir = filepath.Join("..", "db", schemaName)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read schema directory: %v", err)
	}

	var collections []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".txt" {
			collections = append(collections, entry.Name()[:len(entry.Name())-4])
		}
	}
	return collections, nil
}

// runServer starts the Gin server
func runServer() {
	config, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	r := gin.Default()

	// Serve static files
	r.Static("/static", "./static")

	// Load HTML templates
	templatesDir := filepath.Join(".", "templates")
	_, err = os.Stat(templatesDir)
	if os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: templates directory not found in %s\n", templatesDir)
		os.Exit(1)
	}
	tmpl := template.New("").Funcs(template.FuncMap{})
	tmpl, err = tmpl.ParseFiles(
		filepath.Join(templatesDir, "index.html"),
		filepath.Join(templatesDir, "collection.html"),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading templates: %v\n", err)
		os.Exit(1)
	}
	r.SetHTMLTemplate(tmpl)

	// API routes group
	api := r.Group("/v1")
	{
		// API: Connect
		api.POST("/connect", func(c *gin.Context) {
			var reqConfig DBConfig
			if err := c.ShouldBindJSON(&reqConfig); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
				return
			}

			if err := validateConnection(reqConfig); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			if err := ensureSchema(reqConfig.SchemaName); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Connected to schema %s", reqConfig.SchemaName)})
		})

		// API middleware for other routes
		api.Use(func(c *gin.Context) {
			var reqConfig DBConfig
			if err := c.ShouldBindJSON(&reqConfig); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connection details in body"})
				c.Abort()
				return
			}

			if err := validateConnection(reqConfig); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				c.Abort()
				return
			}

			if err := ensureSchema(reqConfig.SchemaName); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				c.Abort()
				return
			}

			c.Set("schema_name", reqConfig.SchemaName)
			c.Next()
		})

		// API: Create collection
		api.POST("/:schema_name/:collection_name/create", func(c *gin.Context) {
			schemaName := c.Param("schema_name")
			collectionName := c.Param("collection_name")
			var body struct {
				Data string `json:"data"`
			}
			if err := c.ShouldBindJSON(&body); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
				return
			}

			if err := addCollection(collectionName, schemaName, body.Data); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Collection %s created", collectionName)})
		})

		// API: Insert record
		api.POST("/:schema_name/:collection_name", func(c *gin.Context) {
			schemaName := c.Param("schema_name")
			collectionName := c.Param("collection_name")
			var body struct {
				Data string `json:"data"`
			}
			if err := c.ShouldBindJSON(&body); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
				return
			}

			if err := insertRecord(collectionName, body.Data, schemaName); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Record inserted"})
		})

		// API: Read collection
		api.GET("/:schema_name/:collection_name", func(c *gin.Context) {
			schemaName := c.Param("schema_name")
			collectionName := c.Param("collection_name")

			records, err := readCollectionAPI(collectionName, schemaName)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, records)
		})

		// API: Update record
		api.PUT("/:schema_name/:collection_name/:id", func(c *gin.Context) {
			schemaName := c.Param("schema_name")
			collectionName := c.Param("collection_name")
			id := c.Param("id")
			var body struct {
				Data string `json:"data"`
			}
			if err := c.ShouldBindJSON(&body); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
				return
			}

			if err := editCollection(collectionName, id, body.Data, schemaName); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Record %s updated", id)})
		})

		// API: Delete record
		api.DELETE("/:schema_name/:collection_name/:id", func(c *gin.Context) {
			schemaName := c.Param("schema_name")
			collectionName := c.Param("collection_name")
			id := c.Param("id")

			if err := removeRecord(collectionName, id, schemaName); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Record %s deleted", id)})
		})

		// API: Drop collection
		api.DELETE("/:schema_name/:collection_name", func(c *gin.Context) {
			schemaName := c.Param("schema_name")
			collectionName := c.Param("collection_name")

			if err := dropCollection(collectionName, schemaName); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Collection %s dropped", collectionName)})
		})
	}

	// Web: Home page (list collections)
	r.GET("/", func(c *gin.Context) {
		collections, err := listCollections(config.SchemaName)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "index.html", gin.H{
				"Error": err.Error(),
			})
			return
		}

		c.HTML(http.StatusOK, "index.html", gin.H{
			"SchemaName":  config.SchemaName,
			"Collections": collections,
		})
	})

	// Web: Collection page (view records)
	r.GET("/collections/:schema_name/:collection_name", func(c *gin.Context) {
		schemaName := c.Param("schema_name")
		collectionName := c.Param("collection_name")

		records, err := readCollectionAPI(collectionName, schemaName)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "collection.html", gin.H{
				"Error": err.Error(),
			})
			return
		}

		c.HTML(http.StatusOK, "collection.html", gin.H{
			"SchemaName":     schemaName,
			"CollectionName": collectionName,
			"Records":        records,
		})
	})

	// Web: Create collection
	r.POST("/web/create", func(c *gin.Context) {
		collectionName := c.PostForm("collection_name")
		data := c.PostForm("data")
		schemaName := config.SchemaName // Default to config schema

		if collectionName == "" {
			c.HTML(http.StatusBadRequest, "index.html", gin.H{
				"Error":      "Collection name is required",
				"SchemaName": schemaName,
			})
			return
		}

		if err := addCollection(collectionName, schemaName, data); err != nil {
			c.HTML(http.StatusBadRequest, "index.html", gin.H{
				"Error":      err.Error(),
				"SchemaName": schemaName,
			})
			return
		}

		collections, err := listCollections(schemaName)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "index.html", gin.H{
				"Error":      err.Error(),
				"SchemaName": schemaName,
			})
			return
		}

		c.HTML(http.StatusOK, "index.html", gin.H{
			"SchemaName":  schemaName,
			"Collections": collections,
			"Message":     fmt.Sprintf("Collection %s created", collectionName),
		})
	})

	// Web: Insert record
	r.POST("/web/insert", func(c *gin.Context) {
		collectionName := c.PostForm("collection_name")
		data := c.PostForm("data")
		schemaName := c.PostForm("schema_name")

		if collectionName == "" || data == "" || schemaName == "" {
			c.HTML(http.StatusBadRequest, "collection.html", gin.H{
				"Error":          "Collection name, schema name, and data are required",
				"SchemaName":     schemaName,
				"CollectionName": collectionName,
			})
			return
		}

		if err := insertRecord(collectionName, data, schemaName); err != nil {
			c.HTML(http.StatusBadRequest, "collection.html", gin.H{
				"Error":          err.Error(),
				"SchemaName":     schemaName,
				"CollectionName": collectionName,
			})
			return
		}

		records, err := readCollectionAPI(collectionName, schemaName)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "collection.html", gin.H{
				"Error":          err.Error(),
				"SchemaName":     schemaName,
				"CollectionName": collectionName,
			})
			return
		}

		c.HTML(http.StatusOK, "collection.html", gin.H{
			"SchemaName":     schemaName,
			"CollectionName": collectionName,
			"Records":        records,
			"Message":        "Record inserted",
		})
	})

	// Web: Edit record
	r.POST("/web/edit", func(c *gin.Context) {
		collectionName := c.PostForm("collection_name")
		schemaName := c.PostForm("schema_name")
		id := c.PostForm("id")
		data := c.PostForm("data")

		if collectionName == "" || schemaName == "" || id == "" || data == "" {
			c.HTML(http.StatusBadRequest, "collection.html", gin.H{
				"Error":          "Collection name, schema name, ID, and data are required",
				"SchemaName":     schemaName,
				"CollectionName": collectionName,
			})
			return
		}

		if err := editCollection(collectionName, id, data, schemaName); err != nil {
			c.HTML(http.StatusBadRequest, "collection.html", gin.H{
				"Error":          err.Error(),
				"SchemaName":     schemaName,
				"CollectionName": collectionName,
			})
			return
		}

		records, err := readCollectionAPI(collectionName, schemaName)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "collection.html", gin.H{
				"Error":          err.Error(),
				"SchemaName":     schemaName,
				"CollectionName": collectionName,
			})
			return
		}

		c.HTML(http.StatusOK, "collection.html", gin.H{
			"SchemaName":     schemaName,
			"CollectionName": collectionName,
			"Records":        records,
			"Message":        fmt.Sprintf("Record %s updated", id),
		})
	})

	// Web: Delete record
	r.POST("/web/delete", func(c *gin.Context) {
		collectionName := c.PostForm("collection_name")
		schemaName := c.PostForm("schema_name")
		id := c.PostForm("id")

		if collectionName == "" || schemaName == "" || id == "" {
			c.HTML(http.StatusBadRequest, "collection.html", gin.H{
				"Error":          "Collection name, schema name, and ID are required",
				"SchemaName":     schemaName,
				"CollectionName": collectionName,
			})
			return
		}

		if err := removeRecord(collectionName, id, schemaName); err != nil {
			c.HTML(http.StatusBadRequest, "collection.html", gin.H{
				"Error":          err.Error(),
				"SchemaName":     schemaName,
				"CollectionName": collectionName,
			})
			return
		}

		records, err := readCollectionAPI(collectionName, schemaName)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "collection.html", gin.H{
				"Error":          err.Error(),
				"SchemaName":     schemaName,
				"CollectionName": collectionName,
			})
			return
		}

		c.HTML(http.StatusOK, "collection.html", gin.H{
			"SchemaName":     schemaName,
			"CollectionName": collectionName,
			"Records":        records,
			"Message":        fmt.Sprintf("Record %s deleted", id),
		})
	})

	// Web: Drop collection
	r.POST("/web/drop", func(c *gin.Context) {
		collectionName := c.PostForm("collection_name")
		schemaName := c.PostForm("schema_name")

		if collectionName == "" || schemaName == "" {
			c.HTML(http.StatusBadRequest, "collection.html", gin.H{
				"Error":          "Collection name and schema name are required",
				"SchemaName":     schemaName,
				"CollectionName": collectionName,
			})
			return
		}

		if err := dropCollection(collectionName, schemaName); err != nil {
			c.HTML(http.StatusBadRequest, "collection.html", gin.H{
				"Error":          err.Error(),
				"SchemaName":     schemaName,
				"CollectionName": collectionName,
			})
			return
		}

		collections, err := listCollections(schemaName)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "index.html", gin.H{
				"Error":      err.Error(),
				"SchemaName": schemaName,
			})
			return
		}

		c.HTML(http.StatusOK, "index.html", gin.H{
			"SchemaName":  schemaName,
			"Collections": collections,
			"Message":     fmt.Sprintf("Collection %s dropped", collectionName),
		})
	})

	// Run server
	addr := fmt.Sprintf(":%s", config.Port)
	if err := r.Run(addr); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start server: %v\n", err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: kitedb <command> [args]")
		fmt.Println("Commands:")
		fmt.Println("  server - Start the REST API and web portal")
		fmt.Println("  add <collection_name> [<schema_name> [<json_data>]]")
		fmt.Println("  insert <collection_name> <json_data> [<schema_name>]")
		fmt.Println("  read <collection_name> [<schema_name>]")
		fmt.Println("  edit <collection_name> <id> <json_data> [<schema_name>]")
		fmt.Println("  remove <collection_name> <id> [<schema_name>]")
		fmt.Println("  drop <collection_name> [<schema_name>]")
		fmt.Println("Examples:")
		fmt.Println("  kitedb server")
		fmt.Println("  kitedb add users")
		fmt.Println("  kitedb add users public '{\"name\":\"nun\", \"age\": 20}'")
		fmt.Println("  kitedb insert users '{\"name\":\"bob\", \"level\": 5}' public")
		fmt.Println("  kitedb read users")
		fmt.Println("  kitedb edit users <id> '{\"name\":\"newname\", \"age\": 25}' public")
		fmt.Println("  kitedb remove users <id>")
		fmt.Println("  kitedb drop users public")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		if err := ensureSchema("public"); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to ensure default schema: %v\n", err)
			os.Exit(1)
		}
		runServer()
	case "add":
		addCmd := flag.NewFlagSet("add", flag.ExitOnError)
		addCmd.Parse(os.Args[2:])
		args := addCmd.Args()
		if len(args) < 1 {
			fmt.Println("Usage: kitedb add <collection_name> [<schema_name> [<json_data>]]")
			os.Exit(1)
		}

		collectionName := args[0]
		schemaName := ""
		jsonData := ""
		if len(args) >= 2 {
			schemaName = args[1]
		}
		if len(args) >= 3 {
			jsonData = args[2]
		}

		if err := addCollection(collectionName, schemaName, jsonData); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "insert":
		insertCmd := flag.NewFlagSet("insert", flag.ExitOnError)
		insertCmd.Parse(os.Args[2:])
		args := insertCmd.Args()
		if len(args) < 2 {
			fmt.Println("Usage: kitedb insert <collection_name> <json_data> [<schema_name>]")
			os.Exit(1)
		}

		collectionName := args[0]
		jsonData := args[1]
		schemaName := ""
		if len(args) >= 3 {
			schemaName = args[2]
		}

		if err := insertRecord(collectionName, jsonData, schemaName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "read":
		readCmd := flag.NewFlagSet("read", flag.ExitOnError)
		readCmd.Parse(os.Args[2:])
		args := readCmd.Args()
		if len(args) < 1 {
			fmt.Println("Usage: kitedb read <collection_name> [<schema_name>]")
			os.Exit(1)
		}

		collectionName := args[0]
		schemaName := ""
		if len(args) >= 2 {
			schemaName = args[1]
		}

		if err := readCollection(collectionName, schemaName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "edit":
		editCmd := flag.NewFlagSet("edit", flag.ExitOnError)
		editCmd.Parse(os.Args[2:])
		args := editCmd.Args()
		if len(args) < 2 {
			fmt.Println("Usage: kitedb edit <collection_name> <id> <json_data> [<schema_name>]")
			os.Exit(1)
		}

		collectionName := args[0]
		id := args[1]
		jsonData := args[2]
		schemaName := ""
		if len(args) >= 4 {
			schemaName = args[3]
		}

		if err := editCollection(collectionName, id, jsonData, schemaName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "remove":
		removeCmd := flag.NewFlagSet("remove", flag.ExitOnError)
		removeCmd.Parse(os.Args[2:])
		args := removeCmd.Args()
		if len(args) < 2 {
			fmt.Println("Usage: kitedb remove <collection_name> <id> [<schema_name>]")
			os.Exit(1)
		}

		collectionName := args[0]
		id := args[1]
		schemaName := ""
		if len(args) >= 3 {
			schemaName = args[2]
		}

		if err := removeRecord(collectionName, id, schemaName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "drop":
		dropCmd := flag.NewFlagSet("drop", flag.ExitOnError)
		dropCmd.Parse(os.Args[2:])
		args := dropCmd.Args()
		if len(args) < 1 {
			fmt.Println("Usage: kitedb drop <collection_name> [<schema_name>]")
			os.Exit(1)
		}

		collectionName := args[0]
		schemaName := ""
		if len(args) >= 2 {
			schemaName = args[1]
		}

		if err := dropCollection(collectionName, schemaName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		fmt.Println("Usage: kitedb <command> [args]")
		fmt.Println("Commands:")
		fmt.Println("  server - Start the REST API and web portal")
		fmt.Println("  add <collection_name> [<schema_name> [<json_data>]]")
		fmt.Println("  insert <collection_name> <json_data> [<schema_name>]")
		fmt.Println("  read <collection_name> [<schema_name>]")
		fmt.Println("  edit <collection_name> <id> <json_data> [<schema_name>]")
		fmt.Println("  remove <collection_name> <id> [<schema_name>]")
		fmt.Println("  drop <collection_name> [<schema_name>]")
		os.Exit(1)
	}
}

// package main

// import (
// 	"bytes"
// 	"crypto/aes"
// 	"crypto/cipher"
// 	"crypto/rand"
// 	"encoding/base64"
// 	"encoding/json"
// 	"flag"
// 	"fmt"
// 	"html/template"
// 	"net/http"
// 	"os"
// 	"path/filepath"
// 	"strings"
// 	"time"

// 	"github.com/gin-gonic/gin"
// 	"github.com/google/uuid"
// )

// // DBConfig holds connection details
// type DBConfig struct {
// 	Username   string `json:"username"`
// 	Password   string `json:"password"`
// 	Host       string `json:"host"`
// 	Port       string `json:"port"`
// 	SchemaName string `json:"schema_name"`
// }

// // Record represents the JSON structure
// type Record map[string]interface{}

// // loadConfig reads config.json or creates default
// func loadConfig() (DBConfig, error) {
// 	configPath := filepath.Join("..", "config.json")
// 	defaultConfig := DBConfig{
// 		Username:   "kite",
// 		Password:   "kite",
// 		Host:       "localhost",
// 		Port:       "4141",
// 		SchemaName: "public",
// 	}

// 	data, err := os.ReadFile(configPath)
// 	if os.IsNotExist(err) {
// 		data, err := json.MarshalIndent(defaultConfig, "", "  ")
// 		if err != nil {
// 			return DBConfig{}, fmt.Errorf("failed to marshal default config: %v", err)
// 		}
// 		if err := os.WriteFile(configPath, data, 0600); err != nil {
// 			return DBConfig{}, fmt.Errorf("failed to write default config: %v", err)
// 		}
// 		return defaultConfig, nil
// 	}
// 	if err != nil {
// 		return DBConfig{}, fmt.Errorf("failed to read config: %v", err)
// 	}

// 	var config DBConfig
// 	if err := json.Unmarshal(data, &config); err != nil {
// 		return DBConfig{}, fmt.Errorf("failed to parse config: %v", err)
// 	}
// 	return config, nil
// }

// // generateKey creates a 32-byte key for AES-256
// func generateKey() ([]byte, error) {
// 	key := make([]byte, 32)
// 	_, err := rand.Read(key)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return key, nil
// }

// // encrypt encrypts data using AES-GCM
// func encrypt(data, key []byte) (string, error) {
// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return "", err
// 	}

// 	gcm, err := cipher.NewGCM(block)
// 	if err != nil {
// 		return "", err
// 	}

// 	nonce := make([]byte, gcm.NonceSize())
// 	if _, err := rand.Read(nonce); err != nil {
// 		return "", err
// 	}

// 	ciphertext := gcm.Seal(nonce, nonce, data, nil)
// 	return base64.StdEncoding.EncodeToString(ciphertext), nil
// }

// // decrypt decrypts base64-encoded ciphertext
// func decrypt(encryptedData string, key []byte) ([]byte, error) {
// 	data, err := base64.StdEncoding.DecodeString(encryptedData)
// 	if err != nil {
// 		return nil, err
// 	}

// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}

// 	gcm, err := cipher.NewGCM(block)
// 	if err != nil {
// 		return nil, err
// 	}

// 	nonceSize := gcm.NonceSize()
// 	if len(data) < nonceSize {
// 		return nil, fmt.Errorf("ciphertext too short")
// 	}

// 	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
// 	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return plaintext, nil
// }

// // validateConnection checks DBConfig credentials
// func validateConnection(config DBConfig) error {
// 	if config.Username == "" || config.Password == "" {
// 		return fmt.Errorf("username and password are required")
// 	}
// 	if config.Host == "" {
// 		return fmt.Errorf("host is required")
// 	}
// 	if config.Port == "" {
// 		return fmt.Errorf("port is required")
// 	}
// 	if config.SchemaName == "" {
// 		return fmt.Errorf("schema_name is required")
// 	}
// 	return nil
// }

// // ensureSchema creates schema directory
// func ensureSchema(schemaName string) error {
// 	dir := filepath.Join("..", "db", schemaName)
// 	if err := os.MkdirAll(dir, 0700); err != nil {
// 		return fmt.Errorf("failed to create schema directory %s: %v", dir, err)
// 	}
// 	if err := os.Chmod(dir, 0700); err != nil {
// 		return fmt.Errorf("failed to set permissions on %s: %v", dir, err)
// 	}
// 	return nil
// }

// // addCollection creates a collection
// func addCollection(collectionName, schemaName, jsonData string) error {
// 	dir := filepath.Join("..", "db")
// 	if schemaName != "" {
// 		dir = filepath.Join("..", "db", schemaName)
// 	}

// 	if err := os.MkdirAll(dir, 0700); err != nil {
// 		return fmt.Errorf("failed to create directory %s: %v", dir, err)
// 	}
// 	if err := os.Chmod(dir, 0700); err != nil {
// 		return fmt.Errorf("failed to set permissions on %s: %v", dir, err)
// 	}

// 	collectionPath := filepath.Join(dir, collectionName+".txt")
// 	if _, err := os.Stat(collectionPath); err == nil {
// 		return fmt.Errorf("collection %s already exists in %s", collectionName, dir)
// 	}

// 	key, err := generateKey()
// 	if err != nil {
// 		return fmt.Errorf("failed to generate key: %v", err)
// 	}

// 	var dataToEncrypt []byte
// 	if jsonData == "" {
// 		dataToEncrypt = []byte("[]")
// 	} else {
// 		// Trim single quotes for Windows compatibility
// 		cleanedJSON := strings.Trim(jsonData, "'\"")
// 		var inputData map[string]interface{}
// 		if err := json.Unmarshal([]byte(cleanedJSON), &inputData); err != nil {
// 			return fmt.Errorf("failed to parse JSON data: %v", err)
// 		}

// 		now := time.Now().UTC().Format(time.RFC3339)
// 		record := Record{
// 			"_id":       uuid.New().String(),
// 			"createdAt": now,
// 			"updatedAt": now,
// 			"_version":  float64(0),
// 		}
// 		for k, v := range inputData {
// 			if k != "_id" && k != "createdAt" && k != "updatedAt" && k != "_version" {
// 				record[k] = v
// 			}
// 		}

// 		dataArray := []Record{record}
// 		dataToEncrypt, err = json.Marshal(dataArray)
// 		if err != nil {
// 			return fmt.Errorf("failed to marshal JSON data: %v", err)
// 		}
// 	}

// 	encrypted, err := encrypt(dataToEncrypt, key)
// 	if err != nil {
// 		return fmt.Errorf("failed to encrypt data: %v", err)
// 	}

// 	if err := os.WriteFile(collectionPath, []byte(encrypted), 0600); err != nil {
// 		return fmt.Errorf("failed to write collection file: %v", err)
// 	}

// 	keyPath := filepath.Join(dir, collectionName+".key")
// 	if err := os.WriteFile(keyPath, key, 0600); err != nil {
// 		return fmt.Errorf("failed to write key file: %v", err)
// 	}

// 	fmt.Printf("Created collection %s at %s\n", collectionName, collectionPath)
// 	return nil
// }

// // insertRecord adds a record
// func insertRecord(collectionName, jsonData, schemaName string) error {
// 	dir := filepath.Join("..", "db")
// 	if schemaName != "" {
// 		dir = filepath.Join("..", "db", schemaName)
// 	}

// 	if err := os.MkdirAll(dir, 0700); err != nil {
// 		return fmt.Errorf("failed to create directory %s: %v", dir, err)
// 	}
// 	if err := os.Chmod(dir, 0700); err != nil {
// 		return fmt.Errorf("failed to set permissions on %s: %v", dir, err)
// 	}

// 	collectionPath := filepath.Join(dir, collectionName+".txt")
// 	keyPath := filepath.Join(dir, collectionName+".key")

// 	if _, err := os.Stat(collectionPath); os.IsNotExist(err) {
// 		return addCollection(collectionName, schemaName, jsonData)
// 	}

// 	encryptedData, err := os.ReadFile(collectionPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read collection file: %v", err)
// 	}

// 	key, err := os.ReadFile(keyPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read key file: %v", err)
// 	}

// 	decrypted, err := decrypt(string(encryptedData), key)
// 	if err != nil {
// 		return fmt.Errorf("failed to decrypt data: %v", err)
// 	}

// 	var records []Record
// 	if err := json.Unmarshal(decrypted, &records); err != nil {
// 		return fmt.Errorf("failed to parse collection JSON: %v", err)
// 	}

// 	// Trim single quotes for Windows compatibility
// 	cleanedJSON := strings.Trim(jsonData, "'\"")
// 	var inputData map[string]interface{}
// 	if err := json.Unmarshal([]byte(cleanedJSON), &inputData); err != nil {
// 		return fmt.Errorf("failed to parse JSON data: %v", err)
// 	}

// 	now := time.Now().UTC().Format(time.RFC3339)
// 	newRecord := Record{
// 		"_id":       uuid.New().String(),
// 		"createdAt": now,
// 		"updatedAt": now,
// 		"_version":  float64(0),
// 	}
// 	for k, v := range inputData {
// 		if k != "_id" && k != "createdAt" && k != "updatedAt" && k != "_version" {
// 			newRecord[k] = v
// 		}
// 	}

// 	records = append(records, newRecord)
// 	dataToEncrypt, err := json.Marshal(records)
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal JSON data: %v", err)
// 	}

// 	encrypted, err := encrypt(dataToEncrypt, key)
// 	if err != nil {
// 		return fmt.Errorf("failed to encrypt data: %v", err)
// 	}

// 	if err := os.WriteFile(collectionPath, []byte(encrypted), 0600); err != nil {
// 		return fmt.Errorf("failed to write collection file: %v", err)
// 	}

// 	fmt.Printf("Inserted record into collection %s\n", collectionName)
// 	return nil
// }

// // readCollection reads for CLI
// func readCollection(collectionName, schemaName string) error {
// 	dir := filepath.Join("..", "db")
// 	if schemaName != "" {
// 		dir = filepath.Join("..", "db", schemaName)
// 	}

// 	collectionPath := filepath.Join(dir, collectionName+".txt")
// 	keyPath := filepath.Join(dir, collectionName+".key")

// 	encryptedData, err := os.ReadFile(collectionPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read collection file: %v", err)
// 	}

// 	key, err := os.ReadFile(keyPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read key file: %v", err)
// 	}

// 	decrypted, err := decrypt(string(encryptedData), key)
// 	if err != nil {
// 		return fmt.Errorf("failed to decrypt data: %v", err)
// 	}

// 	var prettyJSON bytes.Buffer
// 	if err := json.Indent(&prettyJSON, decrypted, "", "  "); err != nil {
// 		return fmt.Errorf("failed to format JSON: %v", err)
// 	}

// 	fmt.Printf("Collection %s contents:\n%s\n", collectionName, prettyJSON.String())
// 	return nil
// }

// // readCollectionAPI reads for API and web
// func readCollectionAPI(collectionName, schemaName string) ([]Record, error) {
// 	dir := filepath.Join("..", "db")
// 	if schemaName != "" {
// 		dir = filepath.Join("..", "db", schemaName)
// 	}

// 	collectionPath := filepath.Join(dir, collectionName+".txt")
// 	keyPath := filepath.Join(dir, collectionName+".key")

// 	encryptedData, err := os.ReadFile(collectionPath)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to read collection file: %v", err)
// 	}

// 	key, err := os.ReadFile(keyPath)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to read key file: %v", err)
// 	}

// 	decrypted, err := decrypt(string(encryptedData), key)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to decrypt data: %v", err)
// 	}

// 	var records []Record
// 	if err := json.Unmarshal(decrypted, &records); err != nil {
// 		return nil, fmt.Errorf("failed to parse collection JSON: %v", err)
// 	}

// 	return records, nil
// }

// // editCollection updates a record
// func editCollection(collectionName, id, jsonData, schemaName string) error {
// 	dir := filepath.Join("..", "db")
// 	if schemaName != "" {
// 		dir = filepath.Join("..", "db", schemaName)
// 	}

// 	collectionPath := filepath.Join(dir, collectionName+".txt")
// 	keyPath := filepath.Join(dir, collectionName+".key")

// 	encryptedData, err := os.ReadFile(collectionPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read collection file: %v", err)
// 	}

// 	key, err := os.ReadFile(keyPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read key file: %v", err)
// 	}

// 	decrypted, err := decrypt(string(encryptedData), key)
// 	if err != nil {
// 		return fmt.Errorf("failed to decrypt data: %v", err)
// 	}

// 	var records []Record
// 	if err := json.Unmarshal(decrypted, &records); err != nil {
// 		return fmt.Errorf("failed to parse collection JSON: %v", err)
// 	}

// 	// Trim single quotes for Windows compatibility
// 	cleanedJSON := strings.Trim(jsonData, "'\"")
// 	var inputData map[string]interface{}
// 	if err := json.Unmarshal([]byte(cleanedJSON), &inputData); err != nil {
// 		return fmt.Errorf("failed to parse JSON data: %v", err)
// 	}

// 	found := false
// 	now := time.Now().UTC().Format(time.RFC3339)
// 	for i, record := range records {
// 		if record["_id"] == id {
// 			newRecord := Record{
// 				"_id":       id,
// 				"createdAt": record["createdAt"],
// 				"updatedAt": now,
// 				"_version":  record["_version"].(float64) + 1,
// 			}
// 			for k, v := range inputData {
// 				if k != "_id" && k != "createdAt" && k != "updatedAt" && k != "_version" {
// 					newRecord[k] = v
// 				}
// 			}
// 			records[i] = newRecord
// 			found = true
// 			break
// 		}
// 	}

// 	if !found {
// 		return fmt.Errorf("record with _id %s not found", id)
// 	}

// 	dataToEncrypt, err := json.Marshal(records)
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal JSON data: %v", err)
// 	}

// 	encrypted, err := encrypt(dataToEncrypt, key)
// 	if err != nil {
// 		return fmt.Errorf("failed to encrypt data: %v", err)
// 	}

// 	if err := os.WriteFile(collectionPath, []byte(encrypted), 0600); err != nil {
// 		return fmt.Errorf("failed to write collection file: %v", err)
// 	}

// 	fmt.Printf("Updated record %s in collection %s\n", id, collectionName)
// 	return nil
// }

// // removeRecord removes a record
// func removeRecord(collectionName, id, schemaName string) error {
// 	dir := filepath.Join("..", "db")
// 	if schemaName != "" {
// 		dir = filepath.Join("..", "db", schemaName)
// 	}

// 	collectionPath := filepath.Join(dir, collectionName+".txt")
// 	keyPath := filepath.Join(dir, collectionName+".key")

// 	encryptedData, err := os.ReadFile(collectionPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read collection file: %v", err)
// 	}

// 	key, err := os.ReadFile(keyPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read key file: %v", err)
// 	}

// 	decrypted, err := decrypt(string(encryptedData), key)
// 	if err != nil {
// 		return fmt.Errorf("failed to decrypt data: %v", err)
// 	}

// 	var records []Record
// 	if err := json.Unmarshal(decrypted, &records); err != nil {
// 		return fmt.Errorf("failed to parse collection JSON: %v", err)
// 	}

// 	found := false
// 	newRecords := []Record{}
// 	for _, record := range records {
// 		if record["_id"] != id {
// 			newRecords = append(newRecords, record)
// 		} else {
// 			found = true
// 		}
// 	}

// 	if !found {
// 		return fmt.Errorf("record with _id %s not found", id)
// 	}

// 	dataToEncrypt, err := json.Marshal(newRecords)
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal JSON data: %v", err)
// 	}

// 	encrypted, err := encrypt(dataToEncrypt, key)
// 	if err != nil {
// 		return fmt.Errorf("failed to encrypt data: %v", err)
// 	}

// 	if err := os.WriteFile(collectionPath, []byte(encrypted), 0600); err != nil {
// 		return fmt.Errorf("failed to write collection file: %v", err)
// 	}

// 	fmt.Printf("Removed record %s from collection %s\n", id, collectionName)
// 	return nil
// }

// // dropCollection deletes a collection
// func dropCollection(collectionName, schemaName string) error {
// 	dir := filepath.Join("..", "db")
// 	if schemaName != "" {
// 		dir = filepath.Join("..", "db", schemaName)
// 	}

// 	collectionPath := filepath.Join(dir, collectionName+".txt")
// 	keyPath := filepath.Join(dir, collectionName+".key")

// 	if _, err := os.Stat(collectionPath); os.IsNotExist(err) {
// 		return fmt.Errorf("collection %s does not exist in %s", collectionName, dir)
// 	}

// 	if err := os.Remove(collectionPath); err != nil {
// 		return fmt.Errorf("failed to delete collection file: %v", err)
// 	}

// 	if err := os.Remove(keyPath); err != nil {
// 		return fmt.Errorf("failed to delete key file: %v", err)
// 	}

// 	fmt.Printf("Dropped collection %s from %s\n", collectionName, dir)
// 	return nil
// }

// // listCollections returns collections in a schema
// func listCollections(schemaName string) ([]string, error) {
// 	dir := filepath.Join("..", "db")
// 	if schemaName != "" {
// 		dir = filepath.Join("..", "db", schemaName)
// 	}

// 	entries, err := os.ReadDir(dir)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to read schema directory: %v", err)
// 	}

// 	var collections []string
// 	for _, entry := range entries {
// 		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".txt" {
// 			collections = append(collections, entry.Name()[:len(entry.Name())-4])
// 		}
// 	}
// 	return collections, nil
// }

// // runServer starts the Gin server
// func runServer() {
// 	wd, _ := os.Getwd()
// 	fmt.Printf("Current working directory: %s\n", wd)
// 	fmt.Printf("Templates directory: %s\n", filepath.Join(wd, "templates"))
// 	config, err := loadConfig()

// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
// 		os.Exit(1)
// 	}

// 	r := gin.Default()

// 	// Serve static files
// 	r.Static("/static", "./static")

// 	// Load HTML templates
// 	// _, err = os.Stat("templates")
// 	// if os.IsNotExist(err) {
// 	// 	fmt.Fprintf(os.Stderr, "Error: templates directory not found in %s\n", filepath.Join(".", "templates"))
// 	// 	os.Exit(1)
// 	// }
// 	// tmpl, err := template.ParseFS(os.DirFS("templates"), "templates/*.html")

// 	// if err != nil {
// 	// 	fmt.Fprintf(os.Stderr, "Error loading templates: %v\n", err)
// 	// 	os.Exit(1)
// 	// }
// 	// r.SetHTMLTemplate(tmpl)

// 	// Load HTML templates
// 	templatesDir := filepath.Join(".", "templates")
// 	_, err = os.Stat(templatesDir)
// 	if os.IsNotExist(err) {
// 		fmt.Fprintf(os.Stderr, "Error: templates directory not found in %s\n", templatesDir)
// 		os.Exit(1)
// 	}

// 	// Use explicit file paths instead of ParseFS
// 	tmpl := template.New("").Funcs(template.FuncMap{})
// 	tmpl, err = tmpl.ParseFiles(
// 		filepath.Join(templatesDir, "index.html"),
// 		filepath.Join(templatesDir, "collection.html"),
// 	)
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Error loading templates: %v\n", err)
// 		os.Exit(1)
// 	}
// 	r.SetHTMLTemplate(tmpl)

// 	// API: Connect
// 	r.POST("/connect", func(c *gin.Context) {
// 		var reqConfig DBConfig
// 		if err := c.ShouldBindJSON(&reqConfig); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
// 			return
// 		}

// 		if err := validateConnection(reqConfig); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 			return
// 		}

// 		if err := ensureSchema(reqConfig.SchemaName); err != nil {
// 			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// 			return
// 		}

// 		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Connected to schema %s", reqConfig.SchemaName)})
// 	})

// 	// API middleware
// 	r.Use(func(c *gin.Context) {
// 		var reqConfig DBConfig
// 		if err := c.ShouldBindJSON(&reqConfig); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connection details in body"})
// 			c.Abort()
// 			return
// 		}

// 		if err := validateConnection(reqConfig); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 			c.Abort()
// 			return
// 		}

// 		if err := ensureSchema(reqConfig.SchemaName); err != nil {
// 			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// 			c.Abort()
// 			return
// 		}

// 		c.Set("schema_name", reqConfig.SchemaName)
// 		c.Next()
// 	})

// 	// API: Create collection
// 	r.POST("/:schema_name/:collection_name/create", func(c *gin.Context) {
// 		schemaName := c.Param("schema_name")
// 		collectionName := c.Param("collection_name")
// 		var body struct {
// 			Data string `json:"data"`
// 		}
// 		if err := c.ShouldBindJSON(&body); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
// 			return
// 		}

// 		if err := addCollection(collectionName, schemaName, body.Data); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 			return
// 		}

// 		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Collection %s created", collectionName)})
// 	})

// 	// API: Insert record
// 	r.POST("/:schema_name/:collection_name", func(c *gin.Context) {
// 		schemaName := c.Param("schema_name")
// 		collectionName := c.Param("collection_name")
// 		var body struct {
// 			Data string `json:"data"`
// 		}
// 		if err := c.ShouldBindJSON(&body); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
// 			return
// 		}

// 		if err := insertRecord(collectionName, body.Data, schemaName); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 			return
// 		}

// 		c.JSON(http.StatusOK, gin.H{"message": "Record inserted"})
// 	})

// 	// API: Read collection
// 	r.GET("/:schema_name/:collection_name", func(c *gin.Context) {
// 		schemaName := c.Param("schema_name")
// 		collectionName := c.Param("collection_name")

// 		records, err := readCollectionAPI(collectionName, schemaName)
// 		if err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 			return
// 		}

// 		c.JSON(http.StatusOK, records)
// 	})

// 	// API: Update record
// 	r.PUT("/:schema_name/:collection_name/:id", func(c *gin.Context) {
// 		schemaName := c.Param("schema_name")
// 		collectionName := c.Param("collection_name")
// 		id := c.Param("id")
// 		var body struct {
// 			Data string `json:"data"`
// 		}
// 		if err := c.ShouldBindJSON(&body); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
// 			return
// 		}

// 		if err := editCollection(collectionName, id, body.Data, schemaName); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 			return
// 		}

// 		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Record %s updated", id)})
// 	})

// 	// API: Delete record
// 	r.DELETE("/:schema_name/:collection_name/:id", func(c *gin.Context) {
// 		schemaName := c.Param("schema_name")
// 		collectionName := c.Param("collection_name")
// 		id := c.Param("id")

// 		if err := removeRecord(collectionName, id, schemaName); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 			return
// 		}

// 		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Record %s deleted", id)})
// 	})

// 	// API: Drop collection
// 	r.DELETE("/:schema_name/:collection_name", func(c *gin.Context) {
// 		schemaName := c.Param("schema_name")
// 		collectionName := c.Param("collection_name")

// 		if err := dropCollection(collectionName, schemaName); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 			return
// 		}

// 		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Collection %s dropped", collectionName)})
// 	})

// 	// Web: Home page (list collections)
// 	r.GET("/", func(c *gin.Context) {
// 		collections, err := listCollections(config.SchemaName)
// 		if err != nil {
// 			c.HTML(http.StatusInternalServerError, "index.html", gin.H{
// 				"Error": err.Error(),
// 			})
// 			return
// 		}

// 		c.HTML(http.StatusOK, "index.html", gin.H{
// 			"SchemaName":  config.SchemaName,
// 			"Collections": collections,
// 		})
// 	})

// 	// Web: Collection page (view records)
// 	r.GET("/collections/:schema_name/:collection_name", func(c *gin.Context) {
// 		schemaName := c.Param("schema_name")
// 		collectionName := c.Param("collection_name")

// 		records, err := readCollectionAPI(collectionName, schemaName)
// 		if err != nil {
// 			c.HTML(http.StatusInternalServerError, "collection.html", gin.H{
// 				"Error": err.Error(),
// 			})
// 			return
// 		}

// 		c.HTML(http.StatusOK, "collection.html", gin.H{
// 			"SchemaName":     schemaName,
// 			"CollectionName": collectionName,
// 			"Records":        records,
// 		})
// 	})

// 	// Run server
// 	addr := fmt.Sprintf(":%s", config.Port)
// 	if err := r.Run(addr); err != nil {
// 		fmt.Fprintf(os.Stderr, "Failed to start server: %v\n", err)
// 		os.Exit(1)
// 	}
// }

// func main() {
// 	if len(os.Args) < 2 {
// 		fmt.Println("Usage: kitedb <command> [args]")
// 		fmt.Println("Commands:")
// 		fmt.Println("  server - Start the REST API and web portal")
// 		fmt.Println("  add <collection_name> [<schema_name> [<json_data>]]")
// 		fmt.Println("  insert <collection_name> <json_data> [<schema_name>]")
// 		fmt.Println("  read <collection_name> [<schema_name>]")
// 		fmt.Println("  edit <collection_name> <id> <json_data> [<schema_name>]")
// 		fmt.Println("  remove <collection_name> <id> [<schema_name>]")
// 		fmt.Println("  drop <collection_name> [<schema_name>]")
// 		fmt.Println("Examples:")
// 		fmt.Println("  kitedb server")
// 		fmt.Println("  kitedb add users")
// 		fmt.Println("  kitedb add users public '{\"name\":\"nun\", \"age\": 20}'")
// 		fmt.Println("  kitedb insert users '{\"name\":\"bob\", \"level\": 5}' public")
// 		fmt.Println("  kitedb read users")
// 		fmt.Println("  kitedb edit users <id> '{\"name\":\"newname\", \"age\": 25}' public")
// 		fmt.Println("  kitedb remove users <id>")
// 		fmt.Println("  kitedb drop users public")
// 		os.Exit(1)
// 	}

// 	switch os.Args[1] {
// 	case "server":
// 		if err := ensureSchema("public"); err != nil {
// 			fmt.Fprintf(os.Stderr, "Failed to ensure default schema: %v\n", err)
// 			os.Exit(1)
// 		}
// 		runServer()
// 	case "add":
// 		addCmd := flag.NewFlagSet("add", flag.ExitOnError)
// 		addCmd.Parse(os.Args[2:])
// 		args := addCmd.Args()
// 		if len(args) < 1 {
// 			fmt.Println("Usage: kitedb add <collection_name> [<schema_name> [<json_data>]]")
// 			os.Exit(1)
// 		}

// 		collectionName := args[0]
// 		schemaName := ""
// 		jsonData := ""
// 		if len(args) >= 2 {
// 			schemaName = args[1]
// 		}
// 		if len(args) >= 3 {
// 			jsonData = args[2]
// 		}

// 		if err := addCollection(collectionName, schemaName, jsonData); err != nil {
// 			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
// 			os.Exit(1)
// 		}
// 	case "insert":
// 		insertCmd := flag.NewFlagSet("insert", flag.ExitOnError)
// 		insertCmd.Parse(os.Args[2:])
// 		args := insertCmd.Args()
// 		if len(args) < 2 {
// 			fmt.Println("Usage: kitedb insert <collection_name> <json_data> [<schema_name>]")
// 			os.Exit(1)
// 		}

// 		collectionName := args[0]
// 		jsonData := args[1]
// 		schemaName := ""
// 		if len(args) >= 3 {
// 			schemaName = args[2]
// 		}

// 		if err := insertRecord(collectionName, jsonData, schemaName); err != nil {
// 			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
// 			os.Exit(1)
// 		}
// 	case "read":
// 		readCmd := flag.NewFlagSet("read", flag.ExitOnError)
// 		readCmd.Parse(os.Args[2:])
// 		args := readCmd.Args()
// 		if len(args) < 1 {
// 			fmt.Println("Usage: kitedb read <collection_name> [<schema_name>]")
// 			os.Exit(1)
// 		}

// 		collectionName := args[0]
// 		schemaName := ""
// 		if len(args) >= 2 {
// 			schemaName = args[1]
// 		}

// 		if err := readCollection(collectionName, schemaName); err != nil {
// 			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
// 			os.Exit(1)
// 		}
// 	case "edit":
// 		editCmd := flag.NewFlagSet("edit", flag.ExitOnError)
// 		editCmd.Parse(os.Args[2:])
// 		args := editCmd.Args()
// 		if len(args) < 2 {
// 			fmt.Println("Usage: kitedb edit <collection_name> <id> <json_data> [<schema_name>]")
// 			os.Exit(1)
// 		}

// 		collectionName := args[0]
// 		id := args[1]
// 		jsonData := args[2]
// 		schemaName := ""
// 		if len(args) >= 4 {
// 			schemaName = args[3]
// 		}

// 		if err := editCollection(collectionName, id, jsonData, schemaName); err != nil {
// 			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
// 			os.Exit(1)
// 		}
// 	case "remove":
// 		removeCmd := flag.NewFlagSet("remove", flag.ExitOnError)
// 		removeCmd.Parse(os.Args[2:])
// 		args := removeCmd.Args()
// 		if len(args) < 2 {
// 			fmt.Println("Usage: kitedb remove <collection_name> <id> [<schema_name>]")
// 			os.Exit(1)
// 		}

// 		collectionName := args[0]
// 		id := args[1]
// 		schemaName := ""
// 		if len(args) >= 3 {
// 			schemaName = args[2]
// 		}

// 		if err := removeRecord(collectionName, id, schemaName); err != nil {
// 			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
// 			os.Exit(1)
// 		}
// 	case "drop":
// 		dropCmd := flag.NewFlagSet("drop", flag.ExitOnError)
// 		dropCmd.Parse(os.Args[2:])
// 		args := dropCmd.Args()
// 		if len(args) < 1 {
// 			fmt.Println("Usage: kitedb drop <collection_name> [<schema_name>]")
// 			os.Exit(1)
// 		}

// 		collectionName := args[0]
// 		schemaName := ""
// 		if len(args) >= 2 {
// 			schemaName = args[1]
// 		}

// 		if err := dropCollection(collectionName, schemaName); err != nil {
// 			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
// 			os.Exit(1)
// 		}
// 	default:
// 		fmt.Printf("Unknown command: %s\n", os.Args[1])
// 		fmt.Println("Usage: kitedb <command> [args]")
// 		fmt.Println("Commands:")
// 		fmt.Println("  server - Start the REST API and web portal")
// 		fmt.Println("  add <collection_name> [<schema_name> [<json_data>]]")
// 		fmt.Println("  insert <collection_name> <json_data> [<schema_name>]")
// 		fmt.Println("  read <collection_name> [<schema_name>]")
// 		fmt.Println("  edit <collection_name> <id> <json_data> [<schema_name>]")
// 		fmt.Println("  remove <collection_name> <id> [<schema_name>]")
// 		fmt.Println("  drop <collection_name> [<schema_name>]")
// 		os.Exit(1)
// 	}
// }
