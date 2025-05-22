package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"kite/src/types"
	"kite/src/helper"
	"kite/src/controller"

	"github.com/gin-gonic/gin"
)

func loadConfig() (types.DBConfig, error) {
	configPath := filepath.Join("..", "config.json")
	defaultConfig := types.DBConfig{
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
			return types.DBConfig{}, fmt.Errorf("failed to marshal default config: %v", err)
		}
		if err := os.WriteFile(configPath, data, 0600); err != nil {
			return types.DBConfig{}, fmt.Errorf("failed to write default config: %v", err)
		}
		return defaultConfig, nil
	}
	if err != nil {
		return types.DBConfig{}, fmt.Errorf("failed to read config: %v", err)
	}

	var config types.DBConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return types.DBConfig{}, fmt.Errorf("failed to parse config: %v", err)
	}
	return config, nil
}

func validateConnection(config types.DBConfig) error {
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

func readCollectionAPI(collectionName, schemaName string) ([]types.Record, error) {
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

	decrypted, err := helper.Decrypt(string(encryptedData), key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	var records []types.Record
	if err := json.Unmarshal(decrypted, &records); err != nil {
		return nil, fmt.Errorf("failed to parse collection JSON: %v", err)
	}

	return records, nil
}

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

func runServer() {
	config, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	r := gin.Default()

	r.Static("/static", "./static")

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
			var reqConfig types.DBConfig
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
			var reqConfig types.DBConfig
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

			if err := controller.AddCollection(collectionName, schemaName, body.Data); err != nil {
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

			if err := controller.InsertRecord(collectionName, body.Data, schemaName); err != nil {
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

			if err := controller.EditCollection(collectionName, id, body.Data, schemaName); err != nil {
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

			if err := controller.MoveRecord(collectionName, id, schemaName); err != nil {
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

		if err := controller.AddCollection(collectionName, schemaName, data); err != nil {
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

		if err := controller.InsertRecord(collectionName, data, schemaName); err != nil {
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

		if err := controller.EditCollection(collectionName, id, data, schemaName); err != nil {
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

		if err := controller.MoveRecord(collectionName, id, schemaName); err != nil {
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
	fmt.Printf("Server running at http://localhost:%s\n", config.Port)
	if err := r.Run(addr); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start server: %v\n", err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: kite <command> [args]")
		fmt.Println("Commands:")
		fmt.Println("  serve - Start the REST API and web portal")
		fmt.Println("  add <collection> [<schema> [<json_data>]]")
		fmt.Println("  push <collection> <json_data> [<schema>]")
		fmt.Println("  pull <collection> [<schema>]")
		fmt.Println("  edit <collection> <id> <json_data> [<schema>]")
		fmt.Println("  move <collection> <id> [<schema>]")
		fmt.Println("  drop <collection> [<schema>]")
		fmt.Println("Examples:")
		fmt.Println("  kite server")
		fmt.Println("  kite add users")
		fmt.Println("  kite add users public '{\"name\":\"nun\", \"age\": 20}'")
		fmt.Println("  kite insert users '{\"name\":\"bob\", \"level\": 5}' public")
		fmt.Println("  kite read users")
		fmt.Println("  kite edit users <id> '{\"name\":\"newname\", \"age\": 25}' public")
		fmt.Println("  kite remove users <id>")
		fmt.Println("  kite drop users public")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
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
			fmt.Println("Usage: kite add <collection> [<schema> [<json_data>]]")
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

		if err := controller.AddCollection(collectionName, schemaName, jsonData); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "push":
		pushCmd := flag.NewFlagSet("push", flag.ExitOnError)
		pushCmd.Parse(os.Args[2:])
		args := pushCmd.Args()
		if len(args) < 2 {
			fmt.Println("Usage: kitedb push <collection> <json_data> [<schema>]")
			os.Exit(1)
		}

		collectionName := args[0]
		jsonData := args[1]
		schemaName := ""
		if len(args) >= 3 {
			schemaName = args[2]
		}

		if err := controller.InsertRecord(collectionName, jsonData, schemaName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "pull":
		pullCmd := flag.NewFlagSet("pull", flag.ExitOnError)
		pullCmd.Parse(os.Args[2:])
		args := pullCmd.Args()
		if len(args) < 1 {
			fmt.Println("Usage: kitedb pull <collection_name> [<schema_name>]")
			os.Exit(1)
		}

		collectionName := args[0]
		schemaName := ""
		if len(args) >= 2 {
			schemaName = args[1]
		}

		if err := controller.PullCollection(collectionName, schemaName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "edit":
		editCmd := flag.NewFlagSet("edit", flag.ExitOnError)
		editCmd.Parse(os.Args[2:])
		args := editCmd.Args()
		if len(args) < 2 {
			fmt.Println("Usage: kite edit <collection> <id> <json_data> [<schema>]")
			os.Exit(1)
		}

		collectionName := args[0]
		id := args[1]
		jsonData := args[2]
		schemaName := ""
		if len(args) >= 4 {
			schemaName = args[3]
		}

		if err := controller.EditCollection(collectionName, id, jsonData, schemaName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "move":
		moveCmd := flag.NewFlagSet("move", flag.ExitOnError)
		moveCmd.Parse(os.Args[2:])
		args := moveCmd.Args()
		if len(args) < 2 {
			fmt.Println("Usage: kite move <collection> <id> [<schema>]")
			os.Exit(1)
		}

		collectionName := args[0]
		id := args[1]
		schemaName := ""
		if len(args) >= 3 {
			schemaName = args[2]
		}

		if err := controller.MoveRecord(collectionName, id, schemaName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "drop":
		dropCmd := flag.NewFlagSet("drop", flag.ExitOnError)
		dropCmd.Parse(os.Args[2:])
		args := dropCmd.Args()
		if len(args) < 1 {
			fmt.Println("Usage: kite drop <collection> [<schema>]")
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
		fmt.Println("Usage: kite <command> [args]")
		fmt.Println("Commands:")
		fmt.Println("  serve - Start the REST API and web portal")
		fmt.Println("  add <collection> [<schema> [<json_data>]]")
		fmt.Println("  push <collection> <json_data> [<schema>]")
		fmt.Println("  pull <collection> [<schema>]")
		fmt.Println("  edit <collection> <id> <json_data> [<schema>]")
		fmt.Println("  move <collection> <id> [<schema>]")
		fmt.Println("  drop <collection> [<schema>]")
		os.Exit(1)
	}
}
