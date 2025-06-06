package types

type Record map[string]interface{}

type DBConfig struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Host       string `json:"host"`
	Port       string `json:"port"`
	SchemaName string `json:"schema_name"`
}