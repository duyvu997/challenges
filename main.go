package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	_ "simple-server/docs" // swagger docs

	ginSwagger "github.com/swaggo/gin-swagger"
	swaggerFiles "github.com/swaggo/files"
)

// @title JWT Upload API
// @version 1.0
// @description Simple JWT auth and image upload server using Gin
// @BasePath /
// @host localhost:8080
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

var jwtKey []byte
var tokenExpiry = time.Hour * 1

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

var db *sql.DB

func main() {
	gin.SetMode(gin.DebugMode)

	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, reading environment variables from OS")
	}

	// Read JWT secret from env
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is not set")
	}
	jwtKey = []byte(jwtSecret)

	var err error
	db, err = sql.Open("sqlite3", "file:data.db?cache=shared&mode=rwc")
	if err != nil {
		panic(err)
	}
	initDB()

	r := gin.Default()

	r.POST("/register", register)
	r.POST("/login", login)
	r.POST("/revoke", revokeToken)
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	auth := r.Group("/")
	auth.Use(authMiddleware)
	auth.POST("/upload", uploadHandler)

	r.Run(":8080")
}

func initDB() {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		password TEXT
	);

	CREATE TABLE IF NOT EXISTS uploads (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT,
		filename TEXT,
		content_type TEXT,
		size INTEGER,
		uploaded_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS revoked_tokens (
		token_hash TEXT PRIMARY KEY,
		revoked_at DATETIME
	);
	`)
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// @Summary Register
// @Description Register a new user
// @Accept json
// @Produce json
// @Param credentials body Credentials true "Credentials"
// @Success 201 {string} string "Created"
// @Failure 400 {object} map[string]string
// @Router /register [post]
func register(c *gin.Context) {
	var creds Credentials
	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	_, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", creds.Username, creds.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}
	c.Status(http.StatusCreated)
}

// @Summary Login
// @Description Login and get JWT token
// @Accept json
// @Produce json
// @Param credentials body Credentials true "Credentials"
// @Success 200 {object} map[string]string
// @Failure 400,401 {object} map[string]string
// @Router /login [post]
func login(c *gin.Context) {
	var creds Credentials
	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	var dbPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", creds.Username).Scan(&dbPassword)
	if err != nil || dbPassword != creds.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	expiration := time.Now().Add(tokenExpiry)
	claims := &Claims{
		Username: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiration),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	// Store token hash with revoked_at = NULL (means active)
	tokenHash := hashToken(tokenString)
	_, err = db.Exec("INSERT INTO revoked_tokens (token_hash, revoked_at) VALUES (?, NULL)", tokenHash)
	if err != nil {
		log.Println("Warning: could not store token hash:", err)
		// Do not block login
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// @Summary Revoke Token
// @Description Revoke JWT token (logout)
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /revoke [post]
func revokeToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid token"})
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	tokenHash := hashToken(tokenStr)

	// Mark revoked_at timestamp instead of deleting, for audit
	res, err := db.Exec("UPDATE revoked_tokens SET revoked_at = ? WHERE token_hash = ?", time.Now(), tokenHash)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke token"})
		return
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token not found or already revoked"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Token revoked successfully"})
}

func authMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid token"})
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	tokenHash := hashToken(tokenStr)

	// Check if token hash exists AND is NOT revoked
	var revokedAt sql.NullTime
	err := db.QueryRow("SELECT revoked_at FROM revoked_tokens WHERE token_hash = ?", tokenHash).Scan(&revokedAt)
	if err == sql.ErrNoRows || revokedAt.Valid {
		// No token found or revoked_at set = token revoked
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token revoked"})
		return
	} else if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal error"})
		return
	}

	// Validate token itself
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}

	c.Set("username", claims.Username)
	c.Next()
}

// @Summary Upload Image
// @Description Upload an image file (authenticated)
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "Image file"
// @Success 200 {object} map[string]string
// @Failure 400,401 {object} map[string]string
// @Security BearerAuth
// @Router /upload [post]
func uploadHandler(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to get file"})
		return
	}
	defer file.Close()

	contentType := header.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "image/") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only image files are allowed"})
		return
	}

	uploadDir := "uploads"
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create upload directory"})
		return
	}

	filename := time.Now().Format("20060102150405") + "_" + filepath.Base(header.Filename)
	filePath := filepath.Join(uploadDir, filename)

	out, err := os.Create(filePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to save file"})
		return
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error while saving file"})
		return
	}

	_, err = db.Exec(
		`INSERT INTO uploads (username, filename, content_type, size, uploaded_at) VALUES (?, ?, ?, ?, ?)`,
		username, filename, contentType, header.Size, time.Now(),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save upload info"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "File uploaded successfully", "filename": filename})
}
