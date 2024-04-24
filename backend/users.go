package main

import (
	"database/sql"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
)

type AppSetting struct {
	ID        int    `json:"ID"`
	MetaKey   string `json:"metaKey"`
	MetaValue string `json:"metaValue"`
	Updated   string `json:"updated"`
	Created   string `json:"created"`
}

type Users struct {
	ID              int    `json:"ID"`
	FirstName       string `json:"firstName"`
	LastName        string `json:"lastName"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirmPassword"`
	Email           string `json:"email"`
	MobileNumber    string `json:"mobileNumber"`
}

type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type ValidationError struct {
	Msg string
}

var (
	db *sql.DB

	ErrEmptyField          = NewValidationError("empty field")
	ErrWeakPassword        = NewValidationError("password too weak")
	ErrPasswordMismatch    = NewValidationError("passwords do not match")
	ErrInvalidEmail        = NewValidationError("invalid email format")
	ErrInvalidMobileNumber = NewValidationError("invalid mobile number format")
)

func main() {
	initDB()
	defer db.Close()

	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://frontend", "http://localhost"},
		AllowMethods:     []string{"POST", "GET", "PUT", "PATCH", "OPTIONS"},
		AllowHeaders:     []string{"Origin, Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowOriginFunc: func(origin string) bool {
			return origin == "https://github.com"
		},
		MaxAge: 12 * time.Hour,
	}))

	router.GET("/app_settings", getAppSettings)
	router.POST("/app_settings", addAppSetting)
	router.DELETE("/app_settings/:id", deleteAppSetting)
	router.POST("/users", addUser)
	router.GET("/users", getUsers)
	router.POST("/login", loginUser)

	if err := router.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}

func initDB() {
	var err error
	db, err = sql.Open("mysql", "root:yaman@tcp(mysql:3306)/daily_diary")
	if err != nil {
		log.Fatal(err)
	}
}

func getAppSettings(c *gin.Context) {
	settings, err := loadAppSettingsFromDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load app settings"})
		return
	}
	c.JSON(http.StatusOK, settings)
}

func addAppSetting(c *gin.Context) {
	var newSetting AppSetting
	if err := c.BindJSON(&newSetting); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	now := time.Now().Format("2006-01-02 15:04:05")
	newSetting.Updated = now
	newSetting.Created = now

	if exists, err := checkDuplicateMetaKey(newSetting.MetaKey); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return

	} else if exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Duplicate meta key"})
		return
	}

	if err := saveAppSettingToDB(&newSetting); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save app setting"})
		return
	}

	c.JSON(http.StatusCreated, newSetting)
}

func deleteAppSetting(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid setting ID"})
		return
	}

	if exists, err := checkAppSettingExistence(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	} else if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Setting not found"})
		return
	}

	if err := deleteAppSettingFromDB(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete setting"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Setting deleted successfully"})
}

func checkDuplicateMetaKey(metaKey string) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM app_settings WHERE metakey = ?", metaKey).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func checkAppSettingExistence(id int) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM app_settings WHERE ID = ?", id).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func loadAppSettingsFromDB() ([]AppSetting, error) {
	rows, err := db.Query("SELECT metakey, metavalue, updated, created FROM app_settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var settings []AppSetting
	for rows.Next() {
		var setting AppSetting
		if err := rows.Scan(&setting.MetaKey, &setting.MetaValue, &setting.Updated, &setting.Created); err != nil {
			return nil, err
		}
		settings = append(settings, setting)
	}
	return settings, nil
}

func saveAppSettingToDB(setting *AppSetting) error {
	_, err := db.Exec("INSERT INTO app_settings (metakey, metavalue, updated, created) VALUES (?, ?, ?, ?)",
		setting.MetaKey, setting.MetaValue, setting.Updated, setting.Created)
	return err
}

func deleteAppSettingFromDB(id int) error {
	_, err := db.Exec("DELETE FROM app_settings WHERE ID = ?", id)
	return err
}

func addUser(c *gin.Context) {
	var newUser Users
	if err := c.BindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	if err := validateUser(newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := saveUserToDB(newUser); err != nil {
		log.Fatal(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User signed up successfully"})
}

func getUsers(c *gin.Context) {
	users, err := loadUsersFromDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load users"})
		return
	}
	c.JSON(http.StatusOK, users)
}

func validateUser(user Users) error {
	if user.FirstName == "" || user.LastName == "" || user.Username == "" || user.Password == "" || user.ConfirmPassword == "" || user.Email == "" || user.MobileNumber == "" {
		return ErrEmptyField
	}

	if len(user.Password) < 8 {
		return ErrWeakPassword
	}

	if user.Password != user.ConfirmPassword {
		return ErrPasswordMismatch
	}

	if !isEmailValid(user.Email) {
		return ErrInvalidEmail
	}

	if !isMobileNumberValid(user.MobileNumber) {
		return ErrInvalidMobileNumber
	}

	return nil
}

func isEmailValid(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func isMobileNumberValid(mobileNumber string) bool {
	mobileNumberRegex := regexp.MustCompile(`^[0-9]{10}$`)
	return mobileNumberRegex.MatchString(mobileNumber)
}

func saveUserToDB(user Users) error {
	_, err := db.Exec("INSERT INTO users (firstname, lastname, username, password, confirmpassword, email, mobilenumber) VALUES (?, ?, ?, ?, ?, ?, ?)",
		user.FirstName, user.LastName, user.Username, user.Password, user.ConfirmPassword, user.Email, user.MobileNumber)
	if err != nil {
		log.Printf("Error saving user to database: %v", err)
		return err
	}
	return nil
}

func loadUsersFromDB() ([]Users, error) {
	rows, err := db.Query("SELECT ID, firstname, lastname, username, password, confirmpassword, email, mobilenumber FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []Users
	for rows.Next() {
		var user Users
		if err := rows.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Username, &user.Password, &user.ConfirmPassword, &user.Email, &user.MobileNumber); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func getUserByEmail(email string) (*Users, error) {
	var user Users
	err := db.QueryRow("SELECT ID, firstname, lastname, username, password, confirmpassword, email, mobilenumber FROM users WHERE email = ?", email).Scan(
		&user.ID, &user.FirstName, &user.LastName, &user.Username, &user.Password, &user.ConfirmPassword, &user.Email, &user.MobileNumber)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found
		}
		return nil, err
	}
	return &user, nil
}
func loginUser(c *gin.Context) {
	var credentials Login
	if err := c.BindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	// Query the database to verify the user's credentials
	user, err := getUserByEmail(credentials.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to authenticate"})
		return
	}

	// Check if the user exists and if the password matches
	if user == nil || user.Password != credentials.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	// If the credentials are correct, return a success response
	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "user": user})
}

func NewValidationError(msg string) *ValidationError {
	return &ValidationError{Msg: msg}
}

func (e *ValidationError) Error() string {
	return e.Msg
}
