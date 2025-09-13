package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Models
type User struct {
	ID          string    `json:"id"`
	FirstName   string    `json:"first_name"`
	SecondName  string    `json:"second_name"`
	Birthdate   string    `json:"birthdate"`
	Biography   string    `json:"biography"`
	City        string    `json:"city"`
	Password    string    `json:"-"`
}

type Post struct {
	ID           string `json:"id"`
	Text         string `json:"text"`
	AuthorUserID string `json:"author_user_id"`
}

type DialogMessage struct {
	From      string    `json:"from"`
	To        string    `json:"to"`
	Text      string    `json:"text"`
	Timestamp time.Time `json:"timestamp"`
}

type LoginRequest struct {
	ID       string `json:"id" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
	FirstName  string `json:"first_name" binding:"required"`
	SecondName string `json:"second_name" binding:"required"`
	Birthdate  string `json:"birthdate"`
	Biography  string `json:"biography"`
	City       string `json:"city"`
	Password   string `json:"password" binding:"required"`
}

type PostCreateRequest struct {
	Text string `json:"text" binding:"required"`
}

type PostUpdateRequest struct {
	ID   string `json:"id" binding:"required"`
	Text string `json:"text" binding:"required"`
}

type MessageSendRequest struct {
	Text string `json:"text" binding:"required"`
}

// In-memory storage with mutex
type Storage struct {
	users       map[string]*User
	posts       map[string]*Post
	friendships map[string]map[string]bool // userId -> set of friend userIds
	dialogs     map[string][]*DialogMessage // sorted userIds key -> messages
	tokens      map[string]string           // token -> userId
	mu          sync.RWMutex
}

var storage = &Storage{
	users:       make(map[string]*User),
	posts:       make(map[string]*Post),
	friendships: make(map[string]map[string]bool),
	dialogs:     make(map[string][]*DialogMessage),
	tokens:      make(map[string]string),
}

// Helper functions
func createDialogKey(userId1, userId2 string) string {
	if userId1 < userId2 {
		return userId1 + "_" + userId2
	}
	return userId2 + "_" + userId1
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Middleware
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header required"})
			c.Abort()
			return
		}

		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid authorization format"})
			c.Abort()
			return
		}

		token := tokenParts[1]
		storage.mu.RLock()
		userId, exists := storage.tokens[token]
		storage.mu.RUnlock()

		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("userId", userId)
		c.Next()
	}
}

// Auth handlers
func login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request data"})
		return
	}

	storage.mu.RLock()
	user, exists := storage.users[req.ID]
	storage.mu.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
		return
	}

	if !checkPasswordHash(req.Password, user.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid credentials"})
		return
	}

	token := uuid.New().String()
	storage.mu.Lock()
	storage.tokens[token] = req.ID
	storage.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request data"})
		return
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Server error", "code": 500})
		return
	}

	userId := uuid.New().String()
	user := &User{
		ID:          userId,
		FirstName:   req.FirstName,
		SecondName:  req.SecondName,
		Birthdate:   req.Birthdate,
		Biography:   req.Biography,
		City:        req.City,
		Password:    hashedPassword,
	}

	storage.mu.Lock()
	storage.users[userId] = user
	storage.friendships[userId] = make(map[string]bool)
	storage.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"user_id": userId})
}

// User handlers
func getUser(c *gin.Context) {
	userId := c.Param("id")

	storage.mu.RLock()
	user, exists := storage.users[userId]
	storage.mu.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func searchUsers(c *gin.Context) {
	firstName := c.Query("first_name")
	lastName := c.Query("last_name")

	if firstName == "" || lastName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Both first_name and last_name required"})
		return
	}

	var results []*User
	storage.mu.RLock()
	for _, user := range storage.users {
		firstMatch := strings.Contains(strings.ToLower(user.FirstName), strings.ToLower(firstName))
		lastMatch := strings.Contains(strings.ToLower(user.SecondName), strings.ToLower(lastName))

		if firstMatch && lastMatch {
			results = append(results, user)
		}
	}
	storage.mu.RUnlock()

	c.JSON(http.StatusOK, results)
}

// Friend handlers
func addFriend(c *gin.Context) {
	currentUserId := c.GetString("userId")
	friendUserId := c.Param("user_id")

	if currentUserId == friendUserId {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Cannot add yourself as friend"})
		return
	}

	storage.mu.RLock()
	_, friendExists := storage.users[friendUserId]
	storage.mu.RUnlock()

	if !friendExists {
		c.JSON(http.StatusBadRequest, gin.H{"message": "User not found"})
		return
	}

	storage.mu.Lock()
	if storage.friendships[currentUserId] == nil {
		storage.friendships[currentUserId] = make(map[string]bool)
	}
	storage.friendships[currentUserId][friendUserId] = true
	storage.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "Friend added successfully"})
}

func deleteFriend(c *gin.Context) {
	currentUserId := c.GetString("userId")
	friendUserId := c.Param("user_id")

	storage.mu.Lock()
	if storage.friendships[currentUserId] != nil {
		delete(storage.friendships[currentUserId], friendUserId)
	}
	storage.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "Friend removed successfully"})
}

// Post handlers
func createPost(c *gin.Context) {
	currentUserId := c.GetString("userId")
	var req PostCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request data"})
		return
	}

	postId := uuid.New().String()
	post := &Post{
		ID:           postId,
		Text:         req.Text,
		AuthorUserID: currentUserId,
	}

	storage.mu.Lock()
	storage.posts[postId] = post
	storage.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"id": postId})
}

func updatePost(c *gin.Context) {
	currentUserId := c.GetString("userId")
	var req PostUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request data"})
		return
	}

	storage.mu.Lock()
	post, exists := storage.posts[req.ID]
	if !exists {
		storage.mu.Unlock()
		c.JSON(http.StatusBadRequest, gin.H{"message": "Post not found"})
		return
	}

	if post.AuthorUserID != currentUserId {
		storage.mu.Unlock()
		c.JSON(http.StatusBadRequest, gin.H{"message": "Access denied"})
		return
	}

	post.Text = req.Text
	storage.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "Post updated successfully"})
}

func deletePost(c *gin.Context) {
	currentUserId := c.GetString("userId")
	postId := c.Param("id")

	storage.mu.Lock()
	post, exists := storage.posts[postId]
	if !exists {
		storage.mu.Unlock()
		c.JSON(http.StatusBadRequest, gin.H{"message": "Post not found"})
		return
	}

	if post.AuthorUserID != currentUserId {
		storage.mu.Unlock()
		c.JSON(http.StatusBadRequest, gin.H{"message": "Access denied"})
		return
	}

	delete(storage.posts, postId)
	storage.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "Post deleted successfully"})
}

func getPost(c *gin.Context) {
	postId := c.Param("id")

	storage.mu.RLock()
	post, exists := storage.posts[postId]
	storage.mu.RUnlock()

	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Post not found"})
		return
	}

	c.JSON(http.StatusOK, post)
}

func getFeed(c *gin.Context) {
	currentUserId := c.GetString("userId")
	
	offsetStr := c.DefaultQuery("offset", "0")
	limitStr := c.DefaultQuery("limit", "10")
	
	offset, _ := strconv.Atoi(offsetStr)
	limit, _ := strconv.Atoi(limitStr)

	storage.mu.RLock()
	friends := storage.friendships[currentUserId]
	var feedPosts []*Post
	
	for _, post := range storage.posts {
		if friends[post.AuthorUserID] {
			feedPosts = append(feedPosts, post)
		}
	}
	storage.mu.RUnlock()

	// Simple pagination
	start := offset
	end := offset + limit
	if start > len(feedPosts) {
		start = len(feedPosts)
	}
	if end > len(feedPosts) {
		end = len(feedPosts)
	}

	result := feedPosts[start:end]
	c.JSON(http.StatusOK, result)
}

// Dialog handlers
func sendMessage(c *gin.Context) {
	currentUserId := c.GetString("userId")
	toUserId := c.Param("user_id")
	
	var req MessageSendRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request data"})
		return
	}

	// Проверяем что получатель существует
	storage.mu.RLock()
	_, exists := storage.users[toUserId]
	storage.mu.RUnlock()

	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Recipient not found"})
		return
	}

	message := &DialogMessage{
		From:      currentUserId,
		To:        toUserId,
		Text:      req.Text,
		Timestamp: time.Now(),
	}

	dialogKey := createDialogKey(currentUserId, toUserId)
	
	storage.mu.Lock()
	storage.dialogs[dialogKey] = append(storage.dialogs[dialogKey], message)
	storage.mu.Unlock()

	log.Printf("Message sent from %s to %s: %s", currentUserId, toUserId, req.Text)
	c.JSON(http.StatusOK, gin.H{"message": "Message sent successfully"})
}

func getDialog(c *gin.Context) {
	currentUserId := c.GetString("userId")
	otherUserId := c.Param("user_id")

	dialogKey := createDialogKey(currentUserId, otherUserId)
	
	storage.mu.RLock()
	messages := storage.dialogs[dialogKey]
	storage.mu.RUnlock()

	if messages == nil {
		messages = []*DialogMessage{}
	}

	log.Printf("Retrieved %d messages for dialog between %s and %s", len(messages), currentUserId, otherUserId)
	c.JSON(http.StatusOK, messages)
}

func setupRoutes() *gin.Engine {
	r := gin.Default()

	// Health check
	r.GET("/health", func(c *gin.Context) {
		storage.mu.RLock()
		totalUsers := len(storage.users)
		totalPosts := len(storage.posts)
		totalDialogs := len(storage.dialogs)
		storage.mu.RUnlock()

		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"service": "monolith",
			"stats": gin.H{
				"users": totalUsers,
				"posts": totalPosts,
				"dialogs": totalDialogs,
			},
		})
	})

	// Auth routes
	r.POST("/login", login)
	r.POST("/user/register", register)

	// User routes
	r.GET("/user/get/:id", getUser)
	r.GET("/user/search", searchUsers)

	// Protected routes
	protected := r.Group("/")
	protected.Use(authMiddleware())
	{
		// Friend routes
		protected.PUT("/friend/set/:user_id", addFriend)
		protected.PUT("/friend/delete/:user_id", deleteFriend)

		// Post routes
		protected.POST("/post/create", createPost)
		protected.PUT("/post/update", updatePost)
		protected.PUT("/post/delete/:id", deletePost)
		protected.GET("/post/get/:id", getPost)
		protected.GET("/post/feed", getFeed)

		// Dialog routes - ВСЁ В МОНОЛИТЕ
		protected.POST("/dialog/:user_id/send", sendMessage)
		protected.GET("/dialog/:user_id/list", getDialog)
	}

	return r
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	r := setupRoutes()
	
	log.Printf("Monolith server starting on port %s", port)
	log.Fatal(r.Run(":" + port))
}