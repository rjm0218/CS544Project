package server

import (
	"fmt"
	"sync"
	"time"
)

type User struct {
	Username    string
	Password    string
	Permissions []string
}

var users = map[string]*User{
	"user1": {Username: "user1", Password: "password1!", Permissions: []string{"upload", "download"}},
	"user2": {Username: "user2", Password: "password2!", Permissions: []string{"download"}},
}

var sessions = make(map[string]*User)
var sessionMutex sync.Mutex

func authenticateUser(username, password string) (*User, bool) {
	storedUser, ok := users[username]
	if !ok || storedUser.Password != password {
		return nil, false
	}
	return storedUser, true
}

func authorizeUser(user *User, permission string) bool {
	for _, p := range user.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

func createSession(user *User) string {
	sessionToken := fmt.Sprintf("%d", time.Now().UnixNano())
	sessionMutex.Lock()
	sessions[sessionToken] = user
	sessionMutex.Unlock()
	return sessionToken
}

func getSession(token string) (*User, bool) {
	sessionMutex.Lock()
	user, exists := sessions[token]
	sessionMutex.Unlock()
	return user, exists
}

func deleteSession(token string) {
	sessionMutex.Lock()
	delete(sessions, token)
	sessionMutex.Unlock()
}
