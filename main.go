package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log"
	mrand "math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"github.com/labstack/echo"
	"github.com/labstack/echo/engine/standard"
	"github.com/labstack/echo/middleware"
	"golang.org/x/crypto/scrypt"
)

const (
	chars      string = "abcdefghijklmnopqrstuvwxyz0123456789"
	emailRegEx string = "^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$"
)

//https://chart.googleapis.com/chart?chs=150x150&cht=qr&chl=cool&choe=UTF-8

var (
	rxEmail = regexp.MustCompile(emailRegEx)
)

type appResponse struct {
	Message         string `json:"message"`
	SharedSecretKey string `json:"key"`
	Status          string `json:"status"`
}

type inputUser struct {
	Name     string `json:"name" form:"name"`
	Email    string `json:"email" form:"email"`
	Password string `json:"password" form:"password"`
}

// User is app user
type User struct {
	Name            string `json:"name" form:"name"`
	Email           string `json:"email" form:"email"`
	Password        []byte
	Salt            []byte
	SharedSecretKey string
}

func main() {
	port := os.Getenv("PORT")
	//database
	db, err := bolt.Open("appy.db", 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("Users"))
		return err
	})

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.Gzip())

	e.Post("/user", func(c echo.Context) error {
		u := new(inputUser)
		if err := c.Bind(u); err != nil {
			return err
		}
		salt := make([]byte, 32)
		_, err := io.ReadFull(rand.Reader, salt)
		if err != nil {
			log.Fatal(err)
		}
		println(u.Email)
		//validate data
		name := strings.Trim(u.Name, " ")
		email := strings.Trim(strings.ToLower(u.Email), " ")
		password := strings.Trim(u.Password, " ")
		existingUser, err := exists(db, email)

		if isEmail(email) && len(password) >= 6 && err == nil {
			//check for password validation
			hash, _ := scrypt.Key([]byte(password), existingUser.Salt, 16384, 8, 1, 32)
			if bytes.Equal(hash, existingUser.Password) {
				c.JSON(http.StatusBadRequest, &appResponse{"User logged in, please use key to connect", existingUser.SharedSecretKey, "success"})

				return nil
			}
		}
		if (isEmail(email) && len(password) >= 6 && len(name) >= 6) == false {
			c.JSON(http.StatusBadRequest, &appResponse{"Please provide valid details", "", "error"})
			return nil
		}
		hash, _ := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
		sharedSecretKey := randomString(12)

		user := User{
			Name:            name,
			Email:           email,
			Password:        hash,
			Salt:            salt,
			SharedSecretKey: sharedSecretKey,
		}
		err = user.save(db)
		if err != nil {
			c.JSON(http.StatusBadRequest, &appResponse{"Please provide valid details", "", "error"})
		} else {
			c.JSON(http.StatusBadRequest, &appResponse{"User created, please use key to connect", sharedSecretKey, "success"})
		}

		return nil
	})

	e.Run(standard.New(":" + port))

}

func exists(db *bolt.DB, email string) (User, error) {
	appUser := User{}
	userExistsErr := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("Users"))
		v := b.Get([]byte(email))
		if v != nil {
			return json.Unmarshal(v, &appUser)
		}

		return errors.New("Key does not exists in Users")
	})

	if userExistsErr == nil {
		return appUser, nil
	}

	return appUser, userExistsErr
}

func (user *User) save(db *bolt.DB) error {
	// Store the user model in the user bucket using the username as the key.
	err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("Users"))
		if err != nil {
			return err
		}

		encoded, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return b.Put([]byte(user.Email), encoded)
	})

	return err
}

func isEmail(str string) bool {
	// TODO uppercase letters are not supported
	return rxEmail.MatchString(str)
}

func randomString(strlen int) string {
	mrand.Seed(time.Now().UTC().UnixNano())
	result := make([]byte, strlen)
	for i := 0; i < strlen; i++ {
		result[i] = chars[mrand.Intn(len(chars))]
	}
	return string(result)
}
