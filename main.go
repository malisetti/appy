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
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"github.com/labstack/echo"
	"github.com/labstack/echo/engine/standard"
	"github.com/labstack/echo/middleware"
	"golang.org/x/crypto/scrypt"
)

const (
	chars              string = "abcdefghijklmnopqrstuvwxyz0123456789"
	emailRegEx         string = "^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$"
	usersBucket        string = "users"
	sharedKeysBucket   string = "shared_keys"
	database           string = "appy.db"
	couchbaseAdminAPI  string = "http://127.0.0.1:4985"
	couchbaseAdminUser string = "appyadmin"
	couchbaseAdminPass string = "appyadmin"
)

//https://chart.googleapis.com/chart?chs=150x150&cht=qr&chl=cool&choe=UTF-8

var (
	rxEmail = regexp.MustCompile(emailRegEx)
)

type cbUser struct {
	Name          string   `json:"name"`
	Password      string   `json:"password"`
	AdminChannels []string `json:"admin_channels"`
}

type appResponse struct {
	Message         string `json:"message"`
	SharedSecretKey string `json:"key"`
	Status          string `json:"status"`
}

type userResponse struct {
	Message    string     `json:"message"`
	OutputUser outputUser `json:"user"`
	Status     string     `json:"status"`
}

//InputUser is to bind the user creation request
type InputUser struct {
	Name     string `json:"name" form:"name"`
	Email    string `json:"email" form:"email"`
	Password string `json:"password" form:"password"`
}

type outputUser struct {
	Name            string `json:"name"`
	Email           string `json:"email"`
	SharedSecretKey string `json:"key"`
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

	if port == "" {
		panic("Please provide a proper port")
	}

	//database
	db, err := bolt.Open(database, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.Update(func(tx *bolt.Tx) error {
		tx.CreateBucketIfNotExists([]byte(usersBucket))
		tx.CreateBucketIfNotExists([]byte(sharedKeysBucket))

		return nil
	})

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.Gzip())

	e.Get("/users/:sharedKey", func(c echo.Context) error {
		sharedKey := c.Param("sharedKey")
		u := outputUser{}
		existsErr := db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(sharedKeysBucket))
			v := b.Get([]byte(sharedKey))

			if v != nil {
				b2 := tx.Bucket([]byte(usersBucket))
				v2 := b2.Get(v)
				if v2 != nil {
					appUser := User{}
					err := json.Unmarshal(v2, &appUser)

					if err == nil {
						u.Email = appUser.Email
						u.Name = appUser.Name
						u.SharedSecretKey = appUser.SharedSecretKey

						return nil
					}

					return err
				}

				return errors.New("Key could not be found")
			}

			return errors.New("Key could not be found")
		})

		if existsErr != nil {
			c.JSON(http.StatusNotFound, &userResponse{existsErr.Error(), u, "error"})
		} else {
			c.JSON(http.StatusOK, &userResponse{"Please see the user details", u, "success"})
		}

		return nil
	})

	e.Post("/users", func(c echo.Context) error {
		var u InputUser
		ct := c.Request().Header().Get("Content-Type")
		if ct == "application/json" {
			decoder := json.NewDecoder(c.Request().Body())
			err := decoder.Decode(&u)
			if err != nil {
				return err
			}
		} else {
			if err := c.Bind(u); err != nil {
				return err
			}
		}

		salt := make([]byte, 32)
		_, err := io.ReadFull(rand.Reader, salt)
		if err != nil {
			return err
		}

		//validate data
		name := strings.Trim(u.Name, " ")
		email := strings.Trim(strings.ToLower(u.Email), " ")
		password := strings.Trim(u.Password, " ")
		existingUser, err := exists(db, email)

		if isEmail(email) && len(password) >= 6 && err == nil {
			//check for password validation
			hash, _ := scrypt.Key([]byte(password), existingUser.Salt, 16384, 8, 1, 32)
			if bytes.Equal(hash, existingUser.Password) {
				c.JSON(http.StatusOK, &appResponse{"User logged in, please use key to connect", existingUser.SharedSecretKey, "success"})

				return nil
			}
		}
		if (isEmail(email) && len(password) >= 6 && len(name) >= 6) == false {
			c.JSON(http.StatusBadRequest, &appResponse{"Please provide valid details, proper email, name and password should be more than 6 chars", "", "error"})

			return nil
		}

		hash, _ := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
		sharedSecretKey := newSharedKey(db, 12, email)

		user := User{
			Name:            name,
			Email:           email,
			Password:        hash,
			Salt:            salt,
			SharedSecretKey: sharedSecretKey,
		}
		err = user.save(db)
		if err != nil {
			c.JSON(http.StatusOK, &appResponse{"Please provide valid details", "", "error"})
		} else {
			adminChannels := []string{email, sharedSecretKey}
			couchbaseUsers := [2]map[string]string{{"email": email, "password": password}, {"email": sharedSecretKey, "password": sharedSecretKey}}
			var wg sync.WaitGroup
			wg.Add(len(couchbaseUsers))
			for _, cbUser := range couchbaseUsers {
				go func(email, password string, adminChannels []string) {
					err := createCouchbaseUser(email, password, adminChannels)
					if err != nil {
						c.Logger().Error(err.Error())
					}
					wg.Done()
				}(cbUser["email"], cbUser["password"], adminChannels)
			}
			wg.Wait()

			c.JSON(http.StatusCreated, &appResponse{"User created, please use key to connect", sharedSecretKey, "success"})
		}

		return nil
	})

	e.Run(standard.New(":" + port))

}

func exists(db *bolt.DB, email string) (User, error) {
	appUser := User{}
	existsErr := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucket))
		v := b.Get([]byte(email))
		if v != nil {
			return json.Unmarshal(v, &appUser)
		}

		return errors.New("Key does not exists in Users")
	})

	if existsErr == nil {
		return appUser, nil
	}

	return appUser, existsErr
}

func keyExists(db *bolt.DB, bucket string, key string) bool {
	existsErr := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		v := b.Get([]byte(key))

		if v != nil {
			return nil
		}

		return errors.New("Key does not exist")
	})

	if existsErr == nil {
		return true
	}

	return false
}

func (user *User) save(db *bolt.DB) error {
	// Store the user model in the user bucket using the username as the key.
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucket))

		encoded, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return b.Put([]byte(user.Email), encoded)
	})

	return err
}

func deleteKey(db *bolt.DB, bucket, key string) error {
	// Store the user model in the user bucket using the username as the key.
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))

		return b.Delete([]byte(key))
	})

	return err
}

func createCouchbaseUser(email, password string, adminChannels []string) error {
	userCreationURL := couchbaseAdminAPI + "/appydb/_user/"
	timeout := time.Duration(1 * time.Second)
	client := &http.Client{
		Timeout: timeout,
	}
	data, _ := json.Marshal(cbUser{email, password, adminChannels})
	req, err := http.NewRequest(http.MethodPost, userCreationURL, bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(couchbaseAdminUser, couchbaseAdminPass)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusConflict:
		return errors.New("A user with this name already exists")
	default:
		return nil
	}
}

func isEmail(str string) bool {
	// TODO uppercase letters are not supported
	return rxEmail.MatchString(str)
}

func newSharedKey(db *bolt.DB, strlen int, email string) string {
	rstr := randomString(strlen)
	if keyExists(db, sharedKeysBucket, rstr) {
		return newSharedKey(db, strlen, email)
	}

	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(sharedKeysBucket))

		return b.Put([]byte(rstr), []byte(email))
	})

	if err != nil {
		return newSharedKey(db, strlen, email)
	}

	return rstr
}

func randomString(strlen int) string {
	mrand.Seed(time.Now().UTC().UnixNano())
	result := make([]byte, strlen)
	for i := 0; i < strlen; i++ {
		result[i] = chars[mrand.Intn(len(chars))]
	}

	return string(result)
}
