package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"

	"golang.org/x/crypto/ssh/terminal"

	"crypto/sha256"

	"encoding/base64"

	"encoding/hex"

	"github.com/Jeffail/gabs"
)

// URLs to helloFinn
var URLs = map[string]string{
	"testing": "https://dashboard-testing.hellofinn.de/api/v0",
	"prod":    "https://dashboard.hellofinn.de/api/v0",
	// only for staff
	"dev":   "https://dashboard-dev.hellofinn.de/api/v0",
	"local": "http://localhost:8080/api/v0"}

var helloFinnRoutePing = "/ping"
var helloFinnRoutePartner = "/partner"
var helloFinnRouteLogin = "/login"

type PartnerData struct {
	Name     string `json:"name"`
	Country  string `json:"country"`
	State    string `json:"state"`
	Location string `json:"location"`
	Email    string `json:"email"`
}

// 1. collect all informations via flags
// 2. check if hellofinn.de-dashboard is accessible
// 3. fire up register-request
// 4. extract userID and print to console
func main() {
	// collect all flags
	name := flag.String("name", "", "name")
	country := flag.String("country", "", "country")
	state := flag.String("state", "", "state")
	location := flag.String("location", "", "location")
	email := flag.String("email", "", "email")
	env := flag.String("env", "", "environment")
	flag.Parse()

	// check if flags are complete
	if *name == "" || *country == "" || *state == "" || *location == "" || *email == "" {
		panic("ERROR: please use -name <name> -country <country> -state <state> -location <location> -email <email>")
	}

	// build request to register
	partnerData := PartnerData{
		Name:     *name,
		Country:  *country,
		State:    *state,
		Location: *location,
		Email:    *email,
	}

	// check environment
	URL := URLs["prod"]
	if *env != "" {
		URL = URLs[*env]
		if URL == "" {
			panic("please use for -env: dev, testing or prod. Nothing is prod!")
		}
	}
	// if env == dev -> ask user for password
	header := http.Header{}
	if *env == "dev" {
		log.Println("Environment 'dev' is for hellofinn-staff only. Please enter passphrase: ")
		passphrase, _ := terminal.ReadPassword(0)
		hasher := sha256.New()
		hasher.Write(passphrase)
		header.Add("X-HelloFinn-Admin", base64.URLEncoding.EncodeToString([]byte(hex.EncodeToString(hasher.Sum(nil)))))
	}

	// check if hellofinn.de is accessible
	helloFinnServerCheck(URL)

	// register
	partnerID, password := register(URL, partnerData, header)
	log.Println("Your partnerID:", partnerID)
	log.Println("Your password:", password)

	// login
	login(URL, *email, password, &header)

	log.Println("SUCCESSFUL")
}

// check if hellofinn.de is accessible
func helloFinnServerCheck(URL string) {
	pingRequest, _ := http.NewRequest("GET", URL+helloFinnRoutePing, nil)
	pingResponse, err := (&http.Client{}).Do(pingRequest)
	if err != nil || pingResponse.StatusCode != 200 {
		if pingResponse != nil {
			defer pingResponse.Body.Close()
			pingResponseBody, _ := ioutil.ReadAll(pingResponse.Body)
			log.Println("Failure:", pingResponse.StatusCode, "-", string(pingResponseBody))
		}
		panic("ERROR: There is something wrong. Check your internet-connection..")
	}
}

func register(URL string, partnerData PartnerData, header http.Header) (string, string) {
	partnerDataByte, _ := json.Marshal(partnerData)

	// fire up request
	registerRequest, _ := http.NewRequest("POST", URL+helloFinnRoutePartner, bytes.NewReader(partnerDataByte))
	registerRequest.Header = header
	registerResponse, err := (&http.Client{}).Do(registerRequest)
	if err != nil || registerResponse.StatusCode != 200 {
		defer registerResponse.Body.Close()
		registerResponseBody, _ := ioutil.ReadAll(registerResponse.Body)
		panic("ERROR: Something is going wrong. Failure: " + string(registerResponse.StatusCode) + " - " + string(registerResponseBody))
	}

	// try to get userID
	defer registerResponse.Body.Close()
	registerResponseBody, _ := ioutil.ReadAll(registerResponse.Body)
	jsonParsed, err := gabs.ParseJSON(registerResponseBody)
	partnerID, ok := jsonParsed.Path("data.id").Data().(string)
	password, ok := jsonParsed.Path("data.password").Data().(string)
	if err != nil || !ok {
		panic("ERROR: Failure while parsing responseBody: " + string(registerResponse.StatusCode) + " - " + string(registerResponseBody))
	}

	return partnerID, password
}

func login(URL string, email string, password string, header *http.Header) {
	loginRequestBytes, _ := json.Marshal(map[string]string{"email": email, "password": password})
	loginRequest, _ := http.NewRequest("POST", URL+helloFinnRouteLogin, bytes.NewReader(loginRequestBytes))
	loginResponse, err := (&http.Client{}).Do(loginRequest)
	if err != nil || loginResponse.StatusCode != 200 {
		if loginResponse != nil {
			defer loginResponse.Body.Close()
			loginResponseBody, _ := ioutil.ReadAll(loginResponse.Body)
			log.Println("Failure:", loginResponse.StatusCode, "-", string(loginResponseBody))
		}
		panic("ERROR: There is something wrong with login..")
	}

	// try to get headers
	defer loginResponse.Body.Close()
	loginResponseBody, _ := ioutil.ReadAll(loginResponse.Body)
	log.Println(string(loginResponseBody))
}
