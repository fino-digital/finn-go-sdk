package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

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
	"dev": "https://dashboard-dev.hellofinn.de/api/v0"}

var helloFinnRoutePing = "/ping"
var helloFinnRoutePartner = "/partner"

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
		log.Println("ERROR: please use -name <name> -country <country> -state <state> -location <location> -email <email>")
		return
	}

	// check environment
	URL := URLs["prod"]
	if *env != "" {
		URL = URLs[*env]
		if URL == "" {
			log.Println("please use for -env: dev, testing or prod. Nothing is prod!")
			return
		}
	}
	// if env == dev -> ask user for password
	header := http.Header{}
	if *env == "dev" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Environment 'dev' is for hellofinn-staff only.\nPlease enter passphrase: ")
		passphrase, _ := reader.ReadString('\n')
		hasher := sha256.New()
		hasher.Write([]byte(passphrase))
		header.Add("X-HelloFinn-Admin", base64.URLEncoding.EncodeToString([]byte(hex.EncodeToString(hasher.Sum(nil)))))
	}

	// check if hellofinn.de is accessible
	pingRequest, _ := http.NewRequest("GET", URL+helloFinnRoutePing, nil)
	pingResponse, err := (&http.Client{}).Do(pingRequest)
	if err != nil || pingResponse.StatusCode != 200 {
		log.Println("ERROR: There is something wrong. Check your internet-connection..")
		if pingResponse != nil {
			defer pingResponse.Body.Close()
			pingResponseBody, _ := ioutil.ReadAll(pingResponse.Body)
			log.Println("Failure:", pingResponse.StatusCode, "-", string(pingResponseBody))
		}
		return
	}

	// build request to register
	partnerData := PartnerData{
		Name:     *name,
		Country:  *country,
		State:    *state,
		Location: *location,
		Email:    *email,
	}
	partnerDataByte, _ := json.Marshal(partnerData)

	// fire up request
	registerRequest, _ := http.NewRequest("POST", URL+helloFinnRoutePartner, bytes.NewReader(partnerDataByte))
	registerRequest.Header = header
	registerResponse, err := (&http.Client{}).Do(registerRequest)
	if err != nil || registerResponse.StatusCode != 200 {
		defer registerResponse.Body.Close()
		registerResponseBody, _ := ioutil.ReadAll(registerResponse.Body)
		log.Println("ERROR: Something is going wrong. Failure:", registerResponse.StatusCode, "-", string(registerResponseBody))
		return
	}

	// try to get userID
	defer registerResponse.Body.Close()
	registerResponseBody, _ := ioutil.ReadAll(registerResponse.Body)
	jsonParsed, err := gabs.ParseJSON(registerResponseBody)
	partnerID, ok := jsonParsed.Path("data.id").Data().(string)
	if err != nil || !ok {
		log.Println("ERROR: Failure while parsing responseBody:", registerResponse.StatusCode, "-", string(registerResponseBody))
	}
	log.Println("Your partnerID:", partnerID)

	log.Println("SUCCESSFUL")
}
