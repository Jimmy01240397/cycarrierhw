package config

import (
    "os"
    "strconv"
)

var Debug bool
var VirustotalAPIKey string
var AbuseIPDB string

func init() {
    loadenv()
    var err error
    debugstr, exists := os.LookupEnv("DEBUG")
    if !exists {
        Debug = false
    } else {
        Debug, err = strconv.ParseBool(debugstr)
        if err != nil {
            Debug = false
        }
    }
    VirustotalAPIKey = os.Getenv("VIRUSTOTALAPIKEY")
    AbuseIPDB = os.Getenv("ABUSEIPDB")
}
