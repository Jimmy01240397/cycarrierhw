package abuseipdb

import (
    "io/ioutil"
    "net/url"
    "net/http"

    "cycarrierhw/utils/config"
)

var client *http.Client

const (
    apiurl = "https://api.abuseipdb.com/api/v2"
)

func init() {
    client = &http.Client{}
}

func Get(path string, param map[string]string) (string, error) {
    nowurl, err := url.JoinPath(apiurl, path)
    if err != nil {
        return "", err
    }
    req, err := http.NewRequest("GET", nowurl, nil)
    if err != nil {
        return "", err
    }

    req.Header.Set("Key", config.AbuseIPDB)
    q := req.URL.Query()
    for key, val := range param {
        q.Add(key, val)
    }
    req.URL.RawQuery = q.Encode()
    res, err := client.Do(req)
    if err != nil {
        return "", err
    }
    defer res.Body.Close()
    result, err := ioutil.ReadAll(res.Body)
    if err != nil {
        return "", err
    }
    return string(result), nil
}

