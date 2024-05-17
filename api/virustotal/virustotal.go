package virustotal

import (
    "io/ioutil"
    "net/url"
    "net/http"
    
    "cycarrierhw/utils/config"
)

var client *http.Client

const (
    apiurl = "https://www.virustotal.com/api/v3"
)

func init() {
    client = &http.Client{}
}

func Get(path string, data ...string) (string, error) {
    nowurl, err := url.JoinPath(apiurl, append([]string{path}, data...)...)
    if err != nil {
        return "", err
    }
    req, err := http.NewRequest("GET", nowurl, nil)
    if err != nil {
        return "", err
    }
    req.Header.Set("x-apikey", config.VirustotalAPIKey)
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

