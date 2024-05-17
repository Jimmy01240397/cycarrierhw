package crt

import (
    "encoding/base64"
    "crypto/rand"
    "io/ioutil"
    "net/url"
    "net/http"
)

var client *http.Client

const (
    apiurl = "https://crt.sh/"
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
    q := req.URL.Query()
    for key, val := range param {
        q.Add(key, val)
    }
    req.URL.RawQuery = q.Encode()
    buf := make([]byte, 12)
    rand.Read(buf)
    req.Header.Set("User-Agent", base64.StdEncoding.EncodeToString(buf))
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

