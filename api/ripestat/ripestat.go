package ripestat

import (
    "io/ioutil"
    "net/url"
    "net/http"
)

var client *http.Client

const (
    apiurl = "https://stat.ripe.net/data"
)

func init() {
    client = &http.Client{}
}

func Get(path string, param map[string]string) (string, error) {
    nowurl, err := url.JoinPath(apiurl, path, "data.json")
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

