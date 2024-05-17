package ldap

import (
    "fmt"
    "log"
    "sync"
    "bytes"
    "strings"
    "regexp"
    "io/ioutil"

    "github.com/go-ldap/ldap/v3"
    "github.com/spf13/viper"
    //"github.com/go-errors/errors"
    
    "cycarrierhw/utils/config"
)

var Lock *sync.RWMutex
var ldapconf *viper.Viper
var db *ldap.Conn

func init() {
    ldapconfcontent, err := ioutil.ReadFile(config.LDAPConf)
    if err != nil {
        log.Fatalln(err)
    }
    ldapconf = viper.New()
    ldapconf.SetConfigType("yaml")
    ldapconf.ReadConfig(bytes.NewBuffer(ldapconfcontent))

    Lock = new(sync.RWMutex)
    Lock.Lock()
    defer Lock.Unlock()
    db, err = ldap.DialURL(ldapconf.GetString("url"))
    if err != nil {
        log.Fatalln(err)
    }
    db.Bind(ldapconf.GetString("binddn"), ldapconf.GetString("bindpasswd"))
}

func basedn() string {
    dn := strings.Split(ldapconf.GetString("binddn"), ",")
    result := []string{}
    matchdc := regexp.MustCompile(`^dc=.*$`)
    for _, now := range dn {
        if matchdc.MatchString(now) {
            result = append(result, now)
        }
    }
    return strings.Join(result, ",")
}

func Query(subdn, filter string, attributes ...string) ([]*ldap.Entry, error) {
    dn := basedn()
    if subdn != "" {
        dn = fmt.Sprintf("%s,%s", subdn, dn)
    }
    searchReq := ldap.NewSearchRequest(
        dn,
        ldap.ScopeWholeSubtree,
        ldap.NeverDerefAliases,
        0,
        0,
        false,
        filter,
        attributes,
        nil,
    )
    Lock.RLock()
    defer Lock.RUnlock()
    result, err := db.Search(searchReq)
    if err != nil {
        return nil, err
    }
    return result.Entries, nil
}
