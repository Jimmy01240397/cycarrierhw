package crt

import (
    "fmt"
//    "time"
//    "net"
    "strings"
    "html"
    "sort"
//    "crypto/tls"
    "crypto/x509"
    "encoding/pem"
    "encoding/xml"

    "cycarrierhw/api/crt"
)

type feed struct {
    XMLName xml.Name `xml:"feed"`
    Entries []entry  `xml:"entry"`
}

type entry struct {
    XMLName xml.Name `xml:"entry"`
    Summary summary  `xml:"summary"`
}

type summary struct {
    XMLName xml.Name `xml:"summary"`
    Content string   `xml:",innerxml"`
}

func getCertificate(data string) ([]*x509.Certificate, error) {
    var feeddata feed
    err := xml.Unmarshal([]byte(data), &feeddata)
    if err != nil {
        return nil, err
    }

    certs := make([]*x509.Certificate, len(feeddata.Entries))

    for idx, entry := range feeddata.Entries {
        certstr := strings.Replace(html.UnescapeString(extractCert(entry.Summary.Content)), "<br>", "\n", -1)
        block, _ := pem.Decode([]byte(certstr))
        if block == nil {
            certs[idx] = nil
            continue
        }
        cert, err := x509.ParseCertificate(block.Bytes)
        if err != nil {
            certs[idx] = nil
            continue
        }
        certs[idx] = cert
        //printCert(cert)
    }
    return certs, nil
}

func extractCert(summary string) string {
    start := "-----BEGIN CERTIFICATE-----"
    end := "-----END CERTIFICATE-----"
    startIdx := strings.Index(summary, start)
    endIdx := strings.Index(summary, end)
    if startIdx == -1 || endIdx == -1 {
        return ""
    }
    endIdx += len(end)
    return summary[startIdx:endIdx]
}


func printCert(cert *x509.Certificate) {
    if cert == nil {
        return
    }
    output := fmt.Sprintf(`Issuer: %s
Subject: %s
Not Before: %s
Not After: %s
`, cert.Issuer, cert.Subject, cert.NotBefore, cert.NotAfter)
    for _, dnsName := range cert.DNSNames {
        output += fmt.Sprintf("DNS Name: %s\n", dnsName)
    }
    fmt.Println(output)
}

func GetInfo(domain string, limit int) (certs []*x509.Certificate, err error) {
    var data string
    
    data, err = crt.Get("atom", map[string]string{"q": domain})
    if err != nil {
        return
    }
    certs, err = getCertificate(data)
    if err != nil {
        return
    }
    
    var tmp []*x509.Certificate
    data, err = crt.Get("atom", map[string]string{"q": strings.Join(append([]string{"*"}, strings.Split(domain, ".")[1:]...), ".")})
    if err != nil {
        return
    }
    tmp, err = getCertificate(data)
    if err != nil {
        return
    }
    certs = append(certs, tmp...)
    sort.Slice(certs, func(i, j int) bool {
        return certs[i].NotAfter.After(certs[j].NotAfter)
    })
    return
}
