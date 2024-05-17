package domain

import (
    "strings"
    "net"

    "github.com/tidwall/gjson"
    "cycarrierhw/api/virustotal"
    "github.com/likexian/whois"
    "github.com/likexian/whois-parser"
    "github.com/StalkR/dnssec-analyzer/dnssec"

    "cycarrierhw/models/network"
)

type DNInfo struct {
    DN string
    IPs []network.IPInfo
    Whois whoisparser.WhoisInfo
    DNSSEC dnssec.Analysis
    Status []statusdata
    PassiveDNS []DNInfo
}

type statusdata struct {
    Name string
    Type string
    Data string
}

func GetInfo(domain string, fulldata bool) (dninfo DNInfo, err error) {
    dninfo.DN = domain
    var data string

    ips, err := net.LookupIP(domain)
    if err != nil {
        return
    }
    dninfo.IPs = make([]network.IPInfo, len(ips))
    for idx, ip := range ips {
        dninfo.IPs[idx], err = network.GetInfo(ip.String(), false)
    }

    if fulldata {
        domainpart := strings.Split(domain, ".")
        for i, _ := range domainpart {
            data, err = whois.Whois(strings.Join(domainpart[i:len(domainpart)], "."))
            if err == nil {
                dninfo.Whois, err = whoisparser.Parse(data)
                if err == nil {
                    break
                }
            }
        }
        dninfo.DNSSEC, err = dnssec.Analyze(domain)
        if err != nil {
            return
        }
        data, err = virustotal.Get("domains", domain)
        if err != nil {
            return
        }
        status := gjson.Get(data, "data.attributes.last_analysis_results").Map()
        dninfo.Status = make([]statusdata, len(status))
        statusidx := 0
        for key, val := range status {
            dninfo.Status[statusidx] = statusdata{
                Name: key,
                Type: val.Get("category").String(),
                Data: val.Get("result").String(),
            }
            statusidx++
        }
        data, err = virustotal.Get("domains", domain, "siblings")
        if err != nil {
            return
        }
        dns := gjson.Get(data, "data").Array()
        data, err = virustotal.Get("domains", domain, "subdomains")
        if err != nil {
            return
        }
        dns = append(dns, gjson.Get(data, "data").Array()...)
        dninfo.PassiveDNS = make([]DNInfo, len(dns))
        for idx, dn := range dns {
            dninfo.PassiveDNS[idx], _ = GetInfo(dn.Get("id").String(), false)
        }
    }
    return
}
