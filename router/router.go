package router

import (
    "strings"
    "fmt"
    "flag"
    "sort"
    "golang.org/x/exp/slices"
    "github.com/StalkR/dnssec-analyzer/dnssec"
    "cycarrierhw/models/network"
    "cycarrierhw/models/domain"
    "cycarrierhw/models/crt"
)

var f *flag.FlagSet

func Usage() {
    fmt.Fprintf(f.Output(), "Usage: %s <domain or ip>\n", f.Name())
}

func Setup(name string) {
    f = flag.NewFlagSet(name, flag.ExitOnError)
    //flag
    f.Usage = Usage
}

func Run(args []string) {
    f.Parse(args)
    subargs := f.Args()
    if len(subargs) == 0 {
        subargs = append(subargs, "")
    }
    switch subargs[0] {
    default:
        run(subargs)
    }
}

func run(subargs []string) {
    if subargs[0] == "" {
        Usage()
        return
    }
    ipinfo, err := network.GetInfo(subargs[0], true)
    if err == nil {
        runip(ipinfo)
        return
    }
    dninfo, err := domain.GetInfo(subargs[0], true)
    if err != nil {
        fmt.Println(err)
        return
    }
    rundn(dninfo)
}

func runip(ipinfo network.IPInfo) {
    output := fmt.Sprintf(`IP: %s
Prefix: %s
`, ipinfo.IP.String(), ipinfo.Prefix.String())
    for _, asn := range ipinfo.ASN {
        output += fmt.Sprintf(`ASN: %d
RPKI Status: %s
`, asn.ASN, asn.RPKI)
    }
    for _, abuse := range ipinfo.Abuse {
        output += fmt.Sprintf("Abuse Contact: %s\n", abuse)
    }
    for _, report := range ipinfo.Reports {
        output += fmt.Sprintf("Abuse Report: %s %s\n", report.ReportedAt.Format("2006-01-02T15:04:05-07:00"), report.Comment)
    }
    for _, dns := range ipinfo.PassiveDNS {
        output += fmt.Sprintf("PassiveDNS: %s\n", dns)
    }
    output += "\nWeaknesses:\n"
    for _, asn := range ipinfo.ASN {
        if asn.RPKI != "valid" {
            output += fmt.Sprintf("This IP prifix RPKI Status is not 'valid' at AS%d. It means that the prefix does not have a valid cryptographic signature attesting to its authenticity and proper authorization. Without an RPKI certificate, there is no cryptographic proof of authorization, leaving the prefix vulnerable to hijacking.\n", asn.ASN)
        }
    }
    fmt.Println(output)
}

func rundn(dninfo domain.DNInfo) {
    domainmap := make(map[string]domain.DNInfo)
    usecfcdn := false
    usecfcdnleak := false
    leakdomain := make(map[string]domain.DNInfo)
    if _, exist := domainmap[dninfo.DN]; !exist {
        domainmap[dninfo.DN] = dninfo
    }
    output := fmt.Sprintf(`FQDN: %s
Domain: %s
`, dninfo.DN, dninfo.Whois.Domain.Domain)
    for _, ip := range dninfo.IPs {
        output += fmt.Sprintf("IP: %s\n", ip.IP.String())
        if slices.ContainsFunc(ip.ASN, func(asn network.ASNdata) bool {
            return asn.ASN == 13335
        }) {
            usecfcdn = true
        } else {
            usecfcdnleak = true
            if _, exist := leakdomain[dninfo.DN]; !exist {
                leakdomain[dninfo.DN] = dninfo
            }
        }
        for _, asn := range ip.ASN {
            output += fmt.Sprintf(`ASN: %d
RPKI Status: %s
`, asn.ASN, asn.RPKI)
        }
    }
    for _, ns := range dninfo.Whois.Domain.NameServers {
        output += fmt.Sprintf("Nameserver: %s\n", ns)
    }
    output += fmt.Sprintf(`Abuse Contact: %s
Registrar: %s
`, dninfo.Whois.Registrant.Email, dninfo.Whois.Registrar.Name)
    output += fmt.Sprintf("DNSSEC trace:\n%s\n", dninfo.DNSSEC)
    sort.Slice(dninfo.Status, func(i, j int) bool {
        if dninfo.Status[i].Type != dninfo.Status[j].Type {
            return dninfo.Status[i].Type == "malicious" || (dninfo.Status[i].Type == "harmless" && dninfo.Status[j].Type == "undetected")
        } else if dninfo.Status[i].Data != dninfo.Status[j].Data {
            return strings.Compare(dninfo.Status[i].Data, dninfo.Status[j].Data) < 0
        }
        return strings.Compare(dninfo.Status[i].Name, dninfo.Status[j].Name) < 0
    })
    output += "Security vendors' analysis:\n"
    for _, status := range dninfo.Status {
        output += fmt.Sprintf("%s: %s\n", status.Name, status.Data)
    }
    output += "\n"
    for _, dns := range dninfo.PassiveDNS {
        if _, exist := domainmap[dns.DN]; !exist {
            domainmap[dns.DN] = dns
        }
        output += fmt.Sprintf("PassiveDNS: %s\n", dns.DN)
        for _, ip := range dns.IPs {
            output += fmt.Sprintf("IP: %s\n", ip.IP.String())
            if !slices.ContainsFunc(ip.ASN, func(asn network.ASNdata) bool {
                return asn.ASN == 13335
            }) {
                usecfcdnleak = true
                if _, exist := leakdomain[dns.DN]; !exist {
                    leakdomain[dns.DN] = dns
                }
            }
            for _, asn := range ip.ASN {
                output += fmt.Sprintf(`ASN: %d
RPKI Status: %s
`, asn.ASN, asn.RPKI)
            }
        }
    }
    output += "\n"
    output += "Certificats:\n"
    certs, _ := crt.GetInfo(dninfo.DN, 5)
    for _, cert := range certs {
        if cert == nil {
            continue
        }
        output += fmt.Sprintf(`Issuer: %s
Subject: %s
Not Before: %s
Not After: %s
`, cert.Issuer, cert.Subject, cert.NotBefore, cert.NotAfter)
        for _, dnsName := range cert.DNSNames {
            output += fmt.Sprintf("DNS Name: %s\n", dnsName)
            if !strings.Contains(dnsName, "*") {
                if _, exist := domainmap[dnsName]; !exist {
                    dns, err := domain.GetInfo(dnsName, false)
                    if err == nil {
                        domainmap[dnsName] = dns
                    }
                }
                for _, ip := range domainmap[dnsName].IPs {
                    output += fmt.Sprintf("IP: %s\n", ip.IP.String())
                    if !slices.ContainsFunc(ip.ASN, func(asn network.ASNdata) bool {
                        return asn.ASN == 13335
                    }) {
                        usecfcdnleak = true
                        if _, exist := leakdomain[dnsName]; !exist {
                            leakdomain[dnsName] = domainmap[dnsName]
                        }
                    }
                    for _, asn := range ip.ASN {
                        output += fmt.Sprintf(`ASN: %d
RPKI Status: %s
`, asn.ASN, asn.RPKI)
                    }
                }
            }
        }
    }
    output += "\nWeaknesses:\n"
    if usecfcdn && usecfcdnleak {
        output += "Your original IP address will be leak by these domain names when you using Cloudflare CDN. Please check it:\n"
        for dn, info := range leakdomain {
            output += fmt.Sprintf("Domain: %s\n", dn)
            for _, ip := range info.IPs {
                if !slices.ContainsFunc(ip.ASN, func(asn network.ASNdata) bool {
                    return asn.ASN == 13335
                }) {
                    output += fmt.Sprintf("Leak IP: %s\n", ip.IP.String())
                }
            }
        }
        output += "\n"
    }
    if slices.ContainsFunc(dninfo.DNSSEC, func(dn dnssec.Domain) bool {
        return slices.ContainsFunc(dn.Results, func(result dnssec.Result) bool {
            return result.Status != dnssec.OK
        })
    }) {
        output += "Dnssec tracing got some waring or error that mean your dnssec setting is not completely. This will put the domain at risk of DNS pollution.\n"
        for _, dn := range dninfo.DNSSEC {
            if slices.ContainsFunc(dn.Results, func(result dnssec.Result) bool {
                return result.Status != dnssec.OK
            }) {
                output += fmt.Sprintf("# %s\n", dn.Name)
            }
            for _, result := range dn.Results {
                if result.Status != dnssec.OK {
                    output += fmt.Sprintf("%s: %s\n", result.Status.String(), result.Details)
                }
            }
        }
        output += "\n"
    }
    fmt.Println(output)
}


