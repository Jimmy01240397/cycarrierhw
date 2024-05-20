package network

import (
    "time"

    netaddr "github.com/dspinhirne/netaddr-go"
    "github.com/tidwall/gjson"

    "cycarrierhw/api/ripestat"
    "cycarrierhw/api/abuseipdb"
    "cycarrierhw/api/virustotal"
)

type IPInfo struct {
    IP netaddr.IP
    Prefix netaddr.IPNet
    ASN []ASNdata
    Abuse []string
    Reports []report
    PassiveDNS []string
}

type ASNdata struct {
    ASN uint64
    RPKI string
}

type report struct {
    ReportedAt time.Time
    Comment string
}

func GetInfo(ip string, fulldata bool) (ipinfo IPInfo, err error) {
    ipinfo.IP, err = netaddr.ParseIP(ip)
    if err != nil {
        return
    }
    var data string
    data, err = ripestat.Get("network-info", map[string]string{"resource": ipinfo.IP.String()})
    if err != nil {
        return
    }
    ipinfo.Prefix, err = netaddr.ParseIPNet(gjson.Get(data, "data.prefix").String())
    if err != nil {
        if ipinfo.IP.Version() == 4 {
            ipinfo.Prefix = ipinfo.IP.(*netaddr.IPv4).ToNet()
        } else if ipinfo.IP.Version() == 6 {
            ipinfo.Prefix = ipinfo.IP.(*netaddr.IPv6).ToNet()
        }
    }
    asns := gjson.Get(data, "data.asns").Array()
    ipinfo.ASN = make([]ASNdata, len(asns))
    for idx, asn := range asns {
        ipinfo.ASN[idx].ASN = asn.Uint()
        data, err = ripestat.Get("rpki-validation", map[string]string{"resource": asn.String(), "prefix": ipinfo.Prefix.String()})
        if err != nil {
            ipinfo.ASN[idx].RPKI = "unknown"
            continue
        }
        ipinfo.ASN[idx].RPKI = gjson.Get(data, "data.status").String()
    }
    data, err = ripestat.Get("abuse-contact-finder", map[string]string{"resource": ipinfo.IP.String()})
    if err != nil {
        return
    }
    abuses := gjson.Get(data, "data.abuse_contacts").Array()
    ipinfo.Abuse = make([]string, len(abuses))
    for idx, abuse := range abuses {
        ipinfo.Abuse[idx] = abuse.String()
    }


    if fulldata {
        data, err = abuseipdb.Get("check", map[string]string{
            "ipAddress": ipinfo.IP.String(),
            "maxAgeInDays": "90",
            "verbose": "",
        })
        if err != nil {
            return
        }
        reports := gjson.Get(data, "data.reports").Array()
        ipinfo.Reports = make([]report, len(reports))
        for idx, report := range reports {
            ipinfo.Reports[idx].ReportedAt, err = time.Parse("2006-01-02T15:04:05-07:00" ,report.Get("reportedAt").String())
            if err != nil {
                return
            }
            ipinfo.Reports[idx].Comment = report.Get("comment").String()
        }
        data, err = virustotal.Get("ip_addresses", ipinfo.IP.String(), "resolutions")
        if err != nil {
            return
        }
        dns := gjson.Get(data, "data").Array()
        ipinfo.PassiveDNS = make([]string, len(dns))
        for idx, dn := range dns {
            ipinfo.PassiveDNS[idx] = dn.Get("attributes.host_name").String()
        }
    }
    return
}
