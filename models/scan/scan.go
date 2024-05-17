package scan

import (
    "fmt"
    "net"
    "time"
)

func scanPort(protocol, hostname string, port uint16) bool {
    conn, err := net.DialTimeout(protocol, fmt.Sprintf("%s:%d", hostname, port), 1*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

func Scan(host string) map[string][]uint16 {
    result := make(map[string][]uint16)
    ports := make(chan int)
    for i := 0; i <= 1024; i++ {
        go func(port uint16) {
            if scanPort("tcp", host, port) {
                ports <- int(port)
            } else {
                ports <- -1
            }
        }(uint16(i))
    }
    for i := 0; i <= 1024; i++ {
        nowport := <- ports
        if nowport > 0 {
            result["tcp"] = append(result["tcp"], uint16(nowport))
        }
    }
    /*for i := 0; i <= 1024; i++ {
        go func(port uint16) {
            if scanPort("udp", host, port) {
                ports <- int(port)
            } else {
                ports <- -1
            }
        }(uint16(i))
    }
    for i := 0; i <= 1024; i++ {
        nowport := <- ports
        if nowport > 0 {
            result["udp"] = append(result["udp"], uint16(nowport))
        }
    }*/
    return result
}
