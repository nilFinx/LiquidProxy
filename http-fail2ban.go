package main

import (
	"log"
	"strings"
)

var f2bIPList = make(map[string]int)
var bannedIPList []string

func addFailedIP(ipmash string) {
	ip := unmashIP(ipmash)
	f2bIPList[ip] += 1
	if f2bIPList[ip] >= *fail2banOn {
		bannedIPList = append(bannedIPList, ip)
		log.Printf("[%s] Banned", ip)
	}
}

func isIPBanned(ipmash string) (banned bool) {
	ip := unmashIP(ipmash)
	for _, banned := range bannedIPList {
		if ip == banned {
			return true
		}
	}
	return false
}

func unmashIP(ipmash string) (ip string) {
	ip, _, _ = strings.Cut(ipmash, ":")
	return ip
}
