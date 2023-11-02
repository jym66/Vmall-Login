package main

import (
	"VmallSeckill/login"
	"log"
)

func main() {
	log.SetFlags(log.Llongfile | log.Lmicroseconds | log.Ldate)
	client := login.NewHttpClient()
	client.LoginByQrcode()
}
