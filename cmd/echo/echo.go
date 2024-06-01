package main

import (
	"flag"
	"log"

	"CS544PROJECT/pkg/client"
	"CS544PROJECT/pkg/server"
)

var (
	//GENERAL PARAMETERS
	GENERATE_TLS = true
	MODE_CLIENT  = false
	MODE_SERVER  = false
	CERT_FILE    = ""
	PORT_NUMBER  = 4242

	//SERVER PARAMETERS
	SERVER_IP = ""
	KEY_FILE  = ""

	//CLIENT PARAMETERS
	SERVER_ADDR = ""
)

func processFlags() {
	cliMode := flag.Bool("client",
		MODE_CLIENT, "client mode")
	svrMode := flag.Bool("server",
		MODE_SERVER, "server mode")
	tlsMode := flag.Bool("tls-gen",
		GENERATE_TLS, "generate tls config")

	flag.StringVar(&CERT_FILE, "cert-file",
		CERT_FILE, "tls certificate file")
	flag.StringVar(&KEY_FILE, "key-file",
		KEY_FILE, "[server mode] tls key file")
	flag.StringVar(&SERVER_IP, "server-ip",
		SERVER_IP, "[server mode] tls key file")
	flag.StringVar(&SERVER_ADDR, "server-addr",
		SERVER_ADDR, "[client mode] server address")

	flag.IntVar(&PORT_NUMBER, "port",
		PORT_NUMBER, "port number")

	flag.Parse()
	MODE_CLIENT = *cliMode
	MODE_SERVER = *svrMode
	GENERATE_TLS = *tlsMode

	if !MODE_SERVER {
		//If the server wasnt selected, lets make the client the default
		MODE_CLIENT = true
	}
}

func main() {
	processFlags()

	if MODE_CLIENT {
		if SERVER_ADDR == "" {
			log.Printf("Must specify server address using server-addr flag")
			return
		}
		clientConfig := client.ClientConfig{
			ServerAddr: SERVER_ADDR,
			PortNumber: PORT_NUMBER,
			CertFile:   CERT_FILE,
		}
		client := client.NewClient(clientConfig)
		client.Run()
	} else {
		if SERVER_IP == "" {
			log.Printf("Must specify server ip using server-ip flag")
			return
		}
		serverConfig := server.ServerConfig{
			GenTLS:   GENERATE_TLS,
			CertFile: CERT_FILE,
			KeyFile:  KEY_FILE,
			Address:  SERVER_IP,
			Port:     PORT_NUMBER,
		}

		server := server.NewServer(serverConfig)
		server.Run()
	}
}
