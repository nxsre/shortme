package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nxsre/shortme/conf"
	"github.com/nxsre/shortme/short"
	"github.com/nxsre/shortme/web"
)

func main() {
	cfgFile := flag.String("c", "config.conf", "configuration file")
	version := flag.Bool("v", false, "Version")

	flag.Parse()

	if *version {
		fmt.Println(conf.Version)
		os.Exit(0)
	}

	// parse config
	conf.MustParseConfig(*cfgFile)

	// short service
	short.Start()

	// api
	web.Start()
}
