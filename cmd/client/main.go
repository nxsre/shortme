package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/imroc/req"
	"github.com/urfave/cli"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

var (
	flags           []cli.Flag
	short           bool
	expand          bool
	urlstr          string
	server          string
	debug           bool
	accessKeyId     string
	accessKeySecret string
	tycReq          *req.Req
)

func init() {
	tycReq = ReqSetup()

	flags = []cli.Flag{
		&cli.BoolFlag{
			Name:        "short",
			Aliases:     []string{"s"},
			Usage:       "short flag",
			Value:       true,
			Destination: &short,
		},
		&cli.BoolFlag{
			Name:        "expand",
			Aliases:     []string{"e"},
			Usage:       "expand flag",
			Destination: &expand,
		},
		&cli.BoolFlag{
			Name:        "debug",
			Aliases:     []string{"d"},
			Usage:       "debug flag",
			Destination: &debug,
		},
		&cli.StringFlag{
			Name:        "url",
			Aliases:     []string{"u"},
			Usage:       "url",
			Destination: &urlstr,
		},
		&cli.StringFlag{
			Name:        "server",
			Usage:       "server addr",
			Value:       "http://127.0.0.1:3030",
			EnvVars:     []string{"SHORT_SERVER_ADDR"},
			Destination: &server,
		},
		&cli.StringFlag{
			Name:        "keyid",
			EnvVars:     []string{"SHORT_ACCESSKEY_ID"},
			Destination: &accessKeyId,
		},
		&cli.StringFlag{
			Name:        "keysecret",
			EnvVars:     []string{"SHORT_ACCESSKEY_SECRET"},
			Destination: &accessKeySecret,
		},
	}
}

type TycTransport struct {
	transport http.RoundTripper
}

func (t *TycTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.transport == nil {
		t.transport = http.DefaultTransport
	}
	dateTime := time.Now().Format(time.RFC1123)
	req.Header.Add("Date", dateTime)
	signature := Signature(req.Method, req.URL.EscapedPath(), dateTime, accessKeySecret)
	req.Header.Add("Authorization", fmt.Sprintf("%s %s:%s", "TYC", accessKeyId, signature))

	return t.transport.RoundTrip(req)
}

func Signature(method, uri, dateTime, secret string) string {
	str2Sign := fmt.Sprintf("%s %s\n%s", method, uri, dateTime)
	hash := hmac.New(sha1.New, []byte(secret))
	io.WriteString(hash, str2Sign)
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func ReqSetup() *req.Req {
	r := req.New()
	r.SetClient(&http.Client{Transport: &TycTransport{}})
	return r
}

func Action(c *cli.Context) error {
	req.Debug = debug
	if expand {
		short = !expand
	}

	if short {
		res, err := Short(urlstr)
		if err != nil {
			log.Fatalln(err)
		}
		bs, _ := json.Marshal(res)
		log.Println(string(bs))
	}

	if expand {
		res, err := Expand(urlstr)
		if err != nil {
			log.Fatalln(err)
		}
		bs, _ := json.Marshal(res)
		log.Println(string(bs))
	}
	return nil
}

type shortUrl struct {
	ShortURL string `json:"shortURL"`
	Msg      string `json:"msg"`
}
type longUrl struct {
	LongURL string `json:"longURL"`
	Msg     string `json:"msg"`
}

func Short(url string) (*shortUrl, error) {
	resp, err := tycReq.Post(server+"/api/short", req.BodyJSON(map[string]string{
		"longURL": url,
	}))
	if err != nil {
		return nil, err
	}
	res := &shortUrl{}
	resp.ToJSON(res)
	return res, err
}

func Expand(url string) (*longUrl, error) {
	resp, err := tycReq.Post(server+"/api/expand", req.BodyJSON(map[string]string{
		"shortURL": url,
	}))
	if err != nil {
		return nil, err
	}
	res := &longUrl{}
	resp.ToJSON(res)
	return res, err
}

func main() {
	app := cli.NewApp()
	app.Name = "shorturl"
	app.Usage = "Short or Expand URL"
	app.HideVersion = true
	app.Flags = flags
	app.Action = Action

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
