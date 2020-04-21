package web

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"crypto/sha1"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/nxsre/shortme/conf"
	"github.com/nxsre/shortme/web/api"
	"github.com/nxsre/shortme/web/www"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	json "github.com/json-iterator/go"
	"github.com/spf13/viper"
	"github.com/urfave/negroni"
)

func endAPICall(w http.ResponseWriter, httpStatus int, anyStruct interface{}) {
	result, err := json.MarshalIndent(anyStruct, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(httpStatus)
	w.Write(result)
}

type Accesskey struct {
	ID     string `yaml:"id"`
	Secret string `yaml:secret`
}

type Accesskeys map[string][]Accesskey

type Keys struct {
	lock *sync.RWMutex
	vals map[string]Accesskey
}

var (
	keysCfg *viper.Viper
	aks     = NewKeys()
)

func BaAuth(w http.ResponseWriter, r *http.Request) error {
	authorization := r.Header.Get("Authorization")
	dateTime := r.Header.Get("Date")
	if authorization == "" {
		w.WriteHeader(http.StatusUnauthorized)
		errMsg, _ := json.Marshal(map[string]interface{}{"msg": http.StatusText(http.StatusUnauthorized)})
		w.Write(errMsg)
		return errors.New("Authorization is empty!")
	}
	_, err := time.Parse(time.RFC1123, dateTime)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		errMsg, _ := json.Marshal(map[string]interface{}{"msg": http.StatusText(http.StatusUnauthorized)})
		w.Write(errMsg)
		return errors.New("Date does not exist or is incorrectly formatted!")
	}

	// 验证签名
	baReq := ParseAuthorization(authorization)
	log.Println(Signature(r.Method, r.URL.EscapedPath(), dateTime, aks.Get(baReq.KeyID).Secret), baReq.Signature)
	return nil
}

type BaReq struct {
	Name      string
	AppID     string
	KeyID     string
	Signature string
}

func Signature(method, uri, dateTime, secret string) string {
	str2Sign := fmt.Sprintf("%s %s\n%s", method, uri, dateTime)
	hash := hmac.New(sha1.New, []byte(secret))
	io.WriteString(hash, str2Sign)
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func ParseAuthorization(val string) BaReq {
	re := regexp.MustCompile(`(?P<name>[A-Z]+)\s+((?P<appid>\w+):)?(?P<keyid>\w+):(?P<signature>.*)`)
	match := re.FindStringSubmatch(val)
	groupNames := re.SubexpNames()

	result := make(map[string]string)
	for i, name := range groupNames {
		if i != 0 && name != "" { // 第一个分组为空（也就是整个匹配）
			result[name] = match[i]
		}
	}

	log.Printf("%+v", result)
	return BaReq{
		Name:      result["name"],
		AppID:     result["appid"],
		KeyID:     result["keyid"],
		Signature: result["signature"],
	}
}

func AccessKeySetup() {
	keysCfg = viper.New()
	keysCfg.SetConfigName("accesskeys")
	keysCfg.SetConfigType("yaml")
	pwd, _ := os.Getwd()
	keysCfg.AddConfigPath(pwd)
	keysCfg.ReadInConfig()
	keysCfg.WatchConfig()
	accesskeys := Accesskeys{}
	keysCfg.Unmarshal(&accesskeys)
	aks.Parse(accesskeys)
	keysCfg.OnConfigChange(func(e fsnotify.Event) {
		accesskeys := Accesskeys{}
		keysCfg.Unmarshal(&accesskeys)
		aks.Parse(accesskeys)
	})
}

func NewKeys() *Keys {
	return &Keys{lock: &sync.RWMutex{}, vals: map[string]Accesskey{}}
}

func (k Keys) Parse(ks Accesskeys) {
	k.lock.Lock()
	defer k.lock.Unlock()
	for i, _ := range k.vals {
		delete(k.vals, i)
	}
	for _, keys := range ks {
		for _, key := range keys {
			k.vals[key.ID] = key
		}
	}
}

func (k *Keys) Get(id string) Accesskey {
	return k.vals[id]
}

func Start() {
	AccessKeySetup()

	log.Println("web starts")
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/version", api.CheckVersion).Methods(http.MethodGet)

	r.Handle("/health", negroni.New(
		/* Health-check routes are unprotected */
		negroni.HandlerFunc(
			func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
				endAPICall(rw, 200, "OK")
			}),
	))
	r.HandleFunc("/{shortenedURL:[a-zA-Z0-9]{1,11}}", api.Redirect).Methods(http.MethodGet)

	apiPath := "/api"
	apiRouter := mux.NewRouter().PathPrefix(apiPath).Subrouter().StrictSlash(true)
	apiRouter.HandleFunc("/short", api.ShortURL).Methods(http.MethodPost).HeadersRegexp("Content-Type", "application/json")
	apiRouter.HandleFunc("/expand", api.ExpandURL).Methods(http.MethodPost).HeadersRegexp("Content-Type", "application/json")

	r.PathPrefix(apiPath).Handler(negroni.New(
		negroni.HandlerFunc(func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
			if err := BaAuth(w, r); err != nil {
				log.Println(err.Error())
				return
			}
			/* Call the next handler iff Basic-Auth succeeded */
			next(w, r)
		}),
		negroni.Wrap(apiRouter),
	))

	r.HandleFunc("/index.html", www.Index).Methods(http.MethodGet)

	r.Handle("/static/{type}/{file}", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	r.Handle("/favicon.ico", http.StripPrefix("/", http.FileServer(http.Dir("."))))

	loggedRouter := handlers.LoggingHandler(os.Stdout, r)

	log.Fatal(http.ListenAndServe(conf.Conf.Http.Listen, loggedRouter))
}
