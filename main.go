package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/casbin/casbin/v2"
	xormadapter "github.com/casbin/xorm-adapter/v2"
	_ "github.com/lib/pq"
)

const (
	defDBHost	= "localhost"
	defDBPort	= "5432"
	defDBName	= "casbin"
	defDBUser	= "authorizer"
	defDBPass	= "authorizer"

	envDBHost	= "AUTHORIZER_DB_HOST"
	envDBPort	= "AUTHORIZER_DB_PORT"
	envDBName	= "AUTHORIZER_DB_NAME"
	envDBUser	= "AUTHORIZER_DB_USER"
	envDBPass	= "AUTHORIZER_DB_PASS"
)

// AuthorizeInfo : authorize info for checking
type AuthorizeInfo struct {
	Subject string		`json:"subject"`
	Resource string		`json:"resource"`
	Action string		`json:"action"`	
}

// AuthorizeInfoRes : struct for response
type AuthorizeInfoRes struct {
	Policies []AuthorizeInfo	`json:"policies"`
}

func main(){
	// init postgres db adapter
	dbresource := fmt.Sprintf("user=%s password=%s host=%s port=%s sslmode=disable", 
								env(envDBUser, defDBUser), 
								env(envDBPass, defDBPass), 
								env(envDBHost, defDBHost),
								env(envDBPort, defDBPort),
							)
	a,err := xormadapter.NewAdapter("postgres", dbresource)
	if err != nil {
		log.Fatal(err)
	}

	// create new enforcer
	authEnforcer, err := casbin.NewCachedEnforcer("./auth_model.conf", a)
	// authEnforcer, err := casbin.NewEnforcer("./auth_model.conf", a)
	if err != nil {
		log.Fatal(err)
	}

	// load policy from db
	authEnforcer.LoadPolicy()

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(res http.ResponseWriter, req *http.Request){
		header := res.Header()

		header.Set("Content-Type", "application/json")

		res.Header().Set("Date", "01/01/2020")

		res.WriteHeader(http.StatusAccepted)

		fmt.Fprint(res, `{"status":"OK"}`)
	})

	mux.HandleFunc("/check", checkAuthorizeHandler(authEnforcer))
	mux.HandleFunc("/policies/add", addPoliciesHandler(authEnforcer))
	mux.HandleFunc("/policies/delete", deletePoliciesHandler(authEnforcer))
	mux.HandleFunc("/policies/get", getPoliciesHandler(authEnforcer))

	log.Fatal(http.ListenAndServe(":9000", mux))
}

func checkAuthorizeHandler(enforce *casbin.CachedEnforcer) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var authInfo AuthorizeInfo
		err := json.NewDecoder(r.Body).Decode(&authInfo)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
		}

		// check resource allow or not
		res, err := enforce.Enforce(authInfo.Subject, authInfo.Resource, authInfo.Action)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		if res {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Allow"))
		} else {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Deny"))
		}
	})
}

func addPoliciesHandler(enforce *casbin.CachedEnforcer) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var authInfo AuthorizeInfo
			err := json.NewDecoder(r.Body).Decode(&authInfo)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
			}
	
			_,err = enforce.AddPolicy(authInfo.Subject, authInfo.Resource, authInfo.Action)
			if err != nil {
				log.Fatal(err)
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func deletePoliciesHandler(enforce *casbin.CachedEnforcer) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			var authInfo AuthorizeInfo
			err := json.NewDecoder(r.Body).Decode(&authInfo)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
			}
	
			removed,err := enforce.RemovePolicy(authInfo.Subject, authInfo.Resource, authInfo.Action)
			if err != nil {
				log.Fatal(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			} 
			if removed {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotModified)
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func getPoliciesHandler(enforce *casbin.CachedEnforcer) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			policies := enforce.GetPolicy()
			res := AuthorizeInfoRes{
				Policies: []AuthorizeInfo{},
			}
			fmt.Printf("policies %v \n", policies)
			for _,p := range policies {
				fmt.Printf("policy %v \n", p)
				obj := AuthorizeInfo{
					Subject: p[0],
					Resource: p[1],
					Action: p[2],
				}
				res.Policies = append(res.Policies, obj)
			}
			jsonRes,_ := json.Marshal(res)
			header := w.Header()

			header.Set("Content-Type", "application/json")

			w.WriteHeader(http.StatusOK)

			fmt.Fprint(w, string(jsonRes))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// env reads specified environment variable. If no value has been found,
// fallback is returned.
func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}
