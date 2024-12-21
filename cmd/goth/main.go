package main

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"text/template"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/openidConnect"
)

var (
	homeTmpl  = template.Must(template.ParseFiles("templates/home.html"))
	loginTmpl = template.Must(template.ParseFiles("templates/login.html"))
)

func render(w io.Writer, tmpl *template.Template, data any) {
	if err := tmpl.Execute(w, data); err != nil {
		panic(err)
	}
}

func withProvider(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = gothic.GetContextWithProvider(r, "openid-connect")
		next.ServeHTTP(w, r)
	})
}

type ctxKey string

const (
	ctxKeyUserID ctxKey = "user_id"
)

func auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := store.Get(r, "test")
		if err != nil {
			fmt.Fprintf(w, "here: %s", err)
			return
		}

		userID, ok := s.Values["user_id"].(string)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), ctxKeyUserID, userID))
		next.ServeHTTP(w, r)
	})
}

func getUserID(ctx context.Context) string {
	return ctx.Value(ctxKeyUserID).(string)
}

var store *sessions.FilesystemStore

func init() {
	store = sessions.NewFilesystemStore(os.TempDir(), []byte("goth-example"))

	// set the maxLength of the cookies stored on the disk to a larger number to prevent issues with:
	// securecookie: the value is too long
	// when using OpenID Connect , since this can contain a large amount of extra information in the id_token

	// Note, when using the FilesystemStore only the session.ID is written to a browser cookie, so this is explicit for the storage on disk
	store.MaxLength(math.MaxInt64)
	store.Options.Secure = true
	store.Options.HttpOnly = true
	store.Options.SameSite = http.SameSiteLaxMode

	gothic.Store = store
}

func main() {
	openIDConnectKey := "go-keycloak-example"
	openIDConnectSecret := "9m3W6OPnaODBuBJ1zwgmGUmBjCVpR92a"
	openIDConnectDiscoveryURL := "http://localhost:8000/realms/master/.well-known/openid-configuration"
	callbackURL := "http://localhost:3000/auth/callback"

	openidConnect, err := openidConnect.New(openIDConnectKey, openIDConnectSecret, callbackURL, openIDConnectDiscoveryURL)
	if err != nil {
		panic(err)
	}
	goth.UseProviders(openidConnect)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(withProvider)

	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		render(w, loginTmpl, nil)
	})

	r.Get("/auth/openid-connect", func(w http.ResponseWriter, r *http.Request) {
		gothic.BeginAuthHandler(w, r)
	})

	r.Get("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		user, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			fmt.Fprintln(w, err)
			return
		}

		s, err := store.Get(r, "test")
		if err != nil {
			fmt.Fprintln(w, err)
			return
		}

		fmt.Println(user.ExpiresAt.Format(time.RFC3339))
		fmt.Println(user.AccessToken)

		s.Values["user_id"] = user.UserID
		s.Options.MaxAge = int(time.Until(user.ExpiresAt).Seconds())
		fmt.Println(s.Options.MaxAge)

		if err := s.Save(r, w); err != nil {
			fmt.Fprintln(w, err)
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	})

	r.Group(func(r chi.Router) {
		r.Use(auth)

		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			render(w, homeTmpl, map[string]any{
				"UserID": getUserID(r.Context()),
			})
		})

		r.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
			if err := gothic.Logout(w, r); err != nil {
				fmt.Fprintln(w, err)
				return
			}

			s, err := store.Get(r, "test")
			if err != nil {
				fmt.Fprintln(w, err)
				return
			}

			s.Options.MaxAge = -1

			if err := store.Save(r, w, s); err != nil {
				fmt.Fprintln(w, err)
				return
			}

			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		})
	})

	fmt.Println("running")
	if err := http.ListenAndServe(":3000", r); err != nil {
		panic(err)
	}
}
