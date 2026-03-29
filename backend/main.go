package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	// import interne
	"yboost/models"
)

var err error
var tpl *template.Template
var db *gorm.DB
var sessions = map[string]models.Session{}

var supabaseJWKS *keyfunc.JWKS
var supabaseJWKSURL string
var supabaseJWKSLock sync.Mutex

var ApiCategorie []models.Food_categorie
var ApiFoodlist []models.Food_affichage
var ApiRecette []models.Recette

type ErrorPageData struct {
	StatusCode int
	Title      string
	Message    string
	ErrorID    string
	Path       string
	Method     string
	Timestamp  string
	ShowDebug  bool
	Debug      string
}

type SupabaseAuthResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type SupabaseErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	Message          string `json:"message"`
	Msg              string `json:"msg"`
}

func renderErrorPage(w http.ResponseWriter, r *http.Request, statusCode int, userMessage, debugDetail string) {
	errorID := uuid.NewString()
	showDebug := os.Getenv("SHOW_ERROR_DETAILS") == "1"

	log.Printf("[ERROR][%s] status=%d method=%s path=%s remote=%s detail=%s", errorID, statusCode, r.Method, r.URL.Path, r.RemoteAddr, debugDetail)

	data := ErrorPageData{
		StatusCode: statusCode,
		Title:      http.StatusText(statusCode),
		Message:    userMessage,
		ErrorID:    errorID,
		Path:       r.URL.Path,
		Method:     r.Method,
		Timestamp:  time.Now().Format("02/01/2006 15:04:05"),
		ShowDebug:  showDebug,
		Debug:      debugDetail,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	if tplErr := tpl.ExecuteTemplate(w, "error.html", data); tplErr != nil {
		log.Printf("[ERROR][%s] erreur template error.html: %v", errorID, tplErr)
		http.Error(w, userMessage+" (incident: "+errorID+")", statusCode)
		return
	}
}

func getSupabaseConfig() (projectURL, anonKey, jwtSecret string, cfgErr error) {
	projectURL = strings.Trim(os.Getenv("SUPABASE_URL"), "\" \t\n\r")
	anonKey = strings.Trim(os.Getenv("SUPABASE_ANON_KEY"), "\" \t\n\r")
	jwtSecret = strings.Trim(os.Getenv("SUPABASE_JWT_SECRET"), "\" \t\n\r")

	if projectURL == "" || anonKey == "" {
		return "", "", "", fmt.Errorf("variables Supabase manquantes (SUPABASE_URL, SUPABASE_ANON_KEY)")
	}

	projectURL = strings.TrimRight(projectURL, "/")
	return projectURL, anonKey, jwtSecret, nil
}

func getSupabaseJWKS(projectURL string) (*keyfunc.JWKS, error) {
	jwksURL := projectURL + "/auth/v1/.well-known/jwks.json"

	supabaseJWKSLock.Lock()
	defer supabaseJWKSLock.Unlock()

	if supabaseJWKS != nil && supabaseJWKSURL == jwksURL {
		return supabaseJWKS, nil
	}

	if supabaseJWKS != nil {
		supabaseJWKS.EndBackground()
		supabaseJWKS = nil
		supabaseJWKSURL = ""
	}

	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{
		RefreshInterval:   30 * time.Minute,
		RefreshRateLimit:  time.Minute,
		RefreshUnknownKID: true,
		RefreshErrorHandler: func(err error) {
			log.Printf("JWKS refresh error: %v", err)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("chargement JWKS impossible: %w", err)
	}

	supabaseJWKS = jwks
	supabaseJWKSURL = jwksURL
	return supabaseJWKS, nil
}

func parseSupabaseErrorBody(body []byte) string {
	var apiErr SupabaseErrorResponse
	if err := json.Unmarshal(body, &apiErr); err == nil {
		if apiErr.ErrorDescription != "" {
			return apiErr.ErrorDescription
		}
		if apiErr.Message != "" {
			return apiErr.Message
		}
		if apiErr.Msg != "" {
			return apiErr.Msg
		}
		if apiErr.Error != "" {
			return apiErr.Error
		}
	}

	if len(body) == 0 {
		return "réponse vide"
	}
	return string(body)
}

func supabaseAuthenticate(email, password string) (SupabaseAuthResponse, error) {
	projectURL, anonKey, _, err := getSupabaseConfig()
	if err != nil {
		return SupabaseAuthResponse{}, err
	}

	payload := map[string]string{
		"email":    email,
		"password": password,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return SupabaseAuthResponse{}, err
	}

	endpoint := projectURL + "/auth/v1/token?grant_type=password"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return SupabaseAuthResponse{}, err
	}
	req.Header.Set("apikey", anonKey)
	req.Header.Set("Authorization", "Bearer "+anonKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return SupabaseAuthResponse{}, err
	}
	defer resp.Body.Close()

	bodyResp, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return SupabaseAuthResponse{}, fmt.Errorf("supabase auth status=%d detail=%s", resp.StatusCode, parseSupabaseErrorBody(bodyResp))
	}

	var authResp SupabaseAuthResponse
	if err := json.Unmarshal(bodyResp, &authResp); err != nil {
		return SupabaseAuthResponse{}, err
	}
	if authResp.AccessToken == "" {
		return SupabaseAuthResponse{}, fmt.Errorf("supabase auth: access_token absent")
	}

	return authResp, nil
}

func supabaseSignUp(email, password, firstName, lastName string) error {
	projectURL, anonKey, _, err := getSupabaseConfig()
	if err != nil {
		return err
	}

	payload := map[string]interface{}{
		"email":    email,
		"password": password,
		"options": map[string]interface{}{
			"data": map[string]string{
				"first_name": firstName,
				"last_name":  lastName,
			},
		},
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	endpoint := projectURL + "/auth/v1/signup"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("apikey", anonKey)
	req.Header.Set("Authorization", "Bearer "+anonKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyResp, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("supabase signup status=%d detail=%s", resp.StatusCode, parseSupabaseErrorBody(bodyResp))
	}

	return nil
}

func hydrateSessionFromJWT(tokenString string) (models.Session, error) {
	if sess, exists := sessions[tokenString]; exists && time.Now().Before(sess.Expiry) {
		return sess, nil
	}

	projectURL, _, jwtSecret, err := getSupabaseConfig()
	if err != nil {
		return models.Session{}, err
	}

	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		switch token.Method.Alg() {
		case jwt.SigningMethodHS256.Alg(), jwt.SigningMethodHS384.Alg(), jwt.SigningMethodHS512.Alg():
			if jwtSecret == "" {
				return nil, fmt.Errorf("SUPABASE_JWT_SECRET manquant pour validation HMAC")
			}
			return []byte(jwtSecret), nil
		case jwt.SigningMethodES256.Alg(), jwt.SigningMethodES384.Alg(), jwt.SigningMethodES512.Alg(),
			jwt.SigningMethodRS256.Alg(), jwt.SigningMethodRS384.Alg(), jwt.SigningMethodRS512.Alg():
			jwks, jwksErr := getSupabaseJWKS(projectURL)
			if jwksErr != nil {
				return nil, jwksErr
			}
			return jwks.Keyfunc(token)
		default:
			return nil, fmt.Errorf("algorithme JWT non supporté: %s", token.Method.Alg())
		}
	}, jwt.WithValidMethods([]string{
		jwt.SigningMethodHS256.Alg(), jwt.SigningMethodHS384.Alg(), jwt.SigningMethodHS512.Alg(),
		jwt.SigningMethodES256.Alg(), jwt.SigningMethodES384.Alg(), jwt.SigningMethodES512.Alg(),
		jwt.SigningMethodRS256.Alg(), jwt.SigningMethodRS384.Alg(), jwt.SigningMethodRS512.Alg(),
	}))
	if err != nil {
		log.Printf("Erreur détaillée JWT: %v", err)
		return models.Session{}, fmt.Errorf("jwt invalide")
	}
	if !parsedToken.Valid {
		log.Printf("Erreur détaillée JWT: token non valide")
		return models.Session{}, fmt.Errorf("jwt invalide")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return models.Session{}, fmt.Errorf("claims JWT invalides")
	}

	userID, _ := claims["sub"].(string)
	if userID == "" {
		return models.Session{}, fmt.Errorf("claim sub manquante dans JWT")
	}

	expFloat, ok := claims["exp"].(float64)
	if !ok {
		return models.Session{}, fmt.Errorf("claim exp manquante dans JWT")
	}

	expiry := time.Unix(int64(expFloat), 0)
	if time.Now().After(expiry) {
		return models.Session{}, fmt.Errorf("jwt expiré")
	}

	sess := models.Session{Userid: userID, Expiry: expiry}
	sessions[tokenString] = sess
	return sess, nil
}

func SendEmail(to, subject, body string) error {
	apiKey := os.Getenv("RESEND_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("configuration RESEND_API_KEY manquante")
	}

	from := os.Getenv("RESEND_FROM")
	if from == "" {
		from = "onboarding@resend.dev"
	}

	payload := map[string]interface{}{
		"from":    "YBoost <" + from + ">",
		"to":      []string{to},
		"subject": subject,
		"text":    body,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("erreur json resend: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://api.resend.com/emails", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("erreur requête resend: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("❌ ERREUR API RESEND: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		bodyResp, _ := io.ReadAll(resp.Body)
		log.Printf("❌ ERREUR API RESEND: status=%d", resp.StatusCode)
		return fmt.Errorf("erreur API Resend: status %d, body %s", resp.StatusCode, string(bodyResp))
	}

	log.Println("✅ Email envoyé via API avec succès")

	return nil
}

func SendVerificationEmail(to, code string) error {
	subject := "Votre code de vérification"
	body := "Voici votre code : " + code + "\nIl expire dans 5 minutes."
	return SendEmail(to, subject, body)
}

func generateCode() (string, error) {
	codes := make([]byte, 6)
	if _, err := rand.Read(codes); err != nil {
		return "", err
	}

	for i := 0; i < 6; i++ {
		codes[i] = uint8(48 + (codes[i] % 10))
	}

	return string(codes), nil
}

func parseTemplates() (*template.Template, error) {
	tpl, err = template.ParseFiles(
		"../frontend/html/acceuil.html",
		"../frontend/html/login.html",
		"../frontend/html/register.html",
		"../frontend/html/verify.html",
		"../frontend/html/home.html",
		"../frontend/html/categoriefood.html",
		"../frontend/html/meals.html",
		"../frontend/html/favoris.html",
		"../frontend/html/liste.html",
		"../frontend/html/error.html",
	)
	if err != nil {
		return nil, err
	}
	return tpl, nil
}

func connectDB() error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("DATABASE_URL manquante")
	}

	var err error
	// Connexion via GORM avec configuration explicite pour Supabase Pooler
	db, err = gorm.Open(postgres.New(postgres.Config{
		DSN:                  dsn,
		PreferSimpleProtocol: true, // Aide énormément avec le pooler de Supabase
	}), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("erreur ouverture GORM: %w", err)
	}

	// Récupération de l'objet SQL brut pour le Ping (optionnel mais recommandé)
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}

	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("ping échoué: %w", err)
	}

	log.Println("✅ DB Supabase connectée avec GORM!")

	// 3. Migration (Crée tes tables automatiquement)
	// Ajoute ici tous tes modèles (Users, Favoris, Commentaire...)
	err = db.AutoMigrate(&models.Users{}, &models.Favoris{}, &models.Commentaire{}, &models.Liste{})
	if err != nil {
		log.Printf("Erreur migration: %v", err)
	}

	return nil
}

func ensureEmailVerificationSchema() error {
	if !db.Migrator().HasTable(&models.Email_verification{}) {
		return nil
	}

	var dataType string
	if err := db.Raw(`
		SELECT data_type
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name = ?
		  AND column_name = ?
	`, "email_verification", "is_verified").Scan(&dataType).Error; err != nil {
		return err
	}

	if dataType == "" || dataType == "boolean" {
		return nil
	}

	log.Printf("Correction du type email_verification.is_verified (type actuel: %s)", dataType)
	return db.Exec(`
		ALTER TABLE email_verification
		ALTER COLUMN is_verified DROP DEFAULT,
		ALTER COLUMN is_verified TYPE boolean
		USING CASE
			WHEN is_verified IS NULL THEN false
			WHEN is_verified::text IN ('1', 't', 'true', 'TRUE') THEN true
			ELSE false
		END,
		ALTER COLUMN is_verified SET DEFAULT false
	`).Error
}

func acceuilHandle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		renderErrorPage(w, r, http.StatusNotFound, "La page demandée est introuvable.", "route inexistante")
		return
	}

	if err = tpl.ExecuteTemplate(w, "acceuil.html", nil); err != nil {
		renderErrorPage(w, r, http.StatusInternalServerError, "Une erreur est survenue lors de l'affichage de la page.", "template acceuil.html: "+err.Error())
		return
	}
}

func loginHandle(w http.ResponseWriter, r *http.Request) {
	data := models.Pagedata{}
	switch r.Method {
	case http.MethodGet:
		data.Errmsg = ""
		if err = tpl.ExecuteTemplate(w, "login.html", data); err != nil {
			renderErrorPage(w, r, http.StatusInternalServerError, "Une erreur est survenue lors de l'affichage de la page.", "template login.html: "+err.Error())
			return
		}
	case http.MethodPost:
		email := r.FormValue("email")
		password := r.FormValue("password")
		if email == "" || password == "" {
			data.Errmsg = "Email et mot de passe requis"
			tpl.ExecuteTemplate(w, "login.html", data)
			return
		}

		authResp, authErr := supabaseAuthenticate(email, password)
		if authErr != nil {
			log.Printf("login supabase échoué pour %s: %v", email, authErr)
			data.Errmsg = "Mots de passe ou email incorrect"
			if tplErr := tpl.ExecuteTemplate(w, "login.html", data); tplErr != nil {
				renderErrorPage(w, r, http.StatusInternalServerError, "Une erreur est survenue lors de l'affichage de la page.", "template login.html après auth échouée: "+tplErr.Error())
			}
			return
		}

		expiresAt := time.Now().Add(8 * time.Hour)
		if authResp.ExpiresIn > 0 {
			expiresAt = time.Now().Add(time.Duration(authResp.ExpiresIn) * time.Second)
		}

		sessionToken := authResp.AccessToken
		sess, hydrateErr := hydrateSessionFromJWT(sessionToken)
		if hydrateErr != nil {
			renderErrorPage(w, r, http.StatusUnauthorized, "Session invalide, reconnectez-vous.", "hydrateSessionFromJWT login: "+hydrateErr.Error())
			return
		}
		sess.Expiry = expiresAt
		sessions[sessionToken] = sess

		isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Expires:  expiresAt,
			Path:     "/",
			HttpOnly: true,
			Secure:   isSecure,
			SameSite: http.SameSiteLaxMode,
		})

		http.Redirect(w, r, "/home", http.StatusSeeOther)

	default:
		renderErrorPage(w, r, http.StatusMethodNotAllowed, "Méthode HTTP non autorisée.", "loginHandle méthode non autorisée")
		return
	}
}

func registerhandle(w http.ResponseWriter, r *http.Request) {
	var p models.Users
	data := models.Pagedata{}
	switch r.Method {
	case http.MethodGet:
		data.Errmsg = ""
		if err = tpl.ExecuteTemplate(w, "register.html", data); err != nil {
			renderErrorPage(w, r, http.StatusInternalServerError, "Une erreur est survenue lors de l'affichage de la page.", "template register.html: "+err.Error())
			return
		}
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			renderErrorPage(w, r, http.StatusBadRequest, "Le formulaire envoyé est invalide.", "register ParseForm: "+err.Error())
			return
		}

		p.Email = r.FormValue("email")
		p.FirstName = r.FormValue("firstname")
		p.LastName = r.FormValue("lastname")
		password := r.FormValue("password")
		passwordV := r.FormValue("passwordV")

		if password != passwordV {
			data.Errmsg = "Les mots de passe ne correspondent pas !"
			tpl.ExecuteTemplate(w, "register.html", data)
			return
		}

		if password == "" {
			data.Errmsg = "Mot de passe requis"
			tpl.ExecuteTemplate(w, "register.html", data)
			return
		}

		if err := supabaseSignUp(p.Email, password, p.FirstName, p.LastName); err != nil {
			log.Printf("register supabase signup échoué pour %s: %v", p.Email, err)
			data.Errmsg = "Impossible de créer le compte (email déjà utilisé ou invalide)"
			if tplErr := tpl.ExecuteTemplate(w, "register.html", data); tplErr != nil {
				renderErrorPage(w, r, http.StatusInternalServerError, "Une erreur est survenue lors de l'affichage de la page.", "template register.html après signup échoué: "+tplErr.Error())
			}
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)

	default:
		renderErrorPage(w, r, http.StatusMethodNotAllowed, "Méthode HTTP non autorisée.", "registerhandle méthode non autorisée")
	}
}

func verifyHandle(w http.ResponseWriter, r *http.Request) {
	renderErrorPage(w, r, http.StatusGone, "La vérification locale a été retirée. Utilisez la confirmation email Supabase.", "verifyHandle déprécié")
}

func loadCategorieAPI(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	var apiResp models.CategoriesAPIResponse
	if err = json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return err
	}

	ApiCategorie = apiResp.Categories
	return nil
}

func loadListeFood(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		bodyResp, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API food status=%d body=%s", resp.StatusCode, string(bodyResp))
	}

	var apiResp models.ListFoodApi
	if err = json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return err
	}
	ApiFoodlist = apiResp.Meals
	return nil
}

func homeHandle(w http.ResponseWriter, r *http.Request) {
	data := models.Pagedata{}
	switch r.Method {
	case http.MethodGet:
		data.Categoriefood = ApiCategorie

		c, err := r.Cookie("session_token")
		if err != nil {
			renderErrorPage(w, r, http.StatusUnauthorized, "Vous devez être connecté pour accéder à cette page.", "cookie session_token absente")
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			renderErrorPage(w, r, http.StatusUnauthorized, "Votre session a expiré, reconnectez-vous.", "session invalide ou expirée")
			return
		}

		listrandom, err := loadRandomRecettes(20)
		if err != nil {
			renderErrorPage(w, r, http.StatusInternalServerError, "Impossible de charger les recettes du moment.", "loadRandomRecettes: "+err.Error())
			return
		}
		data.Listrandom = listrandom

		liste := getallfavoris(sess.Userid)

		data.Favorisliste = liste

		// ✅ Vérifier AVANT d'écrire
		if err = tpl.ExecuteTemplate(w, "home.html", data); err != nil {
			log.Printf("Erreur template home: %v", err) // Log seulement
			renderErrorPage(w, r, http.StatusInternalServerError, "Une erreur est survenue lors de l'affichage de la page.", "template home.html: "+err.Error())
			return
		}
	default:
		renderErrorPage(w, r, http.StatusMethodNotAllowed, "Méthode HTTP non autorisée.", "homeHandle méthode non autorisée")
		return
	}
}

func ApiSearch(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var apiResp models.ApiRecette
	if err = json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		log.Printf("decode error: %v", err)
		return err
	}
	log.Printf("search results count: %d", len(apiResp.Recette))
	ApiRecette = apiResp.Recette
	return nil
}

func searchHandle(w http.ResponseWriter, r *http.Request) {
	data := models.Pagedata{}
	namestr := r.FormValue("name")
	encoded := url.QueryEscape(namestr)
	url := os.Getenv("API_SEARCH") + encoded

	err = ApiSearch(url)
	if err != nil {
		renderErrorPage(w, r, http.StatusBadGateway, "La recherche de recettes est indisponible pour le moment.", "ApiSearch: "+err.Error())
		return
	}

	data.Recette = ApiRecette
	if err = tpl.ExecuteTemplate(w, "meals.html", data); err != nil {
		renderErrorPage(w, r, http.StatusInternalServerError, "Une erreur est survenue lors de l'affichage de la page.", "template meals.html(search): "+err.Error())
		return
	}
}

func categorieHandle(w http.ResponseWriter, r *http.Request) {
	data := models.Pagedata{}
	switch r.Method {
	case http.MethodGet:
		categorienamestr := r.URL.Query().Get("categorie")
		if categorienamestr == "" {
			renderErrorPage(w, r, http.StatusBadRequest, "La catégorie demandée est invalide.", "paramètre categorie manquant")
			return
		}

		defaultAPIBase := "https://www.themealdb.com/api/json/v1/1/filter.php?c="
		apiFoodBase := os.Getenv("API_FOOD")
		if apiFoodBase == "" {
			apiFoodBase = defaultAPIBase
		}

		endpoint := apiFoodBase + url.QueryEscape(categorienamestr)

		err = loadListeFood(endpoint)
		if err != nil {
			log.Printf("erreur loadListeFood categorie=%q endpoint=%q: %v", categorienamestr, endpoint, err)

			fallbackEndpoint := defaultAPIBase + url.QueryEscape(categorienamestr)
			if endpoint != fallbackEndpoint {
				if fallbackErr := loadListeFood(fallbackEndpoint); fallbackErr == nil {
					log.Printf("fallback loadListeFood réussi categorie=%q fallback=%q", categorienamestr, fallbackEndpoint)
				} else {
					log.Printf("fallback loadListeFood échoué categorie=%q fallback=%q: %v", categorienamestr, fallbackEndpoint, fallbackErr)
					renderErrorPage(w, r, http.StatusBadGateway, "Impossible de charger les recettes de cette catégorie pour le moment.", "loadListeFood primary: "+err.Error()+" | fallback: "+fallbackErr.Error())
					return
				}
			} else {
				renderErrorPage(w, r, http.StatusBadGateway, "Impossible de charger les recettes de cette catégorie pour le moment.", "loadListeFood: "+err.Error())
				return
			}
		}

		data.Listfood = ApiFoodlist

		if err = tpl.ExecuteTemplate(w, "categoriefood.html", data); err != nil {
			renderErrorPage(w, r, http.StatusInternalServerError, "Une erreur est survenue lors de l'affichage de la page.", "template categoriefood.html: "+err.Error())
			return
		}
	default:
		renderErrorPage(w, r, http.StatusMethodNotAllowed, "Méthode HTTP non autorisée.", "categorieHandle méthode non autorisée")
		return
	}
}

func recetteHandle(w http.ResponseWriter, r *http.Request) {
	data := models.Pagedata{}
	switch r.Method {
	case http.MethodGet:
		// Récupérer l'utilisateur connecté
		c, err := r.Cookie("session_token")
		if err != nil {
			renderErrorPage(w, r, http.StatusUnauthorized, "Vous devez être connecté pour accéder à cette page.", "cookie session_token absente")
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			renderErrorPage(w, r, http.StatusUnauthorized, "Votre session a expiré, reconnectez-vous.", "session invalide ou expirée")
			return
		}

		recetteidstr := r.URL.Query().Get("recette")
		recetteid, err := strconv.Atoi(recetteidstr)
		if err != nil {
			renderErrorPage(w, r, http.StatusBadRequest, "Identifiant de recette invalide.", "conversion id recette: "+err.Error())
			return
		}

		url := os.Getenv("API_BYID") + recetteidstr
		err = ApiRecettefunc(url)
		if err != nil {
			renderErrorPage(w, r, http.StatusBadGateway, "Impossible de charger la recette demandée.", "ApiRecettefunc: "+err.Error())
			return
		}

		Liste := GetCommentaireById(recetteid)
		data.Listecommentaire = Liste
		data.Recette = ApiRecette
		data.User_id = sess.Userid

		// ✅ TOUT est prêt → MAINTENANT on écrit
		if err = tpl.ExecuteTemplate(w, "meals.html", data); err != nil {
			log.Printf("Erreur template recette: %v", err)
			renderErrorPage(w, r, http.StatusInternalServerError, "Une erreur est survenue lors de l'affichage de la page.", "template meals.html(recette): "+err.Error())
			return
		}
	}
}

func ApiRecettefunc(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	var apiResp models.ApiRecette
	if err = json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return err
	}

	ApiRecette = apiResp.Recette
	return nil
}

func loadRandomRecettes(n int) ([]models.Recette, error) {
	var res []models.Recette

	for i := 0; i < n; i++ {
		resp, err := http.Get(os.Getenv("API_RANDOM"))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		var apiResp models.ApiRecette
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			return nil, err
		}
		if len(apiResp.Recette) > 0 {
			res = append(res, apiResp.Recette[0])
		}
	}
	return res, nil
}

func addfavorisHandle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:

		referer := r.Header.Get("Referer")
		if referer == "" {
			referer = "/" // Fallback si pas de referer
		}

		c, err := r.Cookie("session_token")
		if err != nil {
			renderErrorPage(w, r, http.StatusUnauthorized, "Vous devez être connecté pour effectuer cette action.", "addfavoris cookie session_token absente")
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			renderErrorPage(w, r, http.StatusUnauthorized, "Votre session a expiré, reconnectez-vous.", "addfavoris session invalide ou expirée")
			return
		}

		id := r.FormValue("id")
		name := r.FormValue("name")
		categorie := r.FormValue("categorie")
		origine := r.FormValue("origine")
		thrumb := r.FormValue("Thumb")

		favoris := models.Favoris{
			Id:        id,
			User_id:   sess.Userid,
			Name:      name,
			Categorie: categorie,
			Origine:   origine,
			Thumb:     thrumb,
		}
		if err = db.Create(&favoris).Error; err != nil {
			renderErrorPage(w, r, http.StatusInternalServerError, "Impossible d'ajouter ce favori.", "insert favoris: "+err.Error())
			return
		}

		http.Redirect(w, r, referer, http.StatusSeeOther)
	default:
		renderErrorPage(w, r, http.StatusMethodNotAllowed, "Méthode HTTP non autorisée.", "addfavorisHandle méthode non autorisée")
		return
	}
}

func favorisHandle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		data := models.Pagedata{}

		c, err := r.Cookie("session_token")
		if err != nil {
			renderErrorPage(w, r, http.StatusUnauthorized, "Vous devez être connecté pour accéder à cette page.", "favoris cookie session_token absente")
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			renderErrorPage(w, r, http.StatusUnauthorized, "Votre session a expiré, reconnectez-vous.", "favoris session invalide ou expirée")
			return
		}

		liste := getallfavoris(sess.Userid)

		data.Favorisliste = liste

		if err = tpl.ExecuteTemplate(w, "favoris.html", data); err != nil {
			renderErrorPage(w, r, http.StatusInternalServerError, "Une erreur est survenue lors de l'affichage de la page.", "template favoris.html: "+err.Error())
			return
		}
	default:
		renderErrorPage(w, r, http.StatusMethodNotAllowed, "Méthode HTTP non autorisée.", "favorisHandle méthode non autorisée")
		return
	}
}

func getallfavoris(User_id string) []models.Favoris {
	var liste []models.Favoris
	if err := db.Where("users_id = ?", User_id).Find(&liste).Error; err != nil {
		log.Printf("erreur select all favoris: %v", err)
	}
	return liste
}

func deletefavorisHandle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		c, err := r.Cookie("session_token")
		if err != nil {
			renderErrorPage(w, r, http.StatusUnauthorized, "Vous devez être connecté pour effectuer cette action.", "deletefavoris cookie session_token absente")
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			renderErrorPage(w, r, http.StatusUnauthorized, "Votre session a expiré, reconnectez-vous.", "deletefavoris session invalide ou expirée")
			return
		}

		name := r.FormValue("name")
		id := r.FormValue("id")

		if err = db.Where("users_id = ? AND id = ? AND name = ?", sess.Userid, id, name).Delete(&models.Favoris{}).Error; err != nil {
			renderErrorPage(w, r, http.StatusInternalServerError, "Impossible de supprimer ce favori.", "delete favoris: "+err.Error())
			return
		}

		http.Redirect(w, r, "/favoris", http.StatusSeeOther)
	default:
		renderErrorPage(w, r, http.StatusMethodNotAllowed, "Méthode HTTP non autorisée.", "deletefavorisHandle méthode non autorisée")
		return
	}
}

func addCom(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var last_name string
		var first_name string
		referer := r.Header.Get("Referer")
		if referer == "" {
			referer = "/" // Fallback si pas de referer
		}

		c, err := r.Cookie("session_token")
		if err != nil {
			renderErrorPage(w, r, http.StatusUnauthorized, "Vous devez être connecté pour effectuer cette action.", "addCom cookie session_token absente")
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			renderErrorPage(w, r, http.StatusUnauthorized, "Votre session a expiré, reconnectez-vous.", "addCom session invalide ou expirée")
			return
		}

		dataCom := r.FormValue("data")
		idstr := r.FormValue("id")
		id, err := strconv.Atoi(idstr)
		if err != nil {
			log.Printf("erreur conversion id commentaire: %v", err)
		}

		var user models.Users
		if err = db.Select("first_name, last_name, email").Where("id = ?", sess.Userid).First(&user).Error; err == nil {
			first_name = user.FirstName
			last_name = user.LastName
		} else {
			first_name = "Utilisateur"
			last_name = "Supabase"
			if tokenClaims, parseErr := jwt.Parse(c.Value, func(token *jwt.Token) (interface{}, error) {
				_, _, jwtSecret, cfgErr := getSupabaseConfig()
				if cfgErr != nil {
					return nil, cfgErr
				}
				if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
					return nil, fmt.Errorf("algorithme JWT inattendu: %s", token.Method.Alg())
				}
				return []byte(jwtSecret), nil
			}); parseErr == nil && tokenClaims.Valid {
				if claims, ok := tokenClaims.Claims.(jwt.MapClaims); ok {
					email, _ := claims["email"].(string)
					if email != "" {
						first_name = strings.Split(email, "@")[0]
						last_name = ""
					}
				}
			}
		}

		commentaire := models.Commentaire{
			Users_id:    sess.Userid,
			Data_string: dataCom,
			Meal_id:     id,
			First_name:  first_name,
			Last_name:   last_name,
		}
		if err = db.Create(&commentaire).Error; err != nil {
			renderErrorPage(w, r, http.StatusInternalServerError, "Impossible d'ajouter votre commentaire.", "insert commentaire: "+err.Error())
			return
		}

		http.Redirect(w, r, referer, http.StatusSeeOther)
	default:
		renderErrorPage(w, r, http.StatusMethodNotAllowed, "Méthode HTTP non autorisée.", "addCom méthode non autorisée")
		return
	}
}

func GetCommentaireById(id int) []models.Commentaire {
	var Listallcommentaire []models.Commentaire
	if err := db.Where("meal_id = ?", id).Find(&Listallcommentaire).Error; err != nil {
		log.Printf("erreur select commentaires: %v", err)
	}
	return Listallcommentaire
}

func deleteCom(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		c, err := r.Cookie("session_token")
		if err != nil {
			renderErrorPage(w, r, http.StatusUnauthorized, "Vous devez être connecté pour effectuer cette action.", "deleteCom cookie session_token absente")
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			renderErrorPage(w, r, http.StatusUnauthorized, "Votre session a expiré, reconnectez-vous.", "deleteCom session invalide ou expirée")
			return
		}

		idstr := r.FormValue("id")
		id, err := strconv.Atoi(idstr)
		if err != nil {
			renderErrorPage(w, r, http.StatusBadRequest, "Identifiant de commentaire invalide.", "deleteCom conversion id: "+err.Error())
			return
		}

		referer := r.Header.Get("Referer")
		if referer == "" {
			referer = "/home"
		}

		if err = db.Where("users_id = ? AND id = ?", sess.Userid, id).Delete(&models.Commentaire{}).Error; err != nil {
			renderErrorPage(w, r, http.StatusInternalServerError, "Impossible de supprimer le commentaire.", "delete commentaire: "+err.Error())
			return
		}

		http.Redirect(w, r, referer, http.StatusSeeOther)
	default:
		renderErrorPage(w, r, http.StatusMethodNotAllowed, "Méthode HTTP non autorisée.", "deleteCom méthode non autorisée")
		return
	}
}

func listeHandle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c, err := r.Cookie("session_token")
		if err != nil {
			renderErrorPage(w, r, http.StatusUnauthorized, "Vous devez être connecté pour accéder à cette page.", "listeHandle cookie session_token absente")
			return
		}
		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			renderErrorPage(w, r, http.StatusUnauthorized, "Votre session a expiré, reconnectez-vous.", "listeHandle session invalide ou expirée")
			return
		}

		var Liste []models.Liste
		if err := db.Where("id_users = ?", sess.Userid).Find(&Liste).Error; err != nil {
			log.Printf("DB erreur: %v", err)
			renderErrorPage(w, r, http.StatusInternalServerError, "Impossible de récupérer votre liste de courses.", "select liste: "+err.Error())
			return
		}

		prixTotal, err := TotalPrix(sess.Userid)
		if err != nil {
			log.Printf("TotalPrix erreur: %v", err)
			prixTotal = 0
		}

		data := models.Pagedata{Liste: Liste, PrixTotal: prixTotal}
		if err := tpl.ExecuteTemplate(w, "liste.html", data); err != nil {
			renderErrorPage(w, r, http.StatusInternalServerError, "Une erreur est survenue lors de l'affichage de la page.", "template liste.html: "+err.Error())
			return
		}
	default:
		renderErrorPage(w, r, http.StatusMethodNotAllowed, "Méthode HTTP non autorisée.", "listeHandle méthode non autorisée")
	}
}

func TotalPrix(id_users string) (float64, error) {
	var total float64
	if err := db.Model(&models.Liste{}).Where("id_users = ?", id_users).Select("COALESCE(SUM(prix), 0)").Scan(&total).Error; err != nil {
		return 0, err
	}
	return total, nil
}

func listeUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/liste", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		log.Printf("ParseForm erreur: %v", err)
		http.Redirect(w, r, "/liste", http.StatusSeeOther)
		return
	}

	// Récup ID depuis le formulaire
	idStr := r.FormValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		log.Printf("ID invalide: %v", err)
		http.Redirect(w, r, "/liste", http.StatusSeeOther)
		return
	}

	// Session check
	c, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	sess, exists := sessions[c.Value]
	if !exists || time.Now().After(sess.Expiry) {
		delete(sessions, c.Value)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Checkbox : coché="1", non coché=absent → 0
	isFinish := r.FormValue("is_finish") == "1"

	// UPDATE DB (sécurisé avec id_users)
	if err = db.Model(&models.Liste{}).Where("id = ? AND id_users = ?", id, sess.Userid).Update("is_finish", isFinish).Error; err != nil {
		log.Printf("Update erreur %d: %v", id, err)
	}

	http.Redirect(w, r, "/liste", http.StatusSeeOther)
}

func ListeAdd(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		c, err := r.Cookie("session_token")
		if err != nil {
			renderErrorPage(w, r, http.StatusUnauthorized, "Vous devez être connecté pour effectuer cette action.", "ListeAdd cookie session_token absente")
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			renderErrorPage(w, r, http.StatusUnauthorized, "Votre session a expiré, reconnectez-vous.", "ListeAdd session invalide ou expirée")
			return
		}

		referer := r.Header.Get("Referer")
		if referer == "" {
			referer = "/home"
		}

		nombrestr := r.FormValue("nombre")
		nombre, err := strconv.ParseFloat(nombrestr, 64)
		if err != nil {
			renderErrorPage(w, r, http.StatusBadRequest, "La quantité saisie est invalide.", "ListeAdd conversion nombre: "+err.Error())
			return
		}
		prixstr := r.FormValue("prix")
		prix, err := strconv.ParseFloat(prixstr, 64)
		if err != nil {
			renderErrorPage(w, r, http.StatusBadRequest, "Le prix saisi est invalide.", "ListeAdd conversion prix: "+err.Error())
			return
		}

		l := models.Liste{
			Id_users: sess.Userid,
			Aliment:  r.FormValue("aliment"),
			Nombre:   nombre,
			Prix:     prix,
			Unite:    r.FormValue("unite"),
		}

		if err = db.Create(&l).Error; err != nil {
			renderErrorPage(w, r, http.StatusInternalServerError, "Impossible d'ajouter cet élément à la liste.", "insert liste: "+err.Error())
			return
		}

		http.Redirect(w, r, referer, http.StatusSeeOther)
	default:
		renderErrorPage(w, r, http.StatusMethodNotAllowed, "Méthode HTTP non autorisée.", "ListeAdd méthode non autorisée")
		return
	}
}

func listeDelete(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		c, err := r.Cookie("session_token")
		if err != nil {
			renderErrorPage(w, r, http.StatusUnauthorized, "Vous devez être connecté pour effectuer cette action.", "listeDelete cookie session_token absente")
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			renderErrorPage(w, r, http.StatusUnauthorized, "Votre session a expiré, reconnectez-vous.", "listeDelete session invalide ou expirée")
			return
		}

		referer := r.Header.Get("Referer")
		if referer == "" {
			referer = "/home"
		}

		idstr := r.FormValue("id")

		id, err := strconv.Atoi(idstr)
		if err != nil {
			renderErrorPage(w, r, http.StatusBadRequest, "Identifiant d'élément invalide.", "listeDelete conversion id: "+err.Error())
			return
		}

		if err = db.Where("id_users = ? AND id = ?", sess.Userid, id).Delete(&models.Liste{}).Error; err != nil {
			renderErrorPage(w, r, http.StatusInternalServerError, "Impossible de supprimer cet élément de la liste.", "delete liste: "+err.Error())
			return
		}

		http.Redirect(w, r, referer, http.StatusSeeOther)
	default:
		renderErrorPage(w, r, http.StatusMethodNotAllowed, "Méthode HTTP non autorisée.", "listeDelete méthode non autorisée")
		return
	}
}

func main() {
	if os.Getenv("RESEND_API_KEY") == "" {
		log.Println("ℹ️ RESEND_API_KEY non défini")
	} else {
		log.Println("ℹ️ Resend configuré")
	}

	if err = loadCategorieAPI(os.Getenv("API_CAT")); err != nil {
		log.Printf("API cat warning: %v", err)
	}

	if err = connectDB(); err != nil {
		log.Fatal("erreur db connexion: ", err)
	}

	tpl, err = parseTemplates()
	if err != nil {
		log.Fatal("erreur template", err)
	}

	fs := http.FileServer(http.Dir("../frontend"))
	http.Handle("/CSS/", http.StripPrefix("/", fs))

	http.HandleFunc("/", acceuilHandle)
	http.HandleFunc("/login", loginHandle)
	http.HandleFunc("/register", registerhandle)
	http.HandleFunc("/verify", verifyHandle)

	http.HandleFunc("/home", requireAuth(homeHandle))
	http.HandleFunc("/categorie", requireAuth(categorieHandle))
	http.HandleFunc("/meals", requireAuth(recetteHandle))
	http.HandleFunc("/search", searchHandle)
	http.HandleFunc("/addfavoris", requireAuth(addfavorisHandle))
	http.HandleFunc("/favoris", requireAuth(favorisHandle))
	http.HandleFunc("/deletefavoris", requireAuth(deletefavorisHandle))
	http.HandleFunc("/addcommentaire", requireAuth(addCom))
	http.HandleFunc("/deletecommentaire", requireAuth(deleteCom))
	http.HandleFunc("/liste", requireAuth(listeHandle))
	http.HandleFunc("/liste/add", requireAuth(ListeAdd))
	http.HandleFunc("/liste/update", requireAuth(listeUpdate)) // ✅ CHECKBOX UPDATE !
	http.HandleFunc("/liste/delete", requireAuth(listeDelete))

	// Récupérer le port via Render, sinon 8080 pour le local
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("🚀 Serveur prêt sur le port %s", port)

	// TRÈS IMPORTANT : il faut que l'app écoute sur 0.0.0.0 pour Render
	log.Fatal(http.ListenAndServe("0.0.0.0:"+port, nil))
}

// ✅ MIDDLEWARE SIMPLE (fonctionne sans Chi)
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session_token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if _, authErr := hydrateSessionFromJWT(c.Value); authErr != nil {
			delete(sessions, c.Value)
			log.Printf("requireAuth refusé: %v", authErr)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}
