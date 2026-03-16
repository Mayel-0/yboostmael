package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	// import interne
	"yboost/models"
)

var err error
var tpl *template.Template
var db *gorm.DB
var sessions = map[string]models.Session{}

var ApiCategorie []models.Food_categorie
var ApiFoodlist []models.Food_affichage
var ApiRecette []models.Recette

func SendEmail(to, subject, body string) error {
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPortStr := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")
	from := os.Getenv("SMTP_FROM")

	if smtpHost == "" || smtpPortStr == "" || smtpUser == "" || smtpPass == "" || from == "" {
		return fmt.Errorf("configuration SMTP manquante (vérifie SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM)")
	}

	var smtpPort int
	_, err := fmt.Sscanf(smtpPortStr, "%d", &smtpPort)
	if err != nil {
		return fmt.Errorf("SMTP_PORT invalide: %w", err)
	}

	// Construction du message.
	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)

	// Dialer SMTP.
	d := gomail.NewDialer(smtpHost, smtpPort, smtpUser, smtpPass)

	// Envoi.
	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("send email: %w", err)
	}

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

	if err := ensureEmailVerificationSchema(); err != nil {
		return fmt.Errorf("préparation schema email_verification: %w", err)
	}

	// 3. Migration (Crée tes tables automatiquement)
	// Ajoute ici tous tes modèles (Users, Favoris, Commentaire...)
	err = db.AutoMigrate(&models.Users{}, &models.Email_verification{}, &models.Favoris{}, &models.Commentaire{}, &models.Liste{})
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
	if err = tpl.ExecuteTemplate(w, "acceuil.html", nil); err != nil {
		http.Error(w, "erreur template", http.StatusInternalServerError)
		return
	}
}

func loginHandle(w http.ResponseWriter, r *http.Request) {
	var p models.Users
	data := models.Pagedata{}
	switch r.Method {
	case http.MethodGet:
		data.Errmsg = ""
		if err = tpl.ExecuteTemplate(w, "login.html", data); err != nil {
			http.Error(w, "erreur template", http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		p.Email = r.FormValue("email")
		password := r.FormValue("password")

		result := db.Select("pass_hash, id").Where("email = ?", p.Email).First(&p)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				data.Errmsg = "Mots de passe ou email incorrect"
				tpl.ExecuteTemplate(w, "login.html", data)
				return
			}
			fmt.Println("erreur de select db", result.Error)
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(p.PasswordHash), []byte(password)); err != nil {
			data.Errmsg = "Mots de passe ou email incorrect"
			tpl.ExecuteTemplate(w, "login.html", data)
			return
		}

		Code, err := generateCode()
		if err != nil {
			http.Error(w, "erreur envoie code", http.StatusInternalServerError)
			return
		}

		expiresAt := time.Now().Add(5 * time.Minute)

		println("voici le code : ", Code)
		err = SendVerificationEmail(p.Email, Code)
		if err != nil {
			log.Printf("erreur envoi email de vérification pour %s: %v", p.Email, err)
			data.Errmsg = "Impossible d'envoyer le code de vérification. Réessaie plus tard."
			if tplErr := tpl.ExecuteTemplate(w, "login.html", data); tplErr != nil {
				http.Error(w, "Erreur lors de l'envoi de l'email : "+err.Error(), http.StatusInternalServerError)
			}
			return
		}

		emailVerif := models.Email_verification{
			User_id:           p.Id,
			Verify_token:      Code,
			Verify_expires_at: expiresAt,
			Is_verified:       false,
		}
		if err := db.Create(&emailVerif).Error; err != nil {
			log.Printf("erreur insert email_verification pour user_id=%d: %v", p.Id, err)
			http.Error(w, "Erreur lors de l'enregistrement du code : "+err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/verify?User_id="+strconv.Itoa(p.Id), http.StatusSeeOther)

	default:
		http.Error(w, "Méthode non autoriser", http.StatusMethodNotAllowed)
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
			http.Error(w, "erreur template", http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Erreur form", http.StatusBadRequest)
			return
		}

		p.Email = r.FormValue("email")
		p.FirstName = r.FormValue("firstname")
		p.LastName = r.FormValue("lastname")
		password := r.FormValue("password")
		passwordV := r.FormValue("passwordV")

		var existingUser models.Users
		if err := db.Select("email").Where("email = ?", p.Email).First(&existingUser).Error; err == nil {
			http.Error(w, "Email deja utiliser", http.StatusBadRequest)
			return
		}

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
		hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "erreur dans le hashed du MDP", http.StatusInternalServerError)
			return
		}

		newUser := models.Users{
			Email:        p.Email,
			PasswordHash: string(hashed),
			FirstName:    p.FirstName,
			LastName:     p.LastName,
			CreatedAt:    time.Now(),
		}
		if err := db.Create(&newUser).Error; err != nil {
			http.Error(w, "ERREUR de Insert db", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)

	default:
		http.Error(w, "Méthode non autoriser", http.StatusMethodNotAllowed)
	}
}

func verifyHandle(w http.ResponseWriter, r *http.Request) {
	var m models.Email_verification
	var p models.Users
	data := models.Pagedata{}
	switch r.Method {
	case http.MethodGet:
		User_idstr := r.URL.Query().Get("User_id")
		User_id, err := strconv.Atoi(User_idstr)
		if err != nil {
			http.Error(w, "erreur de convertion", http.StatusInternalServerError)
			return
		}

		msgerror := r.URL.Query().Get("error")
		if msgerror != "" {
			data.Errmsg = "Code invalide ou expiré"
		} else {
			data.Errmsg = ""
		}
		data.User_id = User_id
		if err = tpl.ExecuteTemplate(w, "verify.html", data); err != nil {
			http.Error(w, "erreur template", http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		idstr := r.FormValue("Users_id")
		p.Id, err = strconv.Atoi(idstr)
		if err != nil {
			http.Error(w, "erreur id users", http.StatusInternalServerError)
			return
		}
		code := r.FormValue("code")

		if err = db.Where("users_id = ?", p.Id).Order("id DESC").First(&m).Error; err != nil {
			http.Redirect(w, r, "/verify?User_id="+idstr+"&error=code", http.StatusSeeOther)
			return
		}

		if m.Verify_token != code || m.Is_verified || time.Now().After(m.Verify_expires_at) {
			http.Redirect(w, r, "/verify?User_id="+idstr+"&error=code", http.StatusSeeOther)
			return
		}

		fmt.Println("code bon gg !")

		if err = db.Model(&models.Email_verification{}).Where("users_id = ? AND verify_token = ? AND id = ?", m.User_id, m.Verify_token, m.Id).Update("is_verified", true).Error; err != nil {
			http.Error(w, "erreur de update code email", http.StatusInternalServerError)
			return
		}

		// we use the "github.com/google/uuid" library to generate UUIDs
		sessionToken := uuid.NewString()
		expiresAt := time.Now().Add(8 * time.Hour)

		sessions[sessionToken] = models.Session{
			Userid: p.Id,
			Expiry: expiresAt,
		}

		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   sessionToken,
			Expires: expiresAt,
		})

		http.Redirect(w, r, "/home", http.StatusSeeOther)
	default:
		http.Error(w, "Méhode non autoriser", http.StatusMethodNotAllowed)
		return
	}
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
			http.Error(w, "Non connecté", http.StatusUnauthorized)
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			http.Error(w, "Session invalide", http.StatusUnauthorized)
			return
		}

		listrandom, err := loadRandomRecettes(20)
		if err != nil {
			http.Error(w, "Erreur de random", http.StatusInternalServerError)
			return
		}
		data.Listrandom = listrandom

		liste := getallfavoris(sess.Userid)

		data.Favorisliste = liste

		// ✅ Vérifier AVANT d'écrire
		if err = tpl.ExecuteTemplate(w, "home.html", data); err != nil {
			log.Printf("Erreur template home: %v", err) // Log seulement
			http.Error(w, "erreur template", http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "Méthode non autoriser", http.StatusMethodNotAllowed)
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
		fmt.Println("decode error:", err)
		return err
	}
	fmt.Println("len search =", len(apiResp.Recette))
	ApiRecette = apiResp.Recette
	return nil
}

func searchHandle(w http.ResponseWriter, r *http.Request) {
	data := models.Pagedata{}
	namestr := r.FormValue("name")
	print(namestr)
	encoded := url.QueryEscape(namestr)
	url := os.Getenv("API_SEARCH") + encoded
	print(url)

	err = ApiSearch(url)
	if err != nil {
		http.Error(w, "erreur de Apisearch", http.StatusInternalServerError)
		return
	}

	data.Recette = ApiRecette
	if err = tpl.ExecuteTemplate(w, "meals.html", data); err != nil {
		http.Error(w, "erreur template", http.StatusInternalServerError)
		return
	}
}

func categorieHandle(w http.ResponseWriter, r *http.Request) {
	data := models.Pagedata{}
	switch r.Method {
	case http.MethodGet:
		categorienamestr := r.URL.Query().Get("categorie")

		url := os.Getenv("API_FOOD") + categorienamestr

		err = loadListeFood(url)
		if err != nil {
			return
		}

		data.Listfood = ApiFoodlist

		if err = tpl.ExecuteTemplate(w, "categoriefood.html", data); err != nil {
			http.Error(w, "erreur template", http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "Méthode non autoriser", http.StatusMethodNotAllowed)
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
			http.Error(w, "Non connecté", http.StatusUnauthorized)
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			http.Error(w, "Session invalide", http.StatusUnauthorized)
			return
		}

		recetteidstr := r.URL.Query().Get("recette")
		recetteid, err := strconv.Atoi(recetteidstr)
		if err != nil {
			http.Error(w, "erreur de convertisseur", http.StatusInternalServerError)
			return
		}

		url := os.Getenv("API_BYID") + recetteidstr
		err = ApiRecettefunc(url)
		if err != nil {
			http.Error(w, "erreur de api recette", http.StatusInternalServerError)
			return
		}

		Liste := GetCommentaireById(recetteid)
		data.Listecommentaire = Liste
		data.Recette = ApiRecette
		data.User_id = sess.Userid

		// ✅ TOUT est prêt → MAINTENANT on écrit
		if err = tpl.ExecuteTemplate(w, "meals.html", data); err != nil {
			log.Printf("Erreur template recette: %v", err)
			http.Error(w, "erreur template", http.StatusInternalServerError)
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
	fmt.Println(resp.Body)

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
			http.Error(w, "Non connecté", http.StatusUnauthorized)
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			http.Error(w, "Session invalide", http.StatusUnauthorized)
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
			http.Error(w, "erreur d'insert", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, referer, http.StatusSeeOther)
	default:
		http.Error(w, "Méthode non autoriser", http.StatusMethodNotAllowed)
		return
	}
}

func favorisHandle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		data := models.Pagedata{}

		c, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "Non connecté", http.StatusUnauthorized)
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			http.Error(w, "Session invalide", http.StatusUnauthorized)
			return
		}

		//users_id := strconv.Itoa(sess.Userid)

		liste := getallfavoris(sess.Userid)

		data.Favorisliste = liste

		if err = tpl.ExecuteTemplate(w, "favoris.html", data); err != nil {
			http.Error(w, "erreur template", http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "Méthode non autoriser", http.StatusMethodNotAllowed)
		return
	}
}

func getallfavoris(User_id int) []models.Favoris {
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
			http.Error(w, "Non connecté", http.StatusUnauthorized)
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			http.Error(w, "Session invalide", http.StatusUnauthorized)
			return
		}

		name := r.FormValue("name")
		id := r.FormValue("id")

		if err = db.Where("users_id = ? AND id = ? AND name = ?", sess.Userid, id, name).Delete(&models.Favoris{}).Error; err != nil {
			http.Error(w, "erreur de delete", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/favoris", http.StatusSeeOther)
	default:
		http.Error(w, "Méthode non autoriser", http.StatusMethodNotAllowed)
		return
	}
}

func addCom(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var last_name string
		var first_name string
		referer := r.Header.Get("Referer")
		print(referer)
		if referer == "" {
			referer = "/" // Fallback si pas de referer
		}

		c, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "Non connecté", http.StatusUnauthorized)
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			http.Error(w, "Session invalide", http.StatusUnauthorized)
			return
		}

		dataCom := r.FormValue("data")
		idstr := r.FormValue("id")
		id, err := strconv.Atoi(idstr)
		if err != nil {
			println("erreur de conv")
		}

		var user models.Users
		if err = db.Select("first_name, last_name").Where("id = ?", sess.Userid).First(&user).Error; err != nil {
			http.Error(w, "select users name", http.StatusInternalServerError)
			return
		}
		first_name = user.FirstName
		last_name = user.LastName

		commentaire := models.Commentaire{
			Users_id:    sess.Userid,
			Data_string: dataCom,
			Meal_id:     id,
			First_name:  first_name,
			Last_name:   last_name,
		}
		if err = db.Create(&commentaire).Error; err != nil {
			http.Error(w, "Erreur d'insert", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, referer, http.StatusSeeOther)
	default:
		http.Error(w, "Méthode non autoriser", http.StatusMethodNotAllowed)
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
			http.Error(w, "Non connecté", http.StatusUnauthorized)
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			http.Error(w, "Session invalide", http.StatusUnauthorized)
			return
		}

		idstr := r.FormValue("id")
		id, err := strconv.Atoi(idstr)
		if err != nil {
			http.Error(w, "erreur convertion", http.StatusInternalServerError)
			return
		}

		referer := r.Header.Get("Referer")
		if referer == "" {
			referer = "/home"
		}

		if err = db.Where("users_id = ? AND id = ?", sess.Userid, id).Delete(&models.Commentaire{}).Error; err != nil {
			http.Error(w, "Erreur delete", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, referer, http.StatusSeeOther)
	default:
		http.Error(w, "Méthode non autoriser", http.StatusMethodNotAllowed)
		return
	}
}

func listeHandle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "Non connecté", http.StatusUnauthorized)
			return
		}
		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			http.Error(w, "Session invalide", http.StatusUnauthorized)
			return
		}

		var Liste []models.Liste
		if err := db.Where("id_users = ?", sess.Userid).Find(&Liste).Error; err != nil {
			log.Printf("DB erreur: %v", err)
			http.Error(w, "Erreur serveur", http.StatusInternalServerError)
			return
		}

		prixTotal, err := TotalPrix(sess.Userid)
		if err != nil {
			log.Printf("TotalPrix erreur: %v", err)
			prixTotal = 0
		}

		data := models.Pagedata{Liste: Liste, PrixTotal: prixTotal}
		tpl.ExecuteTemplate(w, "liste.html", data)
	default:
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
	}
}

func TotalPrix(id_users int) (float64, error) {
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
			http.Error(w, "Non connecté", http.StatusUnauthorized)
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			http.Error(w, "Session invalide", http.StatusUnauthorized)
			return
		}

		referer := r.Header.Get("Referer")
		if referer == "" {
			referer = "/home"
		}

		nombrestr := r.FormValue("nombre")
		nombre, err := strconv.ParseFloat(nombrestr, 64)
		if err != nil {
			http.Error(w, "Erreur de convertion", http.StatusInternalServerError)
			return
		}
		prixstr := r.FormValue("prix")
		prix, err := strconv.ParseFloat(prixstr, 64)
		if err != nil {
			http.Error(w, "Erreur de convertion", http.StatusInternalServerError)
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
			http.Error(w, "Erreur de insert", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, referer, http.StatusSeeOther)
	default:
		http.Error(w, "Méthode non autoriser", http.StatusMethodNotAllowed)
		return
	}
}

func listeDelete(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		c, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "Non connecté", http.StatusUnauthorized)
			return
		}

		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			http.Error(w, "Session invalide", http.StatusUnauthorized)
			return
		}

		referer := r.Header.Get("Referer")
		if referer == "" {
			referer = "/home"
		}

		idstr := r.FormValue("id")

		id, err := strconv.Atoi(idstr)
		if err != nil {
			http.Error(w, "erreur de conv", http.StatusInternalServerError)
			return
		}

		if err = db.Where("id_users = ? AND id = ?", sess.Userid, id).Delete(&models.Liste{}).Error; err != nil {
			http.Error(w, "erreur de delete", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, referer, http.StatusSeeOther)
	default:
		http.Error(w, "Méthode non autoriser", http.StatusMethodNotAllowed)
		return
	}
}

func main() {
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
	http.HandleFunc("/liste/update", listeUpdate) // ✅ CHECKBOX UPDATE !
	http.HandleFunc("/liste/delete", listeDelete)

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
		sess, exists := sessions[c.Value]
		if !exists || time.Now().After(sess.Expiry) {
			delete(sessions, c.Value)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}
