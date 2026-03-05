package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"

	// import interne
	"yboost/models"
)

var err error
var tpl *template.Template
var db *sql.DB
var sessions = map[string]models.Session{}

var ApiCategorie []models.Food_categorie
var ApiFoodlist []models.Food_affichage
var ApiRecette []models.Recette

func SendEmail(to, subject, body string) error {
	// Récupération de la config SMTP dans les variables d'environnement.
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPortStr := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")
	from := os.Getenv("SMTP_FROM")

	if smtpHost == "" || smtpPortStr == "" || smtpUser == "" || smtpPass == "" || from == "" {
		return fmt.Errorf("configuration SMTP manquante (vérifie SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM)")
	}

	// Conversion du port en int.
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

func connectDB() (*sql.DB, error) {
	dsn := os.Getenv("DB_DSN")
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
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

		rows, err := db.Query("SELECT pass_hash, id FROM users WHERE email = ?", &p.Email)
		if err != nil {
			fmt.Println("erreur de select db", err)
			return
		}
		defer rows.Close()

		if rows.Next() == false {
			data.Errmsg = "Mots de passe ou email incorrect"
			tpl.ExecuteTemplate(w, "login.html", data)
			return
		} else {
			//var emaildb strin
			if err := rows.Scan(&p.PasswordHash, &p.Id); err != nil {
				log.Fatal(err)
			}
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
		/*err = SendVerificationEmail(email, Code)
		if err != nil {
			fmt.Println("erreur dans l'envoie du mail")
			return
		}*/

		_, err = db.Query("INSERT INTO email_verification (users_id, verify_token, verify_expires_at, is_verified) VALUES (?,?,?,0)", &p.Id, &Code, &expiresAt)
		if err != nil {
			http.Error(w, "erreur insert db email", http.StatusInternalServerError)
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

		_, err = db.Exec("INSERT INTO users(email, pass_hash, first_name, last_name, created_at) VALUES(?,?,?,?,NOW())", &p.Email, &hashed, &p.FirstName, &p.LastName)
		if err != nil {
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

		if err = db.QueryRow("SELECT id, verify_token , verify_expires_at, is_verified FROM email_verification WHERE users_id = ? ORDER BY id DESC LIMIT 1",
			&p.Id).Scan(&m.Id, &m.Verify_token, &m.Verify_expires_at, &m.Is_verified); err != nil {
			http.Redirect(w, r, "/verify?User_id="+idstr+"&error=code", http.StatusSeeOther)
			return
		}

		if m.Verify_token != code || m.Is_verified != 0 || time.Now().After(m.Verify_expires_at) {
			http.Redirect(w, r, "/verify?User_id="+idstr+"&error=code", http.StatusSeeOther)
			return
		}

		fmt.Println("code bon gg !")

		_, err = db.Query("UPDATE email_verification SET is_verified = 1 WHERE users_id = ? AND verify_token = ? AND id = ? ", &m.User_id, &m.Verify_token, &m.Id)
		if err != nil {
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

		users_id := strconv.Itoa(sess.Userid)

		id := r.FormValue("id")
		name := r.FormValue("name")
		categorie := r.FormValue("categorie")
		origine := r.FormValue("origine")
		thrumb := r.FormValue("Thumb")
		_, err = db.Exec("INSERT INTO favoris (id,users_id,name,categorie,origine,thrumb) VALUES (?,?,?,?,?,?)", &id, &users_id, &name, &categorie, &origine, &thrumb)
		if err != nil {
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
	rows, err := db.Query("SELECT * FROM favoris WHERE users_id = ?", &User_id)
	if err != nil {
		println("erreur select all favoris n1")
	}

	defer rows.Close()

	for rows.Next() {
		var f models.Favoris
		if err = rows.Scan(&f.Id, &f.User_id, &f.Name, &f.Categorie, &f.Origine, &f.Thumb); err != nil {
			println("erreur select all favoris n2")
		}
		liste = append(liste, f)
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
		idstr := r.FormValue("id")
		id, err := strconv.Atoi(idstr)
		if err != nil {
			http.Error(w, "erreur de convertion", http.StatusInternalServerError)
		}

		_, err = db.Exec("DELETE FROM favoris WHERE users_id = ? AND id = ? AND name = ?", &sess.Userid, &id, &name)
		if err != nil {
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
		_, err = db.Exec("INSERT INTO commentaire(users_id,data_string,meal_id) VALUES (?,?,?)", &sess.Userid, &dataCom, &id)
		if err != nil {
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
	rows, err := db.Query("SELECT * FROM commentaire WHERE meal_id = ?", id)
	if err != nil {
		println("erreur select")
	}

	defer rows.Close()

	for rows.Next() {
		var c models.Commentaire
		rows.Scan(&c.Id, &c.Users_id, &c.Data_string, &c.Meal_id)
		Listallcommentaire = append(Listallcommentaire, c)
	}
	println(Listallcommentaire)
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

		_, err = db.Exec("DELETE FROM commentaire WHERE users_id = ? AND id = ?", &sess.Userid, &id)
		if err != nil {
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
		rows, err := db.Query("SELECT * FROM liste WHERE id_users = ?", sess.Userid) // Sans &
		if err != nil {
			log.Printf("DB erreur: %v", err)
			http.Error(w, "Erreur serveur", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var l models.Liste
			if err := rows.Scan(&l.Id, &l.Id_users, &l.Aliment, &l.Nombre, &l.Unite, &l.Prix, &l.Is_finish); err != nil {
				log.Printf("Scan erreur: %v", err)
				continue
			}
			Liste = append(Liste, l)
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
	total := 0.00
	rows, err := db.Query("SELECT prix FROM liste WHERE id_users = ?", &id_users)
	if err != nil {
		return total, err
	}

	defer rows.Close()

	for rows.Next() {
		var n float64
		if err = rows.Scan(&n); err != nil {
			return total, err
		}

		total += n
	}

	return total, err
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
	_, err = db.Exec("UPDATE liste SET is_finish = ? WHERE id = ? AND id_users = ?",
		isFinish, id, sess.Userid)
	if err != nil {
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
			Aliment: r.FormValue("aliment"),
			Nombre:  nombre,
			Prix:    prix,
			Unite:   r.FormValue("unite"),
		}

		_, err = db.Exec("INSERT INTO liste (id_users, aliment, nombre, unite, prix) VALUES (?,?,?,?,?)", &sess.Userid, &l.Aliment, &l.Nombre, &l.Unite, &l.Prix)
		if err != nil {
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
		}

		_, err = db.Exec("DELETE FROM liste WHERE id_users = ? AND id = ?", &sess.Userid, &id)
		if err != nil {
			http.Error(w, "erreur de delete", http.StatusInternalServerError)
		}

		http.Redirect(w, r, referer, http.StatusSeeOther)
	default:
		http.Error(w, "Méthode non autoriser", http.StatusMethodNotAllowed)
		return
	}
}

func main() {
	err = godotenv.Load(".env")
	if err != nil {
		log.Fatal("erreur .env", err)
	}

	if err = loadCategorieAPI(os.Getenv("API_CAT")); err != nil {
		log.Printf("API cat warning: %v", err)
	}

	db, err = connectDB()
	if err != nil {
		log.Fatal("erreur db connexion", err)
	}
	defer db.Close()

	tpl, err = parseTemplates()
	if err != nil {
		log.Fatal("erreur template", err)
	}

	// ✅ Servir les fichiers statiques (CSS, JS, images, etc.)
	fs := http.FileServer(http.Dir("../frontend"))
	http.Handle("/CSS/", http.StripPrefix("/", fs))

	// ✅ ROUTES SANS CHI (plus simple, fonctionne direct)
	http.HandleFunc("/", acceuilHandle)
	http.HandleFunc("/login", loginHandle)
	http.HandleFunc("/register", registerhandle)
	http.HandleFunc("/verify", verifyHandle)

	// ✅ Routes protégées (session manuelle)
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

	log.Println("🚀 Serveur sur http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
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
