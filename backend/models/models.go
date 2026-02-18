package models

import (
	"strings"
	"time"
)

type Users struct {
	Id           int       `db:"id"`
	Email        string    `db:"email"`
	PasswordHash string    `db:"pass_hash"`
	FirstName    string    `db:"first_name"`
	LastName     string    `db:"last_name"`
	CreatedAt    time.Time `db:"created_at"`
}

type Pagedata struct {
	Errmsg        string
	User_id       int
	Categoriefood []Food_categorie
	Listfood      []Food_affichage
	Recette       []Recette
	Listrandom    []Recette
	Favorisliste  []Favoris
}

type Favoris struct {
	Id        int    `db:"id"`
	User_id   int    `db:"users_id"`
	Name      string `db:"name"`
	Categorie string `db:"categorie"`
	Origine   string `db:"origine"`
	Thumb     string `db:"thrumb"`
}

type Email_verification struct {
	Id                int       `db:"id"`
	User_id           int       `db:"users_id"`
	Verify_token      string    `db:"verify_token"`
	Verify_expires_at time.Time `db:"verify_expires_at"`
	Is_verified       int       `db:"is_verified"`
}

type Session struct {
	Userid int
	Expiry time.Time
}

type CategoriesAPIResponse struct {
	Categories []Food_categorie `json:"categories"`
}

type Food_categorie struct {
	Id          string `json:"idCategory"`
	Name        string `json:"strCategory"`
	Thumb       string `json:"strCategoryThumb"`
	Description string `json:"strCategoryDescription"`
}
type ListFoodApi struct {
	Meals []Food_affichage `json:"meals"`
}

type Food_affichage struct {
	Name  string `json:"strMeal"`
	Thumb string `json:"strMealThumb"`
	Id    string `json:"idMeal"`
}

type ApiRecette struct {
	Recette []Recette `json:"meals"`
}

type Recette struct {
	Id           string  `json:"idMeal"`
	Name         *string `json:"strMeal"`
	NameAlternet *string `json:"strMealAlternate"`
	Categorie    *string `json:"strCategory"`
	Origine      *string `json:"strArea"`
	Instruction  *string `json:"strInstructions"`
	Thumb        *string `json:"strMealThumb"`
	Tags         *string `json:"strTags"`
	Youtube      *string `json:"strYoutube"`

	Ingredient1  string `json:"strIngredient1"`
	Ingredient2  string `json:"strIngredient2"`
	Ingredient3  string `json:"strIngredient3"`
	Ingredient4  string `json:"strIngredient4"`
	Ingredient5  string `json:"strIngredient5"`
	Ingredient6  string `json:"strIngredient6"`
	Ingredient7  string `json:"strIngredient7"`
	Ingredient8  string `json:"strIngredient8"`
	Ingredient9  string `json:"strIngredient9"`
	Ingredient10 string `json:"strIngredient10"`
	Ingredient11 string `json:"strIngredient11"`
	Ingredient12 string `json:"strIngredient12"`
	Ingredient13 string `json:"strIngredient13"`
	Ingredient14 string `json:"strIngredient14"`
	Ingredient15 string `json:"strIngredient15"`
	Ingredient16 string `json:"strIngredient16"`
	Ingredient17 string `json:"strIngredient17"`
	Ingredient18 string `json:"strIngredient18"`
	Ingredient19 string `json:"strIngredient19"`
	Ingredient20 string `json:"strIngredient20"`

	Measure1  string `json:"strMeasure1"`
	Measure2  string `json:"strMeasure2"`
	Measure3  string `json:"strMeasure3"`
	Measure4  string `json:"strMeasure4"`
	Measure5  string `json:"strMeasure5"`
	Measure6  string `json:"strMeasure6"`
	Measure7  string `json:"strMeasure7"`
	Measure8  string `json:"strMeasure8"`
	Measure9  string `json:"strMeasure9"`
	Measure10 string `json:"strMeasure10"`
	Measure11 string `json:"strMeasure11"`
	Measure12 string `json:"strMeasure12"`
	Measure13 string `json:"strMeasure13"`
	Measure14 string `json:"strMeasure14"`
	Measure15 string `json:"strMeasure15"`
	Measure16 string `json:"strMeasure16"`
	Measure17 string `json:"strMeasure17"`
	Measure18 string `json:"strMeasure18"`
	Measure19 string `json:"strMeasure19"`
	Measure20 string `json:"strMeasure20"`

	Source                   *string `json:"strSource"`
	ImageSource              *string `json:"strImageSource"`
	CreativeCommonsConfirmed *string `json:"strCreativeCommonsConfirmed"`
	DateModified             *string `json:"dateModified"`
}

func (r Recette) YoutubeEmbed() string {
	if r.Youtube == nil {
		return ""
	}
	u := *r.Youtube
	return strings.Replace(u, "watch?v=", "embed/", 1)
}
