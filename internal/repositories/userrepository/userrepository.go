package userrepository

import (
	"database/sql"
	"errors"

	database "com.pavdevs.learningservice/internal/database"
	"com.pavdevs.learningservice/internal/services/bcryptservice"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
)

type UserRepository struct {
	database *database.Database
	logger   *logrus.Logger
}

func NewUserRepository(db *database.Database, logger *logrus.Logger) *UserRepository {
	return &UserRepository{
		database: db,
		logger:   logger,
	}
}

func (u *UserRepository) CreateUser(user *User) error {
	hashedPassword, err := bcryptservice.EncryptPassword(user.Password)

	if err != nil {
		u.logger.Error("Ошибка создания хэша пароля", err)
		return err
	}

	u.logger.Info("Хэш пароля: ", string(hashedPassword))
	u.logger.Info(user)

	if pingErr := u.database.DB.Ping(); pingErr != nil {
		u.logger.Error("Ошибка пинга базы", pingErr)
		return pingErr
	}

	query := "INSERT INTO users (first_name, last_name, email, encrypted_password) VALUES ($1, $2, $3, $4)"

	_, db_err := u.database.DB.Exec(query, user.FirstName, user.LastName, user.Email, hashedPassword)

	if db_err != nil {
		u.logger.Error("Ошибка создания пользователя", db_err)
		return db_err
	}

	return nil
}

func (u *UserRepository) GetUser(email string) (*User, error) {
	query := "SELECT id, first_name, last_name, email, encrypted_password FROM users WHERE email = $1"
	row := u.database.DB.QueryRow(query, email)
	user := &User{}
	err := row.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.Password)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return user, nil
}

func (u *UserRepository) UpdateUser(user *User) error {
	query := "UPDATE users SET first_name = $1, last_name = $2, email = $3 WHERE id = $4"
	_, err := u.database.DB.Exec(query, user.FirstName, user.LastName, user.Email, user.ID)

	if err != nil {
		return err
	}

	return nil
}

func (u *UserRepository) DeleteUser(email string) error {
	query := "DELETE FROM users WHERE email = $1"
	_, err := u.database.DB.Exec(query, email)

	if err != nil {
		return err
	}

	return nil
}

func (u *UserRepository) GetUsers() ([]User, error) {
	query := "SELECT id, first_name, last_name, email FROM users"
	rows, err := u.database.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		user := User{}
		err := rows.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}
