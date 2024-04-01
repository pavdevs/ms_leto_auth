package database

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
)

type Database struct {
	DB     *sql.DB
	Config Config
	Logger *logrus.Logger
}

func NewDatabase(config Config, logger *logrus.Logger) *Database {
	return &Database{
		Config: config,
		Logger: logger,
	}
}

func (d *Database) Connect() error {
	connectionString := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s", d.Config.Host, d.Config.User, d.Config.DBName, d.Config.SSLMode, d.Config.Password)
	db, err := sql.Open("postgres", connectionString)

	if err != nil {
		d.Logger.Error(err)
		return err
	}

	d.Logger.Info("Database prepared")

	if err := db.Ping(); err != nil {
		d.Logger.Error(err)
		return err
	}

	d.Logger.Info("Database connected")

	d.DB = db

	return nil
}

func (d *Database) Disconnect() {
	if err := d.DB.Close(); err != nil {
		d.Logger.Error(err)
	}

	d.Logger.Info("Database disconnected")
}
