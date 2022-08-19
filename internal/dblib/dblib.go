package dblib

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

type Mysql struct {
	*sql.DB
	Ip       string
	Database string
	User     string
	Passwd   string
	Port     int
}

//NewMysql 產生一個DB
func NewMysql(ip string) *Mysql {
	//初始化
	m := &Mysql{
		DB:       nil,
		Ip:       ip,
		Database: " ",
		User:     " ",
		Passwd:   " ",
		Port:     0,
	}
	return m
}

func (m *Mysql) DBOpen(dataSourceName string) error {
	var err error
	m.DB, err = sql.Open("mysql", dataSourceName)
	if err != nil {
		return err
	}
	return nil
}
