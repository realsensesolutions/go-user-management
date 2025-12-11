package user

func NewRepository() Repository {
	return NewSQLiteRepository()
}

