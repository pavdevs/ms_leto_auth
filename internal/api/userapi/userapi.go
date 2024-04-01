package userapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"com.pavdevs.learningservice/internal/repositories/repositorycontainer"
	"com.pavdevs.learningservice/internal/repositories/userrepository"
	"com.pavdevs.learningservice/internal/services/bcryptservice"
	producer "com.pavdevs.learningservice/internal/services/producerservice"
	"com.pavdevs.learningservice/internal/services/tokenservice"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type UserHandler struct {
	userRepository *userrepository.UserRepository
	logger         *logrus.Logger
	producer       *producer.KafkaProducer
}

func NewUserHandler(repositorycontainer *repositorycontainer.RepositoryContainer, logger *logrus.Logger, producer *producer.KafkaProducer) *UserHandler {
	return &UserHandler{
		userRepository: repositorycontainer.UserRepository,
		logger:         logger,
		producer:       producer,
	}
}

func (uh *UserHandler) Register(router *mux.Router) {
	router.HandleFunc("/users/signin", uh.SignIn).Methods(http.MethodPost)
	router.HandleFunc("/users/signup", uh.SignUp).Methods(http.MethodPost)
	router.HandleFunc("/users/me", uh.Get).Methods(http.MethodGet)
	router.HandleFunc("/users/user", uh.Delete).Methods(http.MethodDelete)
	router.HandleFunc("/users/refresh", uh.GetAccessWithRefresh).Methods(http.MethodPost)
}

// @Summary SignIn
// @Tags Users
// @Description SignIn with JSON payload in the request body
// @ID signin_user
// @Accept json
// @Produce json
// @Param {object} body SignInRequest true "User object to create"
// @Success 201 {object} SignInResponse "User created successfully"
// @Failure 400 {object} ServerError "Invalid request or JSON format"
// @Failure 500 {object} ServerError "Internal server error"
// @Router /users/signin [post]
func (uh *UserHandler) SignIn(w http.ResponseWriter, r *http.Request) {
	var user userrepository.User
	var requestUser SignInRequest
	decodeErr := json.NewDecoder(r.Body).Decode(&requestUser)

	w.Header().Set("Content-Type", "application/json")

	if decodeErr != nil {
		encodeErrorResponse(decodeErr, w, uh.logger, http.StatusBadRequest)
		return
	}

	user = userrepository.User{
		FirstName: requestUser.FirstName,
		LastName:  requestUser.LastName,
		Email:     requestUser.Email,
		Password:  requestUser.Password,
	}

	createErr := uh.userRepository.CreateUser(&user)

	if createErr != nil {
		encodeErrorResponse(createErr, w, uh.logger, http.StatusBadRequest)
		return
	}

	accessToken, accErr := tokenservice.NewAccessToken(*tokenservice.NewUserClaims(user.ID, user.FirstName, user.LastName, user.Email))

	if accErr != nil {
		encodeErrorResponse(accErr, w, uh.logger, http.StatusBadRequest)
		return
	}

	refreshToken, refErr := tokenservice.NewRefreshToken(*tokenservice.NewStandartClaims())

	if refErr != nil {
		encodeErrorResponse(refErr, w, uh.logger, http.StatusBadRequest)
		return
	}

	if responseEncodingErr := json.NewEncoder(w).Encode(
		SignInResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	); responseEncodingErr != nil {
		encodeErrorResponse(responseEncodingErr, w, uh.logger, http.StatusInternalServerError)
		return
	}

	uuidV4, uuidErr := uuid.NewRandom()

	if uuidErr != nil {
		uh.logger.Error(uuidErr)
		return
	}

	if sendPrErr := uh.producer.SendMessage(uuidV4.String(), "signin user success"); sendPrErr != nil {
		uh.logger.Error(sendPrErr)
	}

	w.WriteHeader(http.StatusCreated)
}

// @Summary SignUp
// @Tags Users
// @Description SignUp with JSON payload in the request body
// @ID signup_user
// @Accept json
// @Produce json
// @Param {object} body SignUpRequest true "User object to create"
// @Success 200 {object} SignUpResponse "User created successfully"
// @Failure 400 {object} ServerError "Invalid request or JSON format"
// @Failure 500 {object} ServerError "Internal server error"
// @Router /users/signup [post]
func (uh *UserHandler) SignUp(w http.ResponseWriter, r *http.Request) {

	var requestUser SignUpRequest
	decodeErr := json.NewDecoder(r.Body).Decode(&requestUser)

	w.Header().Set("Content-Type", "application/json")

	if decodeErr != nil {
		encodeErrorResponse(decodeErr, w, uh.logger, http.StatusBadRequest)
		return
	}

	user, findErr := uh.userRepository.GetUser(requestUser.Email)

	if findErr != nil && user == nil {
		encodeErrorResponse(findErr, w, uh.logger, http.StatusBadRequest)
		return
	}

	comparePassErr := bcryptservice.ComparePassword([]byte(user.Password), []byte(requestUser.Password))

	if comparePassErr != nil {
		encodeErrorResponse(findErr, w, uh.logger, http.StatusBadRequest)
		return
	}

	accessToken, accErr := tokenservice.NewAccessToken(*tokenservice.NewUserClaims(user.ID, user.FirstName, user.LastName, user.Email))

	if accErr != nil {
		encodeErrorResponse(accErr, w, uh.logger, http.StatusBadRequest)
		return
	}

	refreshToken, refErr := tokenservice.NewRefreshToken(*tokenservice.NewStandartClaims())

	if refErr != nil {
		encodeErrorResponse(refErr, w, uh.logger, http.StatusBadRequest)
		return
	}

	if responseEncodingErr := json.NewEncoder(w).Encode(
		SignUpResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	); responseEncodingErr != nil {
		encodeErrorResponse(responseEncodingErr, w, uh.logger, http.StatusInternalServerError)
		return
	}

	uuidV4, uuidErr := uuid.NewRandom()

	if uuidErr != nil {
		uh.logger.Error(uuidErr)
		return
	}

	if sendPrErr := uh.producer.SendMessage(uuidV4.String(), "signup user success"); sendPrErr != nil {
		uh.logger.Error(sendPrErr)
	}

	w.WriteHeader(http.StatusOK)
}

// @Summary Get user
// @Security ApiKeyAuth
// @Tags Users
// @Description Get information about current user
// @ID get_user
// @Accept json
// @Produce json
// @Success 200 {object} GetUserResponse "User get successfully"
// @Failure 400 {object} ServerError "Invalid request or JSON format"
// @Failure 401 {object} ServerError "Unauthorized"
// @Failure 500 {object} ServerError "Internal server error"
// @Router /users/me [get]
func (uh *UserHandler) Get(w http.ResponseWriter, r *http.Request) {

	user, authErr := uh.checkAuthToken(r)

	if authErr != nil {
		encodeErrorResponse(authErr, w, uh.logger, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	getUserResponse := GetUserResponse{
		Id:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
	}

	if responseEncodingErr := json.NewEncoder(w).Encode(getUserResponse); responseEncodingErr != nil {
		encodeErrorResponse(responseEncodingErr, w, uh.logger, http.StatusInternalServerError)
		return
	}

	uuidV4, uuidErr := uuid.NewRandom()

	if uuidErr != nil {
		uh.logger.Error(uuidErr)
		return
	}

	if sendPrErr := uh.producer.SendMessage(uuidV4.String(), "get user success"); sendPrErr != nil {
		uh.logger.Error(sendPrErr)
	}

	w.WriteHeader(http.StatusOK)
}

// @Summary Change user
// @Security ApiKeyAuth
// @Tags Users
// @Description Change user informaion in JSON payload in the request body
// @ID change_user
// @Accept json
// @Produce json
// @Param {object} body ChangeUserRequest true "User object updated"
// @Success 200 {object} ChangeUserResponse "User created successfully"
// @Failure 400 {object} ServerError "Invalid request or JSON format"
// @Failure 401 {object} ServerError "Unauthorized"
// @Failure 500 {object} ServerError "Internal server error"
// @Router /users/user [put]
func (uh *UserHandler) Update(w http.ResponseWriter, r *http.Request) {

	user, authErr := uh.checkAuthToken(r)

	w.Header().Set("Content-Type", "application/json")

	if authErr != nil {
		encodeErrorResponse(authErr, w, uh.logger, http.StatusUnauthorized)
		return
	}

	var changeUserRequest ChangeUserRequest
	decodeErr := json.NewDecoder(r.Body).Decode(&changeUserRequest)

	if decodeErr != nil {
		encodeErrorResponse(decodeErr, w, uh.logger, http.StatusBadRequest)
		return
	}

	user.Email = changeUserRequest.Email
	user.FirstName = changeUserRequest.FirstName
	user.LastName = changeUserRequest.LastName

	updateErr := uh.userRepository.UpdateUser(user)

	if updateErr != nil {
		encodeErrorResponse(updateErr, w, uh.logger, http.StatusBadRequest)
		return
	}

	changeUserResponse := ChangeUserResponse(changeUserRequest)

	if responseEncodingErr := json.NewEncoder(w).Encode(changeUserResponse); responseEncodingErr != nil {
		encodeErrorResponse(responseEncodingErr, w, uh.logger, http.StatusInternalServerError)
		return
	}

	uuidV4, uuidErr := uuid.NewRandom()

	if uuidErr != nil {
		uh.logger.Error(uuidErr)
		return
	}

	if sendPrErr := uh.producer.SendMessage(uuidV4.String(), "update user success"); sendPrErr != nil {
		uh.logger.Error(sendPrErr)
	}

	w.WriteHeader(http.StatusOK)
}

// @Summary Delete user
// @Security ApiKeyAuth
// @Tags Users
// @Description Delete user
// @ID delete_user
// @Accept json
// @Produce json
// @Success 200 {object} DeleteUserResponse "User created successfully"
// @Failure 400 {object} ServerError "Invalid request or JSON format"
// @Failure 401 {object} ServerError "Unauthorized"
// @Failure 500 {object} ServerError "Internal server error"
// @Router /users/user [delete]
func (uh *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {

	user, authErr := uh.checkAuthToken(r)

	w.Header().Set("Content-Type", "application/json")

	if authErr != nil {
		encodeErrorResponse(authErr, w, uh.logger, http.StatusUnauthorized)
		return
	}

	deleteErr := uh.userRepository.DeleteUser(user.Email)

	if deleteErr != nil {
		encodeErrorResponse(deleteErr, w, uh.logger, http.StatusBadRequest)
		return
	}

	deleteUserResponse := DeleteUserResponse{
		Message: "User deleted successfully",
	}

	if responseEncodingErr := json.NewEncoder(w).Encode(deleteUserResponse); responseEncodingErr != nil {
		encodeErrorResponse(responseEncodingErr, w, uh.logger, http.StatusInternalServerError)
		return
	}

	uuidV4, uuidErr := uuid.NewRandom()

	if uuidErr != nil {
		uh.logger.Error(uuidErr)
		return
	}

	if sendPrErr := uh.producer.SendMessage(uuidV4.String(), "signin delete success"); sendPrErr != nil {
		uh.logger.Error(sendPrErr)
	}

	w.WriteHeader(http.StatusOK)
}

// @Summary Get access token with refresh token
// @Security ApiKeyAuth
// @Tags Users
// @Description relogout
// @ID refresh_user
// @Accept json
// @Produce json
// @Param {object} body RefreshTokenRequest true "User object to create"
// @Success 200 {object} RefreshTokenResponse "Refresh and access token successfully returned"
// @Failure 400 {object} ServerError "Invalid request or JSON format"
// @Failure 401 {object} ServerError "Unauthorized"
// @Failure 500 {object} ServerError "Internal server error"
// @Router /users/refresh [post]
func (uh *UserHandler) GetAccessWithRefresh(w http.ResponseWriter, r *http.Request) {
	var err error

	if err := uh.checkRefreshToken(r); err != nil {
		encodeErrorResponse(err, w, uh.logger, http.StatusBadRequest)
		return
	}

	user, err := uh.checkAuthToken(r)

	if err != nil {
		encodeErrorResponse(err, w, uh.logger, http.StatusBadRequest)
		return
	}

	accessToken, err := tokenservice.NewAccessToken(*tokenservice.NewUserClaims(user.ID, user.FirstName, user.LastName, user.Email))

	if err != nil {
		encodeErrorResponse(err, w, uh.logger, http.StatusBadRequest)
		return
	}

	refreshToken, err := tokenservice.NewRefreshToken(*tokenservice.NewStandartClaims())

	if err != nil {
		encodeErrorResponse(err, w, uh.logger, http.StatusBadRequest)
		return
	}

	response := RefreshTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	if responseEncodingErr := json.NewEncoder(w).Encode(response); responseEncodingErr != nil {
		encodeErrorResponse(responseEncodingErr, w, uh.logger, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// MARK: - Private functions
func encodeErrorResponse(
	err error,
	w http.ResponseWriter,
	logger *logrus.Logger,
	code int,
) {
	w.WriteHeader(http.StatusInternalServerError)
	logger.Error(err)
	json.NewEncoder(w).Encode(
		ServerError{
			Message: "Something went wrong",
			Code:    code,
		},
	)
}

func (uh *UserHandler) checkAuthToken(r *http.Request) (*userrepository.User, error) {

	tokenString := r.Header.Get("Authorization")
	splitToken := strings.Split(tokenString, "Bearer ")

	if len(splitToken) != 2 {
		return nil, errors.New("invalid token format")
	}

	reqToken := splitToken[1]

	userClaims, err := tokenservice.ParseAccessToken(reqToken)

	if err != nil {
		return nil, errors.New("invalid token format")
	}

	user, findErr := uh.userRepository.GetUser(userClaims.Email)

	if findErr != nil && user == nil {
		return nil, errors.New("invalid user in token")
	}

	return user, nil
}

func (uh *UserHandler) checkRefreshToken(r *http.Request) error {
	var refreshReuest RefreshTokenRequest
	decodeErr := json.NewDecoder(r.Body).Decode(&refreshReuest)

	if decodeErr != nil {
		return errors.New("invalid body")
	}

	stdClaims, refErr := tokenservice.ParseRefreshToken(refreshReuest.RefreshToken)

	if refErr != nil {
		return errors.New("invalid refresh token format")
	}

	uh.logger.Info(stdClaims)

	return nil
}
