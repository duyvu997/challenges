# Challenges
A simple Go server using Gin with JWT authentication and image upload functionality.  
Includes Swagger documentation for the API.

---

## Features

- User registration with username and password
- JWT login to get access token
- Authenticated image upload (only image files)
- Token revocation (logout) with token blacklist
- Swagger UI for API docs and testing

---

## Environment Variables

- `JWT_SECRET`: Secret key used to sign JWT tokens (required)

Create a `.env` file or set this variable in your environment.

---

## Installation & Run

1. Clone the repo and navigate into it.

2. Install dependencies:

```bash
go mod tidy
```

3. Generate Swagger docs:

```bash
swag init
```

4. Run the server:

```bash
go run main.go
```

5. Swagger UI available at:
```bash 
http://localhost:8080/swagger/index.html
```