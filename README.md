

# Setup Database

## Database queries for initial setup

```
create user 'shubham'@'localhost';
create database userservice;
grant all privileges on userservice.* to 'shubham'@'localhost';
```


# User API Documentation

## Base URL

```
http://localhost:9000/users
```

## Authentication

This API uses **OAuth 2.0 with JWT tokens** for authentication. Clients must include a **Bearer Token** in the `Authorization` header for protected endpoints.

**Sample Header:**

```
Authorization: OAuth2.0 token
```

## Database and Migrations
- This service utilizes **Spring Hibernate** for database queries, ensuring efficient ORM-based interactions.
- **Flyway** manages database schema migrations, enabling version-controlled updates and rollback support.
- Database changes are handled through Flyway migration scripts stored in the `db/migration` folder, ensuring smooth and structured updates without data loss.
- Schema updates are automatically applied at application startup, maintaining consistency across environments (Just need to create database separately as mentioned in start of doc).

## Registering a New Client with OAuth2 Server

- A new client can be registered with the OAuth2 server by running the test `addRegisterSampleClient` available in the `ScalerCapstoneUserApplicationTests` class, located in `src/test/java/com/scaler/capstone/user/ScalerCapstoneUserApplicationTests.java` by providing `ClientId`, `ClientSecret`, `redirectUri`, `postLogoutRedirectUri`. Provide client secret by encrypting it using Bcrypt.

## Endpoints

### 1. User SignUp (Public)

**Endpoint:**

```
POST /users/signUp
```

**Description:** Creates a new user. **Request Body:**

```json
{
  "email": "shubham@scaler.com",
  "password": "Shubham@123",
  "name": "Shubham More",
  "street": "Old Mumbai Pune Road",
  "city": "Thane",
  "state": "Maharashtra",
  "zipcode": "400605",
  "country": "INDIA",
  "roles": ["USER"],
  "resetPasswordQuestion": "What is your pet's name?",
  "resetPasswordAnswer": "Chiku"
}
```

**Response:**

```json
{
  "id": 1,
  "email": "shubham@scaler.com",
  "name": "Shubham More",
  "roles": ["USER"]
}
```

**Response Code:** `201 Created`

---

### 2. Get All Users (Requires Authentication)

**Endpoint:**

```
GET /users/getAllUsers
```

**Description:** Fetches all users (Only accessible by `SUPER_ADMIN`). **Response:**

```json
[
  {
    "id": 1,
    "email": "shubham@scaler.com",
    "name": "Shubham More",
    "roles": ["USER"]
  }
]
```

**Response Code:** `200 OK`

---

### 3. Get User by Email (Requires Authentication)

**Endpoint:**

```
GET /users/getUser/{email}
```

**Description:** Fetches a user by their email (Only accessible to the user themselves). **Response:**

```json
{
  "id": 1,
  "email": "shubham@scaler.com",
  "name": "Shubham More",
  "roles": ["USER"]
}
```

**Response Code:** `200 OK`

---

### 4. Get Reset Password Question (Public)

**Endpoint:**

```
GET /users/getResetPasswordQuestion/{email}
```

**Description:** Returns the reset password security question for a user. **Response:**

```json
{
  "resetPasswordQuestion": "What is your pet's name?"
}
```

**Response Code:** `200 OK`

---

### 5. Reset Password (Public)

**Endpoint:**

```
POST /users/resetPassword
```

**Description:** Resets the user's password. **Request Body:**

```json
{
  "email": "shubham@scaler.com",
  "resetPasswordQuestion": "What is your pet's name?",
  "resetPasswordAnswer": "Chiku",
  "newPassword": "Password@123"
}
```

**Response:**

```json
{
  "id": 1,
  "email": "shubham@scaler.com",
  "name": "Shubham More",
  "roles": ["USER"]
}
```

**Response Code:** `200 OK`

---

### 6. Update User Details (Requires Authentication)

**Endpoint:**

```
PATCH /users/updateUser/{id}
```

**Description:** Updates the details of a user (Only accessible to the user themselves). **Request Body:**

```json
{
  "name": "Shubham More",
  "city": "Pune"
}
```

**Response:**

```json
{
  "id": 1,
  "email": "shubham@scaler.com",
  "name": "Shubham More",
  "city": "Pune"
}
```

**Response Code:** `200 OK`

---

### 7. Add Role to User (Requires Authentication)

**Endpoint:**

```
PATCH /users/addRole/{id}
```

**Description:** Adds a role to the user (Only accessible to the user themselves). **Query Parameter:**

```
roleName=ADMIN
```

**Response:**

```json
{
  "id": 1,
  "email": "shubham@scaler.com",
  "roles": ["USER", "ADMIN"]
}
```

**Response Code:** `200 OK`

---

### 8. Remove Role from User (Requires Authentication)

**Endpoint:**

```
PATCH /users/removeRole/{id}
```

**Description:** Removes a role from the user (Only accessible to the user themselves). **Query Parameter:**

```
roleName=ROLE_ADMIN
```

**Response:**

```json
{
  "id": 1,
  "email": "shubham@scaler.com",
  "roles": ["USER"]
}
```

**Response Code:** `200 OK`

---

### 9. Delete User (Requires Authentication)

**Endpoint:**

```
DELETE /users/deleteUser/{email}
```

**Description:** Deletes a user account (Only accessible to the user themselves). **Response Code:** `200 OK`

---

## Security & Authentication

- **OAuth 2.0 with JWT authentication required**
- **Public Endpoints:**
    - `/users/signUp`
    - `/users/resetPassword`
    - `/users/getResetPasswordQuestion/{email}`
- **Authentication Required:**
    - `/users/getUser/**`
    - `/users/updateUser/**`
    - `/users/addRole/**`
    - `/users/removeRole/**`
    - `/users/deleteUser/**`

## Error Responses

- **400 Bad Request:** Invalid request format.
- **401 Unauthorized:** Invalid or missing JWT token.
- **403 Forbidden:** User does not have permission.
- **404 Not Found:** User not found.
- **500 Internal Server Error:** Unexpected server error.

---

### Author

*API developed for user management with OAuth 2.0 authentication, role-based access control using JWT tokens, and database management using Spring Hibernate with Flyway migrations.*

