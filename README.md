# KeeperApp API

A simple Node.js + Express REST API for a personal notes application (KeeperApp). It includes local username/password registration and login, Google OAuth sign-in, JWT-based authentication, and note management persisted in MongoDB.

## Features

- User registration and login (bcrypt-hashed passwords)
- Google OAuth 2.0 sign-in integration (Passport.js)
- JWT tokens for authenticating API requests
- Create, list (protected), and delete notes per user
- MongoDB (Mongoose) data models

## Technology stack

- Node.js
- Express
- MongoDB with Mongoose
- Passport.js (Google OAuth)
- JSON Web Tokens (jsonwebtoken)
- bcrypt for password hashing

## Quick start

Prerequisites:

- Node.js 18+ and npm
- A MongoDB Atlas cluster or MongoDB connection URI
- Google OAuth client credentials (if using Google sign-in)

1. Clone the repository and install dependencies:

```
git clone <REPO_URL>
cd KeeperAppAPI
npm install
```

2. Create a `.env` file at the project root with the following variables:

```
USER_NAME=<mongodb-username>
PASSWORD=<mongodb-password>
secret=<jwt-secret>
GOOGLE_CLIENT_ID=<google-client-id>
GOOGLE_CLIENT_SECRET=<google-client-secret>
```

Notes:
- `USER_NAME` and `PASSWORD` are used to build the MongoDB connection string in the form of a MongoDB Atlas connection.
- `secret` is used to sign JWT tokens. Use a long, random string in production.

3. Start the server:

```
node app.js
```

By default the server listens on port 3001.

## API Reference

All JSON requests and responses use UTF-8 and application/json where appropriate.

Base URL: http://localhost:3001

Endpoints:

- POST /register
  - Registers a new user.
  - Request body: { "username": "...", "password": "...", "email": "..." }
  - Response: 201 Created on success with JSON containing a JWT token.

- POST /login
  - Logs a user in with username/password.
  - Request body: { "username": "...", "password": "..." }
  - Response: 200 OK on success with JSON containing a JWT token.

- GET /auth/google
  - Starts Google OAuth flow (redirects to Google).

- GET /auth/google/callback
  - OAuth callback endpoint. On success the server issues a JWT and redirects to the configured front-end URL.

- GET /protected
  - Protected endpoint that returns the authenticated user's notes.
  - Requires Authorization header: `Bearer <token>`

- POST /addNote
  - Adds a note to the authenticated user's notes array.
  - Request body: { "title": "...", "content": "..." }
  - Requires Authorization header: `Bearer <token>`

- POST /deleteNote
  - Deletes a note by id from the authenticated user's notes array.
  - Request body: { "noteId": "<note-id>" }
  - Requires Authorization header: `Bearer <token>`

## Data models (Mongoose)

- User
  - username: String
  - password: String (hashed)
  - email: String
  - googleId: String
  - notes: [ { title: String, content: String } ]

- Note
  - title: String
  - content: String

## Authentication

- Local users: passwords are hashed with bcrypt before storage. After login or registration the server returns a JWT signed with the `secret` environment variable. Use `Authorization: Bearer <token>` when calling protected endpoints.
- Google OAuth: uses Passport.js to authenticate users via Google. After successful OAuth the server signs and sets a JWT cookie and redirects to the front-end.

## Security considerations

- Do not commit the `.env` file to source control. Ensure environment variables like database credentials and JWT secrets remain private.
- In production, set secure cookie flags (httpOnly and secure) appropriately and enable HTTPS.
- Use short-lived JWTs or implement token revocation for stronger account security.

## Environment & Deployment

- This application is suitable for deployment to services like Render, Heroku, or any VPS. Ensure environment variables are configured in the hosting environment.
- For production, provide a proper MongoDB connection URI (or use `USER_NAME` and `PASSWORD` as shown) and configure the Google OAuth callback URL to match the hosted domain.

## Known limitations & notes

- The JWT expiration in the current code is set to a long duration (`10y`). Review and change to a shorter duration for production.
- Some dependencies (for example `fs`, `https`, and `crypto`) are included in `package.json` but are core Node modules and don't need to be installed as npm packages.

## Contributing

Contributions are welcome. Please open an issue or pull request with a clear description of changes.

## License

This project is provided under the ISC license (see `package.json`).
