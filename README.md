# Aegis API Backend

A robust, secure Node.js backend API built with Express.js and MongoDB, designed with security and scalability in mind.

## 📋 Overview

This backend provides a complete authentication and user management system with features like:

- JWT-based authentication
- Role-based access control
- Password reset functionality
- Multi-device session management
- API rate limiting and security features

The API is designed to be deployed on Vercel's serverless infrastructure but can also run as a traditional Node.js server.

## 🛠️ Technology Stack

- **Runtime**: Node.js (v14+)
- **Framework**: Express.js
- **Database**: MongoDB with Mongoose ODM
- **Authentication**: JWT (JSON Web Tokens)
- **Security Packages**:
  - helmet (HTTP headers security)
  - express-rate-limit (rate limiting)
  - express-mongo-sanitize (NoSQL injection prevention)
  - xss-clean (XSS prevention)
  - hpp (HTTP parameter pollution protection)

## 🏗️ Project Structure

```
backend/
├── config/           # Configuration files
│   └── dbConnection.js  # MongoDB connection logic
├── controllers/      # Request handlers
│   └── userController.js  # User-related operations
├── middleware/       # Custom middleware
│   └── authMiddleware.js  # Authentication & authorization middleware
├── models/           # Database models
│   └── userModel.js  # User schema definition
├── routes/           # API routes
│   └── userRoutes.js  # User-related routes
├── .env              # Environment variables (not in git)
├── .gitignore        # Git ignore configuration
├── package.json      # Project dependencies
├── server.js         # Main application entry point
└── vercel.json       # Vercel deployment configuration
```

## 🚀 Getting Started

### Prerequisites

- Node.js (v14 or higher)
- MongoDB database (local or Atlas)

### Environment Variables

Create a `.env` file in the root directory with the following variables:

```
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_secret_key_for_jwt
NODE_ENV=development
```

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the server:
   ```bash
   # Development mode
   npm run dev
   
   # Production mode
   npm start
   ```

## 🔑 API Endpoints

### Public Routes (No Authentication Required)

- **POST /api/users/register** - Register a new user
- **POST /api/users/login** - Authenticate a user
- **POST /api/users/forgotPassword** - Request password reset
- **POST /api/users/resetPassword/:token** - Reset password with token
- **GET /api/health** - API health check
- **GET /** - API information

### Protected Routes (Authentication Required)

- **GET /api/users/profile** - Get current user profile
- **PUT /api/users/profile** - Update user profile
- **PUT /api/users/password** - Change password
- **POST /api/users/logout** - Logout current session
- **POST /api/users/logoutAll** - Logout from all devices

### Admin Routes (Admin Role Required)

- **GET /api/users** - Get all users
- **GET /api/users/:id** - Get user by ID
- **PUT /api/users/:id** - Update user
- **DELETE /api/users/:id** - Delete user

## 🔐 Authentication

The API uses JWT (JSON Web Tokens) for authentication:

1. Upon successful login or registration, a JWT is generated and returned
2. This token must be included in the Authorization header for protected routes:
   ```
   Authorization: Bearer <your_jwt_token>
   ```
3. Tokens are stored in the user document in MongoDB
4. Users can have multiple active tokens (for multiple devices)
5. Tokens expire after 24 hours

## 👥 User Roles

- **user**: Regular user with access to their own data
- **admin**: Can manage all users
- **superadmin**: Full system access

## 🚢 Deployment

The project is configured for deployment on Vercel with the provided `vercel.json` configuration. It automatically detects whether it's running in a serverless environment.

To deploy:

1. Install Vercel CLI: `npm i -g vercel`
2. Run: `vercel`

## 🚨 Error Handling

The API implements comprehensive error handling:

- Validation errors are returned with appropriate messages
- JWT errors (expired, invalid) are handled gracefully
- Mongoose errors are properly formatted
- 404 handling for undefined routes
- Global error handler for unexpected exceptions

## 🔒 Security Features

- Password hashing with bcrypt
- JWT-based authentication
- HTTP headers security with Helmet
- Rate limiting to prevent brute force attacks
- Data sanitization against NoSQL injection
- XSS protection
- Parameter pollution protection
- CORS configuration

## 📝 License

This project is licensed under the MIT License.
