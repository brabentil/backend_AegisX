const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const User = require('../models/userModel');

/**
 * Authentication middleware
 * Protects routes from unauthorized access
 */
exports.protect = async (req, res, next) => {
  try {
    let token;
    
    // Get token from header
    if (
      req.headers.authorization && 
      req.headers.authorization.startsWith('Bearer')
    ) {
      token = req.headers.authorization.split(' ')[1];
    } 
    // Or from cookies if you're using them
    else if (req.cookies?.jwt) {
      token = req.cookies.jwt;
    }
    
    // Check if token exists
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'You are not logged in. Please log in to access this resource.'
      });
    }
    
    // Verify token
    const decoded = await promisify(jwt.verify)(
      token, 
      process.env.JWT_SECRET || 'fallback_secret_should_be_set_in_env'
    );
    
    // Check if user still exists
    const currentUser = await User.findById(decoded._id);
    if (!currentUser) {
      return res.status(401).json({
        success: false,
        message: 'The user belonging to this token no longer exists.'
      });
    }
    
    // Check if user changed password after the token was issued
    if (currentUser.passwordChangedAt) {
      const changedTimestamp = parseInt(
        currentUser.passwordChangedAt.getTime() / 1000, 
        10
      );
      
      if (decoded.iat < changedTimestamp) {
        return res.status(401).json({
          success: false,
          message: 'User recently changed password. Please log in again.'
        });
      }
    }
    
    // Check if token exists in user's token array
    const tokenExists = currentUser.tokens.some(t => t.token === token);
    if (!tokenExists) {
      return res.status(401).json({
        success: false,
        message: 'Invalid token. Please log in again.'
      });
    }
    
    // Grant access to protected route
    req.user = currentUser;
    req.token = token;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token. Please log in again.'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Your token has expired. Please log in again.'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Authentication error.'
    });
  }
};

/**
 * Authorization middleware
 * Restricts routes to specific user roles
 */
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    // Check if user role is allowed
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to perform this action'
      });
    }
    
    next();
  };
};
