const User = require('../models/userModel');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');

// Helper function for standard responses
const sendResponse = (res, statusCode, success, message, data = null) => {
  return res.status(statusCode).json({
    success,
    message,
    data,
    timestamp: new Date().toISOString()
  });
};

/**
 * @desc    Register a new user
 * @route   POST /api/users/register
 * @access  Public
 */
exports.registerUser = async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    // Check if user already exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      return sendResponse(res, 400, false, 'User with this email already exists');
    }

    // Create new user
    const user = await User.create({
      firstName,
      lastName,
      email,
      password
    });

    // Generate token
    const token = await user.generateAuthToken();

    sendResponse(res, 201, true, 'User registered successfully', {
      user,
      token
    });
  } catch (error) {
    console.error('Register error:', error);
    
    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(err => err.message);
      return sendResponse(res, 400, false, messages.join(', '));
    }
    
    sendResponse(res, 500, false, 'Server error during registration');
  }
};

/**
 * @desc    Login user
 * @route   POST /api/users/login
 * @access  Public
 */
exports.loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if email and password are provided
    if (!email || !password) {
      return sendResponse(res, 400, false, 'Please provide email and password');
    }

    // Check if user exists
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return sendResponse(res, 401, false, 'Invalid credentials');
    }

    // Check if user is active
    if (!user.isActive) {
      return sendResponse(res, 401, false, 'Your account has been deactivated');
    }

    // Check if password is correct
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return sendResponse(res, 401, false, 'Invalid credentials');
    }

    // Update last login
    await user.updateLastLogin();

    // Generate token
    const token = await user.generateAuthToken();

    sendResponse(res, 200, true, 'Login successful', {
      user,
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    sendResponse(res, 500, false, 'Server error during login');
  }
};

/**
 * @desc    Logout user
 * @route   POST /api/users/logout
 * @access  Private
 */
exports.logoutUser = async (req, res) => {
  try {
    // Remove the token used for authentication
    await req.user.logout(req.token);
    
    sendResponse(res, 200, true, 'Logged out successfully');
  } catch (error) {
    console.error('Logout error:', error);
    sendResponse(res, 500, false, 'Server error during logout');
  }
};

/**
 * @desc    Logout from all devices
 * @route   POST /api/users/logoutAll
 * @access  Private
 */
exports.logoutAll = async (req, res) => {
  try {
    await req.user.logoutAll();
    
    sendResponse(res, 200, true, 'Logged out from all devices');
  } catch (error) {
    console.error('Logout all error:', error);
    sendResponse(res, 500, false, 'Server error during logout from all devices');
  }
};

/**
 * @desc    Get current user profile
 * @route   GET /api/users/profile
 * @access  Private
 */
exports.getUserProfile = async (req, res) => {
  try {
    sendResponse(res, 200, true, 'User profile retrieved', req.user);
  } catch (error) {
    console.error('Get profile error:', error);
    sendResponse(res, 500, false, 'Server error retrieving user profile');
  }
};

/**
 * @desc    Update user profile
 * @route   PUT /api/users/profile
 * @access  Private
 */
exports.updateUserProfile = async (req, res) => {
  try {
    const updates = Object.keys(req.body);
    const allowedUpdates = ['firstName', 'lastName', 'email'];
    const isValidOperation = updates.every(update => allowedUpdates.includes(update));

    if (!isValidOperation) {
      return sendResponse(res, 400, false, 'Invalid updates');
    }

    updates.forEach(update => req.user[update] = req.body[update]);
    await req.user.save();

    sendResponse(res, 200, true, 'Profile updated successfully', req.user);
  } catch (error) {
    console.error('Update profile error:', error);
    
    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(err => err.message);
      return sendResponse(res, 400, false, messages.join(', '));
    }
    
    if (error.code === 11000) {
      return sendResponse(res, 400, false, 'Email already in use');
    }
    
    sendResponse(res, 500, false, 'Server error updating profile');
  }
};

/**
 * @desc    Change user password
 * @route   PUT /api/users/password
 * @access  Private
 */
exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return sendResponse(res, 400, false, 'Please provide current and new password');
    }

    // Get user with password
    const user = await User.findById(req.user._id).select('+password');

    // Check current password
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
      return sendResponse(res, 401, false, 'Current password is incorrect');
    }

    // Set new password and change date
    user.password = newPassword;
    user.passwordChangedAt = Date.now();
    await user.save();

    sendResponse(res, 200, true, 'Password changed successfully');
  } catch (error) {
    console.error('Change password error:', error);
    sendResponse(res, 500, false, 'Server error changing password');
  }
};

/**
 * @desc    Request password reset
 * @route   POST /api/users/forgotPassword
 * @access  Public
 */
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return sendResponse(res, 400, false, 'Please provide an email address');
    }

    const user = await User.findOne({ email });
    if (!user) {
      // For security, don't reveal that email doesn't exist
      return sendResponse(res, 200, true, 'If your email is registered, you will receive a password reset link');
    }

    // Generate reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    // In a real app, send email with token
    // For now, just return the token for testing purposes
    const resetUrl = `${req.protocol}://${req.get('host')}/api/users/resetPassword/${resetToken}`;

    sendResponse(res, 200, true, 'Password reset email sent', 
      process.env.NODE_ENV === 'development' ? { resetUrl, resetToken } : null);
  } catch (error) {
    console.error('Forgot password error:', error);
    sendResponse(res, 500, false, 'Server error processing password reset');
  }
};

/**
 * @desc    Reset password
 * @route   POST /api/users/resetPassword/:token
 * @access  Public
 */
exports.resetPassword = async (req, res) => {
  try {
    const { password } = req.body;
    const { token } = req.params;

    if (!password) {
      return sendResponse(res, 400, false, 'Please provide a new password');
    }

    // Create hash of the token received
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    // Find user by the hashed token and check if token has expired
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return sendResponse(res, 400, false, 'Token is invalid or has expired');
    }

    // Update password and clear reset fields
    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.passwordChangedAt = Date.now();
    await user.save();

    // Log the user in, send JWT
    const authToken = await user.generateAuthToken();

    sendResponse(res, 200, true, 'Password has been reset', {
      user,
      token: authToken
    });
  } catch (error) {
    console.error('Reset password error:', error);
    sendResponse(res, 500, false, 'Server error resetting password');
  }
};

/**
 * @desc    Get all users (admin only)
 * @route   GET /api/users
 * @access  Private/Admin
 */
exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find({});
    
    sendResponse(res, 200, true, 'Users retrieved successfully', { users, count: users.length });
  } catch (error) {
    console.error('Get all users error:', error);
    sendResponse(res, 500, false, 'Server error retrieving users');
  }
};

/**
 * @desc    Get user by ID (admin only)
 * @route   GET /api/users/:id
 * @access  Private/Admin
 */
exports.getUserById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return sendResponse(res, 404, false, 'User not found');
    }
    
    sendResponse(res, 200, true, 'User retrieved successfully', user);
  } catch (error) {
    console.error('Get user by ID error:', error);
    
    if (error.kind === 'ObjectId') {
      return sendResponse(res, 404, false, 'User not found - Invalid ID');
    }
    
    sendResponse(res, 500, false, 'Server error retrieving user');
  }
};

/**
 * @desc    Update user by ID (admin only)
 * @route   PUT /api/users/:id
 * @access  Private/Admin
 */
exports.updateUser = async (req, res) => {
  try {
    const updates = Object.keys(req.body);
    const allowedUpdates = ['firstName', 'lastName', 'email', 'isActive', 'role'];
    const isValidOperation = updates.every(update => allowedUpdates.includes(update));

    if (!isValidOperation) {
      return sendResponse(res, 400, false, 'Invalid updates');
    }

    const user = await User.findById(req.params.id);
    
    if (!user) {
      return sendResponse(res, 404, false, 'User not found');
    }
    
    updates.forEach(update => user[update] = req.body[update]);
    await user.save();
    
    sendResponse(res, 200, true, 'User updated successfully', user);
  } catch (error) {
    console.error('Update user error:', error);
    
    if (error.kind === 'ObjectId') {
      return sendResponse(res, 404, false, 'User not found - Invalid ID');
    }
    
    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(err => err.message);
      return sendResponse(res, 400, false, messages.join(', '));
    }
    
    sendResponse(res, 500, false, 'Server error updating user');
  }
};

/**
 * @desc    Delete user by ID (admin only)
 * @route   DELETE /api/users/:id
 * @access  Private/Admin
 */
exports.deleteUser = async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    
    if (!user) {
      return sendResponse(res, 404, false, 'User not found');
    }
    
    sendResponse(res, 200, true, 'User deleted successfully');
  } catch (error) {
    console.error('Delete user error:', error);
    
    if (error.kind === 'ObjectId') {
      return sendResponse(res, 404, false, 'User not found - Invalid ID');
    }
    
    sendResponse(res, 500, false, 'Server error deleting user');
  }
};
