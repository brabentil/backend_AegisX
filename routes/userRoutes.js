const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');

// Middleware imports (to be implemented)
const { protect, restrictTo } = require('../middleware/authMiddleware');

/**
 * Public Routes - No Authentication Required
 */

// Authentication routes
router.post('/register', userController.registerUser);
router.post('/login', userController.loginUser);
router.post('/forgotPassword', userController.forgotPassword);
router.post('/resetPassword/:token', userController.resetPassword);

/**
 * Protected Routes - Authentication Required
 */

// User profile management
router.use(protect); // All routes after this middleware require authentication

router.get('/profile', userController.getUserProfile);
router.put('/profile', userController.updateUserProfile);
router.put('/password', userController.changePassword);
router.post('/logout', userController.logoutUser);
router.post('/logoutAll', userController.logoutAll);

/**
 * Admin Routes - Authentication + Admin Role Required
 */

// Admin user management
router.use(restrictTo('admin', 'superadmin')); 

router.route('/')
  .get(userController.getAllUsers);

router.route('/:id')
  .get(userController.getUserById)
  .put(userController.updateUser)
  .delete(userController.deleteUser);

module.exports = router;
