const mongoose = require('mongoose');
require('dotenv').config();

// Track connection status (helpful in serverless)
let isConnected = false;

const connectDB = async () => {
  try {
    // If already connected, reuse connection (important for serverless)
    if (isConnected) {
      console.log('Using existing MongoDB connection');
      return;
    }

    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });

    isConnected = true;
    console.log(`MongoDB Connected: ${conn.connection.host}`);
    
    // Set up event listeners for the connection
    mongoose.connection.on('error', (err) => {
      console.error(`MongoDB connection error: ${err}`);
    });
    
    mongoose.connection.on('disconnected', () => {
      isConnected = false;
      console.log('MongoDB disconnected, attempting to reconnect...');
    });
    
    mongoose.connection.on('reconnected', () => {
      isConnected = true;
      console.log('MongoDB reconnected successfully');
    });

    // Only attach SIGINT handler in non-serverless environment
    if (!process.env.VERCEL) {
      process.on('SIGINT', async () => {
        await mongoose.connection.close();
        console.log('MongoDB connection closed due to app termination');
        process.exit(0);
      });
    }

    return conn;
  } catch (error) {
    console.error(`Error connecting to MongoDB: ${error.message}`);
    
    // Don't exit process in serverless environment
    if (!process.env.VERCEL) {
      process.exit(1);
    }
    
    return null;
  }
};

module.exports = connectDB;
