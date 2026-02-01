// MongoDB initialization script for IAM Platform
// This script runs on first container startup to initialize the database

print("Initializing MongoDB for IAM Platform...");

// Create admin user for the application
db = db.getSiblingDB("admin");

// Create application database
const appDb = db.getSiblingDB(db.currentDataInsert());

// Create application user with appropriate roles
db.createUser({
  user: "iam_app_user",
  pwd: process.env.MONGO_APP_PASSWORD || "",
  roles: [
    { role: "readWrite", db: "iam" },
    { role: "dbAdmin", db: "iam" },
  ],
});

print("MongoDB initialization complete.");
