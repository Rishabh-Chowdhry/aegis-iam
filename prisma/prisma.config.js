const path = require("path");
require("dotenv").config({ path: path.join(process.cwd(), ".env") });

/**
 * Prisma Configuration for MongoDB
 *
 * This configuration is designed for Prisma 7+ with MongoDB support.
 * The DATABASE_URL environment variable must be set in your .env file.
 *
 * Example MongoDB connection string:
 * mongodb://username:password@host:port/database?authSource=admin
 *
 * For MongoDB Atlas (cloud):
 * mongodb+srv://username:password@cluster.mongodb.net/database?retryWrites=true&w=majority
 */
module.exports = {
  // Enable early access for MongoDB support
  earlyAccess: true,

  // Path to the Prisma schema file
  schema: path.join(__dirname, "schema.prisma"),

  // Database connection configuration (Prisma 7+ style)
  migrate: {
    adapter: {
      url: process.env.DATABASE_URL,
    },
  },

  // Generator configuration
  generator: {
    // Output directory for generated client
    output: path.join(process.cwd(), "node_modules", ".prisma", "client"),
  },
};
