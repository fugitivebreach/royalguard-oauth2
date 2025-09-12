#!/usr/bin/env python3
"""
Database initialization script for OAuth verification system.
Creates necessary indexes and ensures proper database setup.
"""

import pymongo
from pymongo import MongoClient, IndexModel
from decouple import config
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_database():
    """Initialize the database with proper indexes and collections."""
    try:
        # Load configuration
        MONGO_URI = config('MONGO_URI', default='mongodb://localhost:27017/royalguard')
        
        # Connect to MongoDB
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        
        # Test connection
        client.admin.command('ping')
        logger.info("Successfully connected to MongoDB")
        
        # Get database and collection
        db = client['royalguard']
        collection = db['verifiedusers']
        
        # Create indexes for better performance
        indexes = [
            IndexModel([("_id", 1)], unique=True),  # Discord ID (primary key)
            IndexModel([("roblox", 1)], unique=False),  # ROBLOX ID (can have duplicates for re-verification)
            IndexModel([("discord_username", 1)], unique=False),
            IndexModel([("roblox_username", 1)], unique=False),
            IndexModel([("verified_at", -1)], unique=False),  # Most recent first
            IndexModel([("banned", 1)], unique=False),
            IndexModel([("suspended", 1)], unique=False)
        ]
        
        # Create indexes
        collection.create_indexes(indexes)
        logger.info("Database indexes created successfully")
        
        # Get collection stats
        try:
            stats = db.command('collStats', 'verifiedusers')
            logger.info(f"Collection stats: {stats.get('count', 0)} documents, {stats.get('size', 0)} bytes")
        except Exception as e:
            logger.info("Collection doesn't exist yet, will be created on first insert")
        
        client.close()
        logger.info("Database initialization completed successfully")
        return True
        
    except pymongo.errors.ServerSelectionTimeoutError:
        logger.error("Could not connect to MongoDB server. Please check if MongoDB is running.")
        return False
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        return False

if __name__ == '__main__':
    success = init_database()
    if success:
        print("✅ Database initialized successfully")
    else:
        print("❌ Database initialization failed")
        exit(1)
