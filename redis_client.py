import redis
import logging
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

class RedisClient:
    def __init__(self):
        try:
            self.client = redis.Redis(
                host=os.getenv("REDIS_HOST", "localhost"), 
                port=int(os.getenv("REDIS_PORT", 6379)), 
                db=int(os.getenv("REDIS_DB", 0)), 
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
            # Test the connection
            self.client.ping()
            logger.info("Redis connection established successfully")
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {str(e)}")
            raise Exception("Redis connection failed. Make sure Redis server is running.")
        except Exception as e:
            logger.error(f"Unexpected error connecting to Redis: {str(e)}")
            raise

    def setex(self, key, expiry_seconds, value):
        """Set the value of the key in Redis with an expiry time"""
        try:
            self.client.setex(key, expiry_seconds, value)
            logger.info(f"Successfully set key: {key}")
        except redis.RedisError as e:
            logger.error(f"Redis error setting key {key}: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error setting key {key}: {str(e)}")
            raise

    def get(self, key):
        """Get the value of the key from Redis"""
        try:
            value = self.client.get(key)
            logger.info(f"Retrieved key: {key}, found: {value is not None}")
            return value
        except redis.RedisError as e:
            logger.error(f"Redis error getting key {key}: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error getting key {key}: {str(e)}")
            raise

    def delete(self, key):
        """Delete the key from Redis"""
        try:
            result = self.client.delete(key)
            logger.info(f"Deleted key: {key}, success: {result > 0}")
            return result
        except redis.RedisError as e:
            logger.error(f"Redis error deleting key {key}: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error deleting key {key}: {str(e)}")
            raise

    def exists(self, key):
        """Check if key exists in Redis"""
        try:
            return self.client.exists(key) > 0
        except redis.RedisError as e:
            logger.error(f"Redis error checking key {key}: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error checking key {key}: {str(e)}")
            raise