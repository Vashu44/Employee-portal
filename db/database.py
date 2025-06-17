from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get database URL from environment variable
MYSQL_URL_DATABASE = os.getenv("MYSQL_URL", "mysql+pymysql://root:Vashu1234%40@localhost:3306/datauser")

# Create the database/SQLAlchemy engine
engine = create_engine(MYSQL_URL_DATABASE)

# Create a configured "Session" class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

#base class for declarative models
Base = declarative_base()