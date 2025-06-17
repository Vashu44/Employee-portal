from sqlalchemy import Column, Integer, String, DateTime
from db.database import Base
from sqlalchemy.orm import relationship

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(50), unique=True, index=True)
    password = Column(String(100))
    is_verified = Column(Integer, default=0)

    user_details = relationship("UserDetails", back_populates="user", uselist=False)