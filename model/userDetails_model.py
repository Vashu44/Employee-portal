from sqlalchemy import Column, Integer, String, DateTime,Date, func, ForeignKey
from db.database import Base
from sqlalchemy.orm import relationship

# UserDetails Model
class UserDetails(Base):
    __tablename__ = "user_details"

    user_id = Column(Integer, ForeignKey('users.id'), primary_key=True, index=True)
    full_name = Column(String(255), nullable=True)
    aadhar_card_no = Column(String(12), nullable=True)
    pan_card_no = Column(String(10), nullable=True)
    address = Column(String(500), nullable=True)
    phone_number = Column(String(15), nullable=True)
    nationality =  Column(String(30),nullable = True)
    emergency_contact = Column(String(15), nullable=True)
    date_of_birth = Column(Date, nullable=True)  # YYYY-MM-DD format

    created_at = Column(DateTime, default=func.now(), server_default=func.now())
    date_of_joining = Column(DateTime, default=func.now(), server_default=func.now())

    working_region_id =  Column(Integer,  ForeignKey("regions.id"), nullable = True)
    home_region_id = Column(Integer, ForeignKey("regions.id"), nullable = True)

    manager_name = Column(String(30), nullable = True)
    current_Department = Column(String(30), nullable=True) 
    current_role = Column(String(30), nullable = True)


    user = relationship("User", back_populates="user_details")