from .user_model import User
from .userDetails_model import UserDetails
from sqlalchemy.orm import relationship

# 👇 NOW safely define
user_details = relationship("UserDetails", back_populates="user", uselist=False)
