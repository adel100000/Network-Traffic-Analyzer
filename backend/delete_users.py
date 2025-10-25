from sqlalchemy import create_engine
from app.models import User
from app.database import Base

# Make sure path is correct
engine = create_engine("sqlite:///cyber.db")
Base.metadata.bind = engine
from sqlalchemy.orm import sessionmaker
Session = sessionmaker(bind=engine)
session = Session()

# Delete all users
session.query(User).delete()
session.commit()
print("All users deleted!")


