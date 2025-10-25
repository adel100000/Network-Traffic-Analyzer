from sqlalchemy import create_engine
from app.models import Base
from app.database import DATABASE_URL  # make sure this points to your SQLite file

engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)  # creates tables if they don’t exist
print("Database tables created!")
