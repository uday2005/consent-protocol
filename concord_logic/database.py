# concord_logic/database.py

import os
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import scoped_session, sessionmaker, relationship, declarative_base
import datetime

# This finds the root directory of your project and creates a database file there.

# This makes it easy for anyone on your team to run.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_PATH = os.path.join(BASE_DIR, 'concord.db')

engine = create_engine(f'sqlite:///{DATABASE_PATH}')
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

Base = declarative_base()
Base.query = db_session.query_property()

# --- Our Application's Database Tables ---

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    google_id = Column(String(120), unique=True, nullable=False)
    display_name = Column(String(120), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    avatar_url = Column(String(255))
    
    credentials = relationship('Credential', back_populates='user', cascade="all, delete-orphan")
    audit_logs = relationship('AuditLog', back_populates='user', cascade="all, delete-orphan")

class Credential(Base):
    __tablename__ = 'credentials'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    service_name = Column(String(50), nullable=False) # e.g., 'google_calendar', 'slack'
    encrypted_token = Column(String, nullable=False)
    
    user = relationship('User', back_populates='credentials')

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    event = Column(String, nullable=False)
    details = Column(String, nullable=False)
    status = Column(String, nullable=False)

    user = relationship('User', back_populates='audit_logs')

def init_db():
    """ This function will create the database file and tables. """
    print("Initializing the database...")
    Base.metadata.create_all(bind=engine)
    print("Database initialized.")