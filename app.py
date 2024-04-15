import re

from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from typing import Annotated, Optional, List
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "disabled": False,
        "roles": ["Read"]
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
        "roles": ["Read", "Write"]
    },
    "bob": {
        "username": "bob",
        "full_name": "Bob Smith",
        "email": "bob@example.com",
        "hashed_password": "fakehashedsecret3",
        "disabled": False,
        "roles": ["Read", "Write"]
    }
}

# Create the FastAPI app
app = FastAPI()

# Define the SQLite database engine
SQLALCHEMY_DATABASE_URL = "sqlite:///./phonebook.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Create a database session class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for the database models
Base = declarative_base()


# Create the PhoneBook model class
class PhoneBook(Base):
    __tablename__ = "phonebook"

    id = Column(Integer, primary_key=True)
    full_name = Column(String)
    phone_number = Column(String)


# Define the AuditLog model
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)
    action = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)


# Function to log an action
def log_action(db: Session, user_id: str, action: str):
    # Create a new audit log entry
    log_entry = AuditLog(user_id=user_id, action=action)
    db.add(log_entry)
    db.commit()


def fake_hash_password(password: str):
    return "fakehashed" + password


# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Import models and functions from the previous code snippet
class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    roles: Optional[list] = None


# Define a Pydantic model for AuditLog
class AuditLogResponse(BaseModel):
    id: int
    user_id: str
    action: str
    timestamp: datetime


class UserInDB(User):
    hashed_password: str
    # password: Optional[str] = None


# Create the database schema
Base.metadata.create_all(engine)

# Create the session class for database operations
Session = sessionmaker(bind=engine)


# Create the Pydantic model class for request and response data
class Person(BaseModel):
    name: str
    phoneNumber: str


# Name Validator
def validate_name(full_name):
    full_name_pattern = r"^(?:[A-Za-z'-]+\s){1,2}[A-Za-z'-]+(?:,\s[A-Za-z'-]+(?:\s[A-Za-z'-]+)?)?$"

    # Validate full_name
    if not re.match(full_name_pattern, full_name):
        raise ValueError("Invalid name format. Name must be in one of the following formats: <first middle last>, "
                         "<first last>, or <last, first MI>.")


# Name Validator
def validate_number(phone_number):
    phone_number_pattern = r"^(?:\+\d{1,2}\s*)?(?:\(?\d{3}\)?[-.\s]*)?\d{3}[-.\s]*\d{4}$"

    # Validate phone_number
    if not re.match(phone_number_pattern, phone_number):
        raise ValueError("Invalid phone number format")


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def fake_decode_token(token):
    # This doesn't provide any security at all
    # Check the next version
    user = get_user(fake_users_db, token)
    return user


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_active_user(
        current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# Define the API endpoints
def convert_audit_log_to_dict(log: AuditLog) -> dict:
    log_dict = log.__dict__.copy()
    # Ensure user_id is a string
    log_dict["user_id"] = str(log_dict["user_id"])
    return log_dict


@app.get("/audit/logs", response_model=List[AuditLogResponse])
def get_audit_logs(
        current_user: Annotated[User, Depends(get_current_active_user)],
        db: Session = Depends(get_db),
        user_id: Optional[str] = None,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
        last_n: Optional[int] = None,
) -> List[AuditLogResponse]:
    session = Session()
    query = session.query(AuditLog)

    # Check if the user has the required role
    if "Read" not in current_user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    # Log the action
    log_action(db=db, user_id=current_user.username, action=f"Read Audit Log")

    # Filter by user ID if provided
    if user_id is not None:
        query = query.filter(AuditLog.user_id == user_id)

    # Filter by date range if from_date and to_date are provided
    if from_date is not None:
        query = query.filter(AuditLog.timestamp >= from_date)
    if to_date is not None:
        query = query.filter(AuditLog.timestamp <= to_date)

    # Order by timestamp in descending order to get the latest logs first
    query = query.order_by(AuditLog.timestamp.desc())

    # Limit the number of logs returned if last_n is provided
    if last_n is not None:
        query = query.limit(last_n)

    # Execute the query and fetch the logs
    logs = query.all()
    session.close()

    # Convert AuditLog objects to dictionaries
    logs_dict = [convert_audit_log_to_dict(log) for log in logs]

    return logs_dict


# Add auditing to the login endpoint
@app.post("/token")
async def login(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
        db: Session = Depends(get_db)
):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    # Log the action
    log_action(db=db, user_id=user.username, action="Login")

    return {"access_token": user.username, "token_type": "bearer"}


@app.get("/users/me")
async def read_users_me(
        current_user: Annotated[User, Depends(get_current_active_user)],
        db: Session = Depends(get_db)
):
    # Log the action
    log_action(db=db, user_id=current_user.username, action="Read user details")

    return current_user


@app.get("/PhoneBook/list")
def list_phonebook(
        current_user: Annotated[User, Depends(get_current_active_user)],
        db: Session = Depends(get_db)
):
    # Check if the user has the required role
    if "Read" not in current_user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    # Log the action
    log_action(db=db, user_id=current_user.username, action="List phonebook entries")

    # Get a new session
    session = Session()
    # Query all the records in the phonebook table
    phonebook = session.query(PhoneBook).all()
    # Close the session
    session.close()
    # Return the list of records as JSON objects
    return phonebook


# Add auditing to the add_person endpoint
@app.post("/PhoneBook/add")
def add_person(
        # name: str,
        # phoneNumber: str,
        person: Person,
        current_user: Annotated[User, Depends(get_current_active_user)],
        db: Session = Depends(get_db)
):
    # Check if the user has the required role
    if "Write" not in current_user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )

    try:
        validate_name(person.name)
        validate_number(person.phoneNumber)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.args[0]))

    # Get a new session
    session = Session()
    # Check if the person already exists in the database by phone number
    existing_person = session.query(PhoneBook).filter_by(phone_number=person.phoneNumber).first()
    # If the person exists, raise an exception
    if existing_person:
        session.close()
        raise HTTPException(status_code=400, detail="Person already exists in the database")
    # Otherwise, create a new PhoneBook record and add it to the database
    new_person = PhoneBook(full_name=person.name, phone_number=person.phoneNumber)
    session.add(new_person)
    session.commit()
    # Close the session
    session.close()

    # Log the action
    log_action(db=db, user_id=current_user.username, action=f"Add phonebook entry: {person.name}")

    # Return a success message
    return {"message": "Person added successfully"}


# Add auditing to the delete_by_name endpoint
@app.put("/PhoneBook/deleteByName")
def delete_by_name(
        name: str,
        current_user: Annotated[User, Depends(get_current_active_user)],
        db: Session = Depends(get_db)
):
    # Check if the user has the required role
    if "Write" not in current_user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )

    try:
        validate_name(name)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.args[0]))

    # Get a new session
    session = Session()
    # Query the person by name in the database
    person = session.query(PhoneBook).filter_by(full_name=name).first()
    # If the person does not exist, raise an exception
    if not person:
        session.close()
        raise HTTPException(status_code=404, detail="Person not found in the database")
    # Otherwise, delete the person from the database
    session.delete(person)
    session.commit()
    # Close the session
    session.close()

    # Log the action
    log_action(db=db, user_id=current_user.username, action=f"Delete phonebook entry by name: {name}")

    # Return a success message
    return {"message": "Person deleted successfully"}


# Add auditing to the delete_by_number endpoint
@app.put("/PhoneBook/deleteByNumber")
def delete_by_number(
        number: str,
        current_user: Annotated[User, Depends(get_current_active_user)],
        db: Session = Depends(get_db)
):
    # Check if the user has the required role
    if "Write" not in current_user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )

    try:
        validate_number(number)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e.args[0]))

    # Get a new session
    session = Session()
    # Query the person by phone number in the database
    person = session.query(PhoneBook).filter_by(phone_number=number).first()
    # If the person does not exist, raise an exception
    if not person:
        session.close()
        raise HTTPException(status_code=404, detail="Person not found in the database")
    # Otherwise, delete the person from the database
    session.delete(person)
    session.commit()
    # Close the session
    session.close()

    # Log the action
    log_action(db=db, user_id=current_user.username, action=f"Delete phonebook entry by number: {number}")

    # Return a success message
    return {"message": "Person deleted successfully"}
