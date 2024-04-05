'''References
1) https://fastapi.tiangolo.com/
2) https://github.com/sumanentc/python-sample-FastAPI-application
3) https://dassum.medium.com/building-rest-apis-using-fastapi-sqlalchemy-uvicorn-8a163ccf3aa1
'''
# Import the required modules
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from typing import Annotated, Optional
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

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
        "roles": ["Read", "ReadWrite"]
    },
}

# Define roles and permissions
ROLES_PERMISSIONS = {
    "Read": ["list"],
    "ReadWrite": ["list", "add", "remove"]
}

# Create the FastAPI app
app = FastAPI()

# Create the SQLite database engine
engine = create_engine("sqlite:///phonebook.db", echo=True)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Create the base class for the database models
Base = declarative_base()


# Create the PhoneBook model class
class PhoneBook(Base):
    __tablename__ = "phonebook"

    id = Column(Integer, primary_key=True)
    full_name = Column(String)
    phone_number = Column(String)

    '''def __repr__(self):
        return f"<PhoneBook(full_name={self.full_name}, last_name={self.last_name}, phone_number={self.phone_number})>" '''


def fake_hash_password(password: str):
    return "fakehashed" + password


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    roles: Optional[list] = None


class UserInDB(User):
    hashed_password: str
    # password: Optional[str] = None


# Create the database schema
Base.metadata.create_all(engine)

# Create the session class for database operations
Session = sessionmaker(bind=engine)


# Create the Pydantic model class for request and response data
class Person(BaseModel):
    full_name: str
    phone_number: str


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
    print(f'Current USer is : {current_user}')
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# Define the API endpoints

@app.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {"access_token": user.username, "token_type": "bearer"}


@app.get("/users/me")
async def read_users_me(
        current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


@app.get("/PhoneBook/list")
def list_phonebook():
    # Get a new session
    session = Session()
    # Query all the records in the phonebook table
    phonebook = session.query(PhoneBook).all()
    # Close the session
    session.close()
    # Return the list of records as JSON objects
    return phonebook


@app.post("/PhoneBook/add")
def add_person(person: Person):
    # Get a new session
    session = Session()
    # Check if the person already exists in the database by phone number
    existing_person = session.query(PhoneBook).filter_by(phone_number=person.phone_number).first()
    # If the person exists, raise an exception
    if existing_person:
        session.close()
        raise HTTPException(status_code=400, detail="Person already exists in the database")
    # Otherwise, create a new PhoneBook record and add it to the database
    new_person = PhoneBook(full_name=person.full_name, phone_number=person.phone_number)
    session.add(new_person)
    session.commit()
    # Close the session
    session.close()
    # Return a success message
    return {"message": "Person added successfully"}


@app.put("/PhoneBook/deleteByName")
def delete_by_name(full_name: str):
    # Get a new session
    session = Session()
    # Query the person by name in the database
    person = session.query(PhoneBook).filter_by(full_name=full_name).first()
    # If the person does not exist, raise an exception
    if not person:
        session.close()
        raise HTTPException(status_code=404, detail="Person not found in the database")
    # Otherwise, delete the person from the database
    session.delete(person)
    session.commit()
    # Close the session
    session.close()
    # Return a success message
    return {"message": "Person deleted successfully"}


@app.put("/PhoneBook/deleteByNumber")
def delete_by_number(phone_number: str):
    # Get a new session
    session = Session()
    # Query the person by phone number in the database
    person = session.query(PhoneBook).filter_by(phone_number=phone_number).first()
    # If the person does not exist, raise an exception
    if not person:
        session.close()
        raise HTTPException(status_code=404, detail="Person not found in the database")
    # Otherwise, delete the person from the database
    session.delete(person)
    session.commit()
    # Close the session
    session.close()
    # Return a success message
    return {"message": "Person deleted successfully"}
