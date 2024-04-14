import pytest
from fastapi.testclient import TestClient

from app import app, PhoneBook
import pytest
from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base

# Setup the engine and sessionmaker
SQLALCHEMY_DATABASE_URL = "sqlite:///./phonebook.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)  # Use an in-memory SQLite database for testing
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def setup_function():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        # Add multiple persons
        persons = [
            PhoneBook(full_name="Jane Doe", phone_number="1234567890"),
            PhoneBook(full_name="John Doe", phone_number="0987654321"),
            PhoneBook(full_name="Alice Smith", phone_number="9876543210"),
            # Add more persons here
        ]
        db.add_all(persons)
        db.commit()
    finally:
        db.close()


def teardown_function():
    db = TestingSessionLocal()
    try:
        db.query(PhoneBook).delete()
        db.commit()
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_and_teardown():
    setup_function()

    yield  # This line is where the test will be run

    teardown_function()


# Create a TestClient instance
client = TestClient(app)

# Define test user credentials
username = "bob"
password = "secret3"


@pytest.fixture
def auth_headers():
    # Send a request to the login endpoint with valid credentials
    response = client.post("/token", data={"username": username, "password": password})

    # Check if the login was successful
    assert response.status_code == 200

    # Extract the token from the response JSON
    token = response.json()["access_token"]

    # Return the token in the format required for authentication headers
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize(
    "name, phoneNumber, expected_status",
    [
        # Good inputs
        ("Alex Doe", "123-456-7890", 200),
        ("Jane Smith", "987-654-3210", 200),
        ("Bob Johnson", "555-555-5555", 200),

        # Bad inputs
        ("John", "12345", 400),  # Invalid phone number
        ("", "123-456-7890", 400),  # Empty name
        ("John Doe", "", 400),  # Empty phone number
        ("John Doe", "123456789012345", 400),  # Phone number too long
        ("John Doe", "abc-def-ghij", 400),  # Phone number contains non-numeric characters
        # Add more test cases here
    ],
)
def test_add_person(name, phoneNumber, expected_status, auth_headers):
    # Test adding a person using the obtained token for authentication
    response = client.post(
        "/PhoneBook/add",
        json={"name": name, "phoneNumber": phoneNumber},
        headers=auth_headers
    )
    if response.status_code != expected_status:
        print(response.json())
    assert response.status_code == expected_status


@pytest.mark.parametrize(
    "name, expected_status",
    [
        # Valid inputs
        ("John Doe", 200),  # person exists in the database
        ("Jane Doe", 200),  # person exists in the database
        ("Alex Smite", 404),  # person does not exist in the database

        # Invalid inputs
        ("Nonexistent Person", 404),  # person does not exist in the database
        ("", 400),  # name is empty
        ("John Smith", 404),  # person does not exist in the database
        # Add more test cases here
    ],
)
def test_delete_by_name(name, expected_status, auth_headers):
    # Test deleting a person by name using the obtained token for authentication
    response = client.put(
        f"/PhoneBook/deleteByName?name={name}",
        headers=auth_headers
    )
    if response.status_code != expected_status:
        print(response.json())
    assert response.status_code == expected_status


@pytest.mark.parametrize(
    "number, expected_status",
    [
        # Valid inputs
        ("1234567890", 200),  # person exists in the database
        ("9876543210", 200),  # person exists in the database
        ("1122331431", 404),  # person does not exist in the database

        # Invalid inputs
        ("", 400),  # number is empty
        ("123456789012345", 400),  # number is too long
        ("abc-def-ghij", 400),  # number contains non-numeric characters
        # Add more test cases here
    ],
)
def test_delete_by_number(number, expected_status, auth_headers):
    # Test deleting a person by number using the obtained token for authentication
    response = client.put(
        f"/PhoneBook/deleteByNumber?number={number}",
        headers=auth_headers
    )
    if response.status_code != expected_status:
        print(response.json())
    assert response.status_code == expected_status
