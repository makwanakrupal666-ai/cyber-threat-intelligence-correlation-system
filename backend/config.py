import os

from dotenv import load_dotenv


# Load variables from the .env file
load_dotenv()


APP_NAME = os.getenv(
    "APP_NAME",
    "CTI Correlation and Prioritization System"
)

APP_ENV = os.getenv(
    "APP_ENV",
    "development"
)

LOG_LEVEL = os.getenv(
    "LOG_LEVEL",
    "INFO"
)