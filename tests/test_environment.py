from backend import config


def test_application_name():
    assert config.APP_NAME == "CTI Correlation and Prioritization System"


def test_environment():
    assert config.APP_ENV == "development"