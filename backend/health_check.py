from backend.config import APP_NAME, APP_ENV
from backend.logging_config import setup_logging


logger = setup_logging()


def main():
    logger.info("Starting CTI project environment check")

    print()
    print("CTI PROJECT ENVIRONMENT CHECK")
    print("-" * 35)
    print(f"Application : {APP_NAME}")
    print(f"Environment : {APP_ENV}")
    print("Python      : OK")
    print("Configuration: OK")
    print("Logging     : OK")
    print("-" * 35)
    print("Phase 0 basic environment is working.")


if __name__ == "__main__":
    main()