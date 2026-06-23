from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PFSENSE_HOST: str
    PFSENSE_USER: str
    PFSENSE_PASS: str
    API_KEY: str = "changeme"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
