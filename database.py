from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

DATABASE_URL = "postgresql+psycopg://securecheck:SecureCheckDev%40123@localhost:5432/securecheck"

engine = create_engine(
    DATABASE_URL,
    connect_args={"connect_timeout": 5},
    echo=True
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)


class Base(DeclarativeBase):
    pass