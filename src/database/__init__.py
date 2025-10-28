import os
from src.database.models.base import Base

environment = os.getenv("ENVIRONMENT", "developing")

if environment == "testing":
    from .session_sqlite import (
        reset_sqlite_database as reset_database,
        initialize_sqlite,
        get_sqlite_db_contextmanager as get_db_contextmanager,
        get_sqlite_db as get_db,
    )
else:
    from .session_postgresql import initialize_postgresql
    initialize_postgresql()
    from .session_postgresql import (
        get_postgresql_db_contextmanager as get_db_contextmanager,
        get_postgresql_db as get_db,
    )
