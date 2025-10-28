import uvicorn
from fastapi import FastAPI
from src.routes import (
    movie_router,
    accounts_router,
)
from src.database import initialize_sqlite
from src.config import get_settings

initialize_sqlite()

settings = get_settings()

app = FastAPI(
    title="Movies homework",
    description="Description of project"
)

api_version_prefix = "/api/v1"

app.include_router(accounts_router, prefix=f"{api_version_prefix}/accounts", tags=["accounts"])
app.include_router(movie_router, prefix=f"{api_version_prefix}/theater", tags=["theater"])


if __name__ == "__main__":
    uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=True)
