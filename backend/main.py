from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import engine, Base, get_db
from crud import init_db
from routes import router

Base.metadata.create_all(bind=engine)

with next(get_db()) as db:
    init_db(db)

app = FastAPI(title="Airport SRUD API", version="3.0.0", docs_url="/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)