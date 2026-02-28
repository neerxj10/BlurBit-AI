from fastapi import FastAPI

from blockchain_logger import router as blockchain_logger_router


app = FastAPI(title="Blurbit Blockchain Logger Example")

# Integrates tamper-proof logging routes:
# POST /log-event
# POST /verify-log
app.include_router(blockchain_logger_router)


@app.get("/")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "Blurbit Blockchain Logger"}
