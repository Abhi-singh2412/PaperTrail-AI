import os
import tempfile
import shutil
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Import our core cybersecurity engine
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from core import extract_metadata, verify_ledger_integrity

app = FastAPI(
    title="PaperTrail AI - Metadata Forensics API",
    description="Layer 1 Document Integrity & Forensics Engine",
    version="1.0.0"
)

# Allow CORS so the React frontend can talk to this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def health_check():
    """Simple health check endpoint."""
    return {"status": "online", "service": "PaperTrail AI Forensics Engine"}


@app.post("/analyze")
async def analyze_document(file: UploadFile = File(...)):
    """
    Accepts a document upload, runs the full forensics pipeline, 
    and returns the risk report.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file uploaded")

    # Save uploaded file to a temporary location securely
    ext = Path(file.filename).suffix.lower()
    
    # We create a temporary file with the exact original extension
    # so our format-specific extractors know how to handle it.
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        # Copy the uploaded file contents to the temp file
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        # Run our cybersecurity engine!
        report = extract_metadata(tmp_path)
        
        # Override the random temp filename with the original filename
        # so the report looks correct.
        report["source_file"] = file.filename
        
        if "error" in report:
            raise HTTPException(status_code=400, detail=report["error"])
            
        return JSONResponse(content=report)
        
    finally:
        # Always clean up the temporary file
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.get("/ledger/verify")
def verify_ledger():
    """
    Verifies the integrity of the Merkle tree document ledger.
    """
    result = verify_ledger_integrity()
    return result

if __name__ == "__main__":
    import uvicorn
    # If someone runs `python api/routes.py`, start the server
    uvicorn.run("api.routes:app", host="0.0.0.0", port=8000, reload=True)
