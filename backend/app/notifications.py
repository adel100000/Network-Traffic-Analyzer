from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import List

router = APIRouter()
active_connections: List[WebSocket] = []

async def notify_all(message: str):
    for conn in active_connections:
        try:
            await conn.send_text(message)
        except:
            pass

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)

@router.post("/send")
async def send_notification(msg: str):
    await notify_all(msg)
    return {"status": "sent", "message": msg}
