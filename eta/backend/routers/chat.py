"""
Real-time support chat between users and admins via WebSocket.
REST endpoints expose chat history and unread counts.
"""
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db, ChatMessage, Notification, User
from routers.auth import get_current_user, verify_access_token

router = APIRouter(prefix="/chat", tags=["chat"])
logger = logging.getLogger(__name__)


# ── WebSocket connection manager ──────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        # user_id -> WebSocket (one active connection per user)
        self._users: Dict[int, WebSocket] = {}
        # All admin WebSocket connections
        self._admins: List[WebSocket] = []

    async def connect_user(self, user_id: int, ws: WebSocket):
        await ws.accept()
        self._users[user_id] = ws
        logger.info("Chat WS connected: user %d", user_id)

    async def connect_admin(self, ws: WebSocket):
        await ws.accept()
        self._admins.append(ws)
        logger.info("Chat WS connected: admin")

    def disconnect_user(self, user_id: int):
        self._users.pop(user_id, None)

    def disconnect_admin(self, ws: WebSocket):
        try:
            self._admins.remove(ws)
        except ValueError:
            pass

    async def send_to_user(self, user_id: int, data: dict):
        ws = self._users.get(user_id)
        if ws:
            try:
                await ws.send_json(data)
            except Exception:
                self.disconnect_user(user_id)

    async def broadcast_to_admins(self, data: dict):
        dead = []
        for ws in list(self._admins):
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect_admin(ws)

    def is_admin_online(self) -> bool:
        return len(self._admins) > 0


manager = ConnectionManager()


def _auth_ws(token: str, db: Session) -> Optional[User]:
    """Validate a Bearer token passed as a WebSocket query param."""
    if not token:
        return None
    try:
        payload = verify_access_token(token)
        user_id = int(payload.get("sub", 0))
        return db.query(User).filter(User.id == user_id, User.is_active == True).first()
    except Exception:
        return None


def _create_notification(db: Session, user_id: int, type_: str, title: str, body: str = None, link: str = None):
    notif = Notification(user_id=user_id, type=type_, title=title, body=body, link=link)
    db.add(notif)
    db.commit()


# ── WebSocket endpoints ───────────────────────────────────────────────────────

@router.websocket("/ws/user")
async def ws_user(websocket: WebSocket, token: str = Query(...), db: Session = Depends(get_db)):
    """User-side WebSocket. Requires ?token=<access_token>."""
    user = _auth_ws(token, db)
    if not user:
        await websocket.close(code=4001)
        return

    await manager.connect_user(user.id, websocket)
    # Tell user whether admin is online
    await websocket.send_json({"type": "status", "admin_online": manager.is_admin_online()})

    try:
        while True:
            raw = await websocket.receive_text()
            data = json.loads(raw)
            text = (data.get("message") or "").strip()
            topic = data.get("topic", "general")
            if not text:
                continue

            # Persist message
            msg = ChatMessage(
                user_id=user.id, sender_role="user",
                sender_name=user.username, message=text, topic=topic,
            )
            db.add(msg)
            db.commit()
            db.refresh(msg)

            payload = {
                "type": "message",
                "id": msg.id,
                "user_id": user.id,
                "username": user.username,
                "sender_role": "user",
                "message": text,
                "topic": topic,
                "created_at": msg.created_at.isoformat(),
            }
            # Forward to all admins
            await manager.broadcast_to_admins(payload)

            # Auto-reply if no admin online
            if not manager.is_admin_online():
                auto = ChatMessage(
                    user_id=user.id, sender_role="admin",
                    sender_name="Support Bot",
                    message="Our support team has received your message and will respond shortly. You'll be notified when they reply.",
                    topic=topic,
                )
                db.add(auto)
                # Notification for later
                _create_notification(db, user.id, "message",
                    "Support message received",
                    "We'll get back to you as soon as an admin is available.", "/")
                db.commit()
                db.refresh(auto)
                await websocket.send_json({
                    "type": "message", "id": auto.id,
                    "sender_role": "admin", "sender_name": "Support Bot",
                    "message": auto.message, "created_at": auto.created_at.isoformat(),
                })

    except WebSocketDisconnect:
        manager.disconnect_user(user.id)


@router.websocket("/ws/admin")
async def ws_admin(websocket: WebSocket, token: str = Query(...), db: Session = Depends(get_db)):
    """Admin-side WebSocket. Connects admin to all user conversations."""
    user = _auth_ws(token, db)
    if not user or user.role not in ("admin", "superadmin"):
        await websocket.close(code=4003)
        return

    await manager.connect_admin(websocket)
    # Notify all connected users that admin is now online
    for uid, ws in list(manager._users.items()):
        try:
            await ws.send_json({"type": "status", "admin_online": True})
        except Exception:
            pass

    try:
        while True:
            raw = await websocket.receive_text()
            data = json.loads(raw)
            text = (data.get("message") or "").strip()
            target_user_id = data.get("user_id")
            if not text or not target_user_id:
                continue

            msg = ChatMessage(
                user_id=int(target_user_id), sender_role="admin",
                sender_name=user.username, message=text,
            )
            db.add(msg)
            # Create notification for the user
            _create_notification(db, int(target_user_id), "message",
                f"Reply from Support",
                text[:120], "/")
            db.commit()
            db.refresh(msg)

            payload = {
                "type": "message", "id": msg.id,
                "sender_role": "admin", "sender_name": user.username,
                "message": text, "created_at": msg.created_at.isoformat(),
            }
            # Send to the target user if online
            await manager.send_to_user(int(target_user_id), payload)
            # Echo back to admin
            await websocket.send_json({**payload, "echo": True, "user_id": int(target_user_id)})

    except WebSocketDisconnect:
        manager.disconnect_admin(websocket)
        for uid, ws in list(manager._users.items()):
            try:
                await ws.send_json({"type": "status", "admin_online": manager.is_admin_online()})
            except Exception:
                pass


# ── REST endpoints ────────────────────────────────────────────────────────────

class SendMessageBody(BaseModel):
    message: str
    topic: Optional[str] = "general"


@router.get("/messages")
def get_my_messages(
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the authenticated user's chat history."""
    msgs = (
        db.query(ChatMessage)
        .filter(ChatMessage.user_id == current_user.id)
        .order_by(ChatMessage.created_at.asc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": m.id, "sender_role": m.sender_role, "sender_name": m.sender_name,
            "message": m.message, "topic": m.topic, "is_read": m.is_read,
            "created_at": m.created_at.isoformat(),
        }
        for m in msgs
    ]


@router.get("/unread-count")
def get_unread_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    count = (
        db.query(ChatMessage)
        .filter(
            ChatMessage.user_id == current_user.id,
            ChatMessage.sender_role == "admin",
            ChatMessage.is_read == False,
        )
        .count()
    )
    return {"count": count}


@router.post("/messages/read")
def mark_messages_read(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    db.query(ChatMessage).filter(
        ChatMessage.user_id == current_user.id,
        ChatMessage.sender_role == "admin",
        ChatMessage.is_read == False,
    ).update({"is_read": True})
    db.commit()
    return {"ok": True}


# ── Admin-only endpoints ──────────────────────────────────────────────────────

@router.get("/admin/conversations")
def admin_get_conversations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return latest message per user (admin inbox view)."""
    if current_user.role not in ("admin", "superadmin"):
        raise HTTPException(403, "Admin only")

    # Get all users who have sent at least one message
    user_ids = (
        db.query(ChatMessage.user_id)
        .filter(ChatMessage.sender_role == "user")
        .distinct()
        .all()
    )
    conversations = []
    for (uid,) in user_ids:
        user = db.query(User).filter(User.id == uid).first()
        last_msg = (
            db.query(ChatMessage)
            .filter(ChatMessage.user_id == uid)
            .order_by(ChatMessage.created_at.desc())
            .first()
        )
        unread = (
            db.query(ChatMessage)
            .filter(ChatMessage.user_id == uid, ChatMessage.sender_role == "user", ChatMessage.is_read == False)
            .count()
        )
        if last_msg:
            conversations.append({
                "user_id": uid,
                "username": user.username if user else f"User {uid}",
                "email": user.email if user else "",
                "last_message": last_msg.message,
                "last_message_role": last_msg.sender_role,
                "last_at": last_msg.created_at.isoformat(),
                "unread": unread,
            })
    conversations.sort(key=lambda x: x["last_at"], reverse=True)
    return conversations


@router.get("/admin/messages/{user_id}")
def admin_get_user_messages(
    user_id: int,
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get full conversation with a specific user (admin only)."""
    if current_user.role not in ("admin", "superadmin"):
        raise HTTPException(403, "Admin only")

    msgs = (
        db.query(ChatMessage)
        .filter(ChatMessage.user_id == user_id)
        .order_by(ChatMessage.created_at.asc())
        .limit(limit)
        .all()
    )
    # Mark user messages as read
    db.query(ChatMessage).filter(
        ChatMessage.user_id == user_id,
        ChatMessage.sender_role == "user",
        ChatMessage.is_read == False,
    ).update({"is_read": True})
    db.commit()

    return [
        {
            "id": m.id, "sender_role": m.sender_role, "sender_name": m.sender_name,
            "message": m.message, "topic": m.topic, "is_read": m.is_read,
            "created_at": m.created_at.isoformat(),
        }
        for m in msgs
    ]
