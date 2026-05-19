"""Tests for authentication endpoints."""
import pytest


def test_register_success(client):
    resp = client.post("/api/auth/register", json={
        "username": "newuser",
        "email": "newuser@example.com",
        "password": "Secure123!",
    })
    assert resp.status_code in (200, 201)
    data = resp.json()
    assert "access_token" in data


def test_register_duplicate_email(client):
    payload = {"username": "dup1", "email": "dup@example.com", "password": "Secure123!"}
    client.post("/api/auth/register", json=payload)
    resp = client.post("/api/auth/register", json={**payload, "username": "dup2"})
    assert resp.status_code == 400


def test_register_weak_password(client):
    resp = client.post("/api/auth/register", json={
        "username": "weakpw",
        "email": "weakpw@example.com",
        "password": "123",
    })
    assert resp.status_code == 422


def test_login_wrong_password(client):
    client.post("/api/auth/register", json={
        "username": "logintest",
        "email": "logintest@example.com",
        "password": "Correct123!",
    })
    resp = client.post("/api/auth/login", data={
        "username": "logintest@example.com",
        "password": "WrongPassword!",
    })
    assert resp.status_code in (400, 401, 403)


def test_login_nonexistent_user(client):
    resp = client.post("/api/auth/login", data={
        "username": "nobody@example.com",
        "password": "Whatever123!",
    })
    assert resp.status_code in (400, 401, 403)


def test_me_unauthenticated(client):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] in ("healthy", "degraded")


def test_root_endpoint(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["status"] == "online"
