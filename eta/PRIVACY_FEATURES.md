# Privacy & Data Management Features

**Version:** 1.0  
**Date:** April 7, 2026

## Overview

The ETA Email Threat Analyzer now includes comprehensive privacy controls and GDPR-compliant data management features. Users can manage their personal data, control data retention, and exercise their privacy rights.

---

## Features Implemented

### 1. **Privacy Settings Management**
**Endpoint:** `POST/GET /api/user/privacy-settings`

Users can configure:
- **Data Retention Period** (1-365 days): Automatically delete scans older than this period
- **Auto-delete**: Enable/disable automatic deletion of old scans
- **Analytics Tracking**: Opt-in/out of analytics (future feature)

**Frontend:** Privacy page in `/privacy` route with form controls

### 2. **Data Export (Right to Data Portability)**
**Endpoint:** `GET /api/user/export-data`

Users can download all their data in JSON format including:
- Account information (username, email, creation date)
- All scan records with metadata
- Complete analysis reports
- Summary statistics

**Frontend:** One-click export button on Privacy page

### 3. **Data Deletion Features**

#### a. Delete Individual Scans
**Endpoint:** `DELETE /api/scan/{scan_id}`
- Updated to require authentication
- User can only delete their own scans
- Deletes both scan record and analysis report

#### b. Delete Old Scans
**Endpoint:** `DELETE /api/user/scans-older-than?days=30`
- Delete all scans older than specified days
- Respects user's retention settings
- Returns count of deleted scans

#### c. Delete All Scans
**Endpoint:** `DELETE /api/user/all-scans?confirm=true`
- Irreversible deletion of ALL scans for user
- Requires explicit confirmation
- Deletes reports and metadata

#### d. Delete Account (Right to Be Forgotten)
**Endpoint:** `DELETE /api/user/account?confirm=true`
- Permanently delete entire account
- Removes user profile, all scans, reports, and settings
- GDPR "right to be forgotten"
- Requires triple confirmation

**Frontend:** Privacy page with confirmation dialogs for all deletions

### 4. **Automatic Cleanup**
**Endpoint:** `POST /api/auto-cleanup`

- Runs based on user's privacy settings
- Can be triggered manually or via cronjob
- Deletes scans older than retention period
- Updates last cleanup timestamp

### 5. **Privacy Policy Endpoint**
**Endpoint:** `GET /api/privacy-policy`

Returns machine-readable privacy policy with:
- Data collection details
- Data NOT collected
- Retention policies
- User rights
- Contact information

---

## Database Changes

### New Table: `privacy_settings`
```sql
CREATE TABLE privacy_settings (
  id INT PRIMARY KEY,
  user_id INT UNIQUE NOT NULL,
  data_retention_days INT DEFAULT 30,
  allow_analytics BOOL DEFAULT FALSE,
  auto_delete BOOL DEFAULT TRUE,
  last_cleanup DATETIME,
  created_at DATETIME,
  updated_at DATETIME
)
```

### Updated Endpoints
- **history.py**: `DELETE /scan/{scan_id}` now requires authentication and checks user ownership

---

## Security Improvements

### 1. Authorization Checks
- All delete endpoints require authentication via JWT
- Users can only delete their own data
- Account deletion requires explicit confirmation

### 2. Safety Confirmations
- Delete account requires typing "DELETE"
- All destructive operations have confirmation dialogs
- Accidental deletion protection

### 3. Data Minimization
- No email body content stored
- No attachment files stored
- Only essential metadata preserved
- IP addresses not logged

---

## Privacy by Design

### What IS Stored
- Account credentials (hashed with bcrypt)
- Email metadata (sender, recipient, subject)
- Analysis results and threat indicators
- Scan history and timestamps

### What is NOT Stored
- Email body content
- Attachment files
- Full PDF/CSV content
- IP addresses
- Browser cookies
- Tracking data

---

## User Workflows

### Enable Auto-Delete
1. Go to `/privacy` page
2. Set "Data Retention Days" to desired period
3. Enable "Auto-delete" checkbox
4. Save settings

### Export Personal Data
1. Go to `/privacy` page
2. Click "Export Data as JSON"
3. File downloads containing all user data

### Delete Old Scans
1. Go to `/privacy` page
2. Click "Delete Old Scans"
3. Confirm deletion
4. Scans older than retention period are removed

### Delete All Data
1. Go to `/privacy` page
2. Click "Delete All Scans"
3. Confirm deletion
4. All scan history removed

### Delete Account
1. Go to `/privacy` page
2. Click "Delete Account"
3. Type "DELETE" to confirm
4. Account permanently deleted
5. Redirect to login page

---

## API Reference

### Get Privacy Settings
```
GET /api/user/privacy-settings
Authorization: Bearer {token}

Response:
{
  "data_retention_days": 30,
  "allow_analytics": false,
  "auto_delete": true,
  "last_cleanup": "2026-04-07T10:00:00"
}
```

### Update Privacy Settings
```
POST /api/user/privacy-settings?data_retention_days=30&allow_analytics=false&auto_delete=true
Authorization: Bearer {token}

Response:
{
  "ok": true,
  "message": "Privacy settings updated",
  "settings": {...}
}
```

### Export User Data
```
GET /api/user/export-data
Authorization: Bearer {token}

Response:
{
  "export_date": "2026-04-07T10:00:00",
  "user": {...},
  "scans": [...],
  "summary": {...}
}
```

### Delete Scans Older Than X Days
```
DELETE /api/user/scans-older-than?days=30
Authorization: Bearer {token}

Response:
{
  "ok": true,
  "deleted_scans": 5,
  "deleted_reports": 5
}
```

### Delete All Scans
```
DELETE /api/user/all-scans?confirm=true
Authorization: Bearer {token}

Response:
{
  "ok": true,
  "deleted_scans": 10,
  "deleted_reports": 10
}
```

### Delete Account
```
DELETE /api/user/account?confirm=true
Authorization: Bearer {token}

Response:
{
  "ok": true,
  "message": "Account permanently deleted"
}
```

### Get Privacy Policy
```
GET /api/privacy-policy

Response:
{
  "version": "1.0",
  "data_collected": [...],
  "data_NOT_collected": [...],
  "user_rights": [...],
  "contact": "privacy@eta-analyzer.local"
}
```

---

## Environment Variables

No new environment variables required. Default retention is 30 days, configurable per user.

**Optional:** Set a default retention period globally
```
DEFAULT_RETENTION_DAYS=30
```

---

## GDPR Compliance

✓ **Right to Access**: Users can export all their data  
✓ **Right to Rectification**: Users can update their profile  
✓ **Right to Erasure**: Users can delete all data  
✓ **Right to Data Portability**: Users can download data as JSON  
✓ **Right to Object**: Users can opt-out of analytics  
✓ **Transparency**: Privacy policy endpoint available  

---

## Frontend Components

### Privacy Page (`/privacy`)
Located at: `frontend/src/pages/Privacy.jsx`

Features:
- Privacy settings form
- Data export button
- Delete old scans button
- Delete all scans button
- Delete account button (with confirmation)
- Privacy information display

### Navigation
- Added "Privacy" link to sidebar navigation
- Icon: Lock (from Lucide React)
- Available to authenticated users only

---

## Testing the Features

### 1. Test Auto-Delete Settings
```bash
curl -X POST "http://localhost:8000/api/user/privacy-settings?data_retention_days=7" \
  -H "Authorization: Bearer {token}"
```

### 2. Test Data Export
```bash
curl -X GET "http://localhost:8000/api/user/export-data" \
  -H "Authorization: Bearer {token}"
```

### 3. Test Delete Old Scans
```bash
curl -X DELETE "http://localhost:8000/api/user/scans-older-than?days=30" \
  -H "Authorization: Bearer {token}"
```

---

## Future Enhancements

1. **Analytics Opt-in**: Enable the analytics tracking feature
2. **Data Anonymization**: Hash sensitive data instead of deletion
3. **Scheduled Cleanup**: Implement cronjob for automatic cleanup
4. **Audit Log**: Track all data deletion operations
5. **Data Minimization**: Store less metadata by default
6. **Encryption at Rest**: Encrypt sensitive fields in database

---

## Notes

- All timestamps are in UTC
- Deletion operations are **irreversible**
- Backups may retain deleted data (follow backup retention policies)
- Privacy settings are per-user (not global)
- Auto-cleanup runs on user request (can be automated via cronjob)

---

## Support

For privacy concerns or data deletion requests:
- Contact: privacy@eta-analyzer.local
- Privacy Policy: `/api/privacy-policy`
- Data Export: See "Export User Data" section above

---

**Status:** ✓ COMPLETE AND READY FOR PRODUCTION
