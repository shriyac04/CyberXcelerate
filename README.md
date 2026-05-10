# CAPE API Interface

A simple web interface for submitting files to the CAPE sandbox API for malware analysis.

## Features

- Clean, modern UI for file upload
- Support for various file types (exe, dll, zip, apk, office documents, pdf, browsers)
- Configurable timeout and priority settings
- **Submission history sidebar** - View all your previous submissions
- **Click to view status** - Click any submission to see detailed task status
- Real-time status updates with color-coded badges
- Persistent storage using localStorage
- Backend proxy to avoid CORS issues

## Installation

1. Install Node.js (if you don't have it already)

2. Install dependencies:
```bash
npm install
```

3. Configure environment (create a `.env` file in the project root):

```
MONGODB_URI=mongodb+srv://USER:PASS@HOST/DBNAME?retryWrites=true&w=majority
JWT_SECRET=<generate_a_long_random_secret>
PORT=3000
CAPE_API_BASE=http://you_cape_ip:port
```

## Usage

1. Start the server:
```bash
npm start
```

Or for development with auto-reload:
```bash
npm run dev
```

2. Open your browser and navigate to:
```
http://localhost:3000
```

3. Register or login using the auth bar at the top (email + password)
4. Select a file, choose the package type, set timeout and priority, then click "Submit for Analysis"
4. View your submission history in the left sidebar
5. Click on any submission to view its current status and details

## Configuration

The CAPE API endpoints are configured in `server.js`:

```javascript
const CAPE_API_BASE = 'http://your_cape_ip:port';
const CAPE_API_UPLOAD_URL = `${CAPE_API_BASE}/apiv2/tasks/create/file/`;
```

You can modify this URL to point to your CAPE sandbox instance.

## How It Works

- The frontend (index.html) sends the file to the local proxy server
- The backend (server.js) forwards the request to the CAPE API
- This approach avoids CORS (Cross-Origin Resource Sharing) issues

## File Structure

```
.
├── index.html      # Frontend web interface
├── server.js       # Backend proxy server
├── package.json    # Node.js dependencies
└── README.md       # This file
```

## API Endpoints

The backend provides the following endpoints:

- `POST /api/upload` - Uploads a file to the CAPE sandbox
  - Parameters:
    - `file` - The file to upload
    - `package` - Package type (exe, dll, zip, etc.)
    - `timeout` - Analysis timeout in seconds
    - `priority` - Task priority (1-10)

- `GET /api/task/:taskId` - Fetches the status of a specific task
  - Returns detailed task information including status, machine, platform, and options

- `POST /api/auth/register` - Register a new user (JSON: `{ email, password }`)
- `POST /api/auth/login` - Login and receive a JWT (JSON: `{ email, password }`)

Protected routes require `Authorization: Bearer <token>`.

# CapeUI
