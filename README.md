# TakedownIQ

TakedownIQ is a comprehensive tool for cybersecurity professionals to safely analyze suspicious domains without directly visiting them. It allows users to capture screenshots, collect domain metadata, and generate detailed PDF reports for takedown requests or internal documentation.

## Features

- **Built-in Screenshot Tool**: Capture screenshots of suspicious domains directly within the application
- **Comprehensive Domain Analysis**: Collect WHOIS, DNS, SSL certificate, and VirusTotal data
- **In-Memory Processing**: All data is processed in memory with no persistence after the session ends
- **AI Risk Scoring**: Get intelligent risk assessments with detailed explanations
- **Forensic Timeline**: View a chronological timeline of domain registration, DNS changes, and certificate issuance
- **PDF Report Generation**: Download professional reports for internal review or registrar escalation

## User Flow

1. Investigate the domain in a secure browser (like Silo)
2. Capture a screenshot using TakedownIQ's built-in screenshot tool
3. Input the domain name and any relevant notes
4. Submit for automated analysis
5. Review the analysis results including forensic timeline, AI risk score, and evidence preview
6. Download the PDF report
7. End the session, ensuring all data is erased

## Project Structure

```
/var/www/TakedownIQ/
├── backend/                 # FastAPI backend
│   ├── main.py              # Main API implementation
│   ├── requirements.txt     # Python dependencies
│   └── venv/                # Python virtual environment
├── frontend/                # React frontend
│   ├── src/                 # Source code
│   │   ├── components/      # Reusable components
│   │   │   └── ScreenshotTool.jsx  # Screenshot capture tool
│   │   ├── pages/           # Application pages
│   │   ├── App.jsx          # Main application component
│   │   └── main.jsx         # Entry point
│   ├── public/              # Static assets
│   ├── index.html           # HTML template
│   ├── package.json         # NPM dependencies
│   └── vite.config.js       # Vite configuration
├── .env.example             # Environment variables template
├── nginx.conf               # Nginx configuration
└── README.md                # This file
```

## Technology Stack

- **Frontend**: React, Vite, Tailwind CSS, Framer Motion
- **Backend**: FastAPI, Python
- **Domain Analysis**:
  - WHOIS: python-whois
  - DNS: dnspython
  - SSL: Python's ssl module
  - Reputation: VirusTotal API (vt-py)
- **PDF Generation**: ReportLab, WeasyPrint
- **Deployment**: Nginx

## Setup Instructions

### Prerequisites

- Python 3.8+
- Node.js 16+
- Nginx
- VirusTotal API key

### Backend Setup

1. Create and activate a virtual environment:
   ```bash
   cd /var/www/TakedownIQ/backend
   python -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file with your VirusTotal API key:
   ```bash
   cp ../.env.example .env
   # Edit .env to add your VirusTotal API key
   ```

4. Start the backend server:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8025
   ```

### Frontend Setup

1. Install dependencies:
   ```bash
   cd /var/www/TakedownIQ/frontend
   npm install
   ```

2. For development:
   ```bash
   npm run dev
   ```

3. For production build:
   ```bash
   npm run build
   ```

### Deployment

1. Configure Nginx:
   ```bash
   sudo cp /var/www/TakedownIQ/nginx.conf /etc/nginx/sites-available/takedowniq
   sudo ln -s /etc/nginx/sites-available/takedowniq /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl reload nginx
   ```

2. Set up a systemd service for the backend:
   ```bash
   sudo nano /etc/systemd/system/takedowniq.service
   ```
   
   Add the following content:
   ```
   [Unit]
   Description=TakedownIQ Backend
   After=network.target

   [Service]
   User=www-data
   WorkingDirectory=/var/www/TakedownIQ/backend
   ExecStart=/var/www/TakedownIQ/backend/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8025
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

3. Start and enable the service:
   ```bash
   sudo systemctl start takedowniq
   sudo systemctl enable takedowniq
   ```

## Security Considerations

- All data is processed in memory and not persisted after the session ends
- The application does not store any user data or evidence
- For production use, restrict CORS settings in the backend
- Use HTTPS in production environments

## API Documentation

The backend API is available at `/tools/takedowniq/api/docs` when the server is running.

## License

This project is proprietary and confidential.

## Support

For support or feature requests, please contact the development team.
