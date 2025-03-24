# GyanShala - Educational Platform

A modern Flask-based educational platform for hosting video lectures and PDF materials.

## Features

- Dynamic welcome page with auto-redirect
- Modern UI for batch display
- Organized content by chapters
- Secure HLS video player for m3u8 streams with quality selection
- Video proxy to protect source URLs
- Gujarati font support (Babloo Bhai)
- PDF material downloads
- Mobile-responsive design

## Installation

1. Make sure you have Python 3.7+ installed
2. Clone this repository
3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Running the Application

```bash
python app.py
```

The application will start on `http://localhost:5000`

## File Structure

- `app.py` - Main Flask application
- `data.txt` - Source data file with course materials
- `templates/` - HTML templates
- `static/` - Static assets (CSS, JS, images)
- `static/fonts/` - Gujarati fonts including Babloo Bhai

## Usage

1. The welcome page appears for 2 seconds before redirecting to the batches page
2. Select the "Aarambh Batch 11th GyanShala" batch to view course content
3. Content is organized by chapters with videos and PDFs
4. Click on a video to view it in the secure player with quality selection
5. Click on a PDF to open or download it

## Security Features

- Videos are streamed through a server-side proxy to hide actual URLs
- Videos are played securely via HLS
- Quality selection with automatic URL adjustment
- Right-click is disabled on videos to prevent easy downloading
- Common keyboard shortcuts for saving content are disabled

## Quality Selector

The video player includes a quality selector that allows users to choose from:
- 1080p (Full HD)
- 720p (HD) - Default
- 480p
- 360p
- 240p

When changing quality, the player maintains the current playback position and state.

## Adding More Content

To add more content, update the `data.txt` file with the following format:

```
Title:URL
```

Where:
- Title should contain chapter information (e.g., "CH 1 Chemistry")
- URL should point to either a video (.m3u8) or PDF file

## License

Copyright (c) 2025 GyanShala 