from flask import Flask, render_template, redirect, url_for, jsonify, request, Response, abort, send_file, make_response
import os
import re
import json
import requests
import time
import hashlib
import uuid
import base64
from functools import wraps
import urllib.parse
import logging
import jwt
from datetime import datetime, timedelta
import mimetypes
from flask_cors import CORS
from urllib.parse import urlparse, unquote
import threading
import subprocess
import platform

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
# JWT settings
JWT_SECRET = os.environ.get('JWT_SECRET', os.urandom(24))
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY = 7200  # Token expiry time in seconds (2 hours)

# Terminal cleaner function
def clear_terminal():
    """Clear the terminal/console screen"""
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')
    print("="*50)
    print(f"Terminal cleared at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*50)

# Start terminal cleaner and ping service background thread
def start_terminal_cleaner_and_ping_service():
    """Start a background thread to clear the terminal periodically and keep app alive on Render"""
    def cleaner_and_ping_thread():
        # Get the app URL from environment or use localhost for development
        app_url = os.environ.get('RENDER_EXTERNAL_URL') or 'http://localhost:8080'
        ping_endpoint = f"{app_url}/ping"
        
        while True:
            try:
                # Clear terminal
                clear_terminal()
                
                # Send ping to keep app alive on Render
                if 'RENDER' in os.environ:
                    try:
                        print(f"Pinging application at {ping_endpoint}")
                        response = requests.get(ping_endpoint, timeout=10)
                        print(f"Ping response: HTTP {response.status_code}")
                    except Exception as e:
                        print(f"Ping error: {str(e)}")
                
                # Sleep for 5 minutes
                time.sleep(300)  # 300 seconds = 5 minutes
            except Exception as e:
                print(f"Cleaner/ping thread error: {str(e)}")
                # Still sleep even if there was an error
                time.sleep(300)
    
    # Start the cleaner thread
    cleaner = threading.Thread(target=cleaner_and_ping_thread, daemon=True)
    cleaner.start()
    print(f"Terminal cleaner and ping service started. Will run every 5 minutes.")

# Start the terminal cleaner when the app is initialized
start_terminal_cleaner_and_ping_service()

# Register custom filter for b64encode
@app.template_filter('b64encode')
def b64encode_filter(s):
    """Filter to base64 encode a string in templates"""
    if isinstance(s, str):
        # Clean up the URL first (remove trailing backslashes and spaces)
        s = s.rstrip('\\').strip()
        # Use urlsafe_b64encode to handle special characters better
        return base64.urlsafe_b64encode(s.encode()).decode()
    return ""

def parse_data_file():
    chapters = {}
    current_chapter = None
    
    with open('data.txt', 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        parts = line.split(':', 1)
        if len(parts) != 2:
            continue
            
        title, url = parts
        
        # Extract chapter number and name
        chapter_match = re.search(r'CH\s*(\d+)', title)
        if chapter_match:
            chapter_num = chapter_match.group(1)
            chapter_name_match = re.search(r'CH\s*\d+\s*([^:]+)', title)
            chapter_name = chapter_name_match.group(1).strip() if chapter_name_match else f"Chapter {chapter_num}"
            
            chapter_key = f"Chapter {chapter_num}: {chapter_name}"
            if chapter_key not in chapters:
                chapters[chapter_key] = {
                    'lectures': [],
                    'pdfs': []
                }
            
            current_chapter = chapter_key
            
        if current_chapter:
            if url.endswith('.pdf'):
                chapters[current_chapter]['pdfs'].append({
                    'title': title,
                    'url': url
                })
            elif '.m3u8' in url or 'videos' in url:
                chapters[current_chapter]['lectures'].append({
                    'title': title,
                    'url': url,
                    'video_id': generate_video_id(url)
                })
    
    return chapters

def generate_video_id(url):
    # Create a unique identifier for each video
    return hashlib.md5(url.encode()).hexdigest()

def generate_jwt_token(video_id):
    """Generate a JWT token for video access"""
    # Set expiry time
    exp_time = datetime.utcnow() + timedelta(seconds=JWT_EXPIRY)
    
    # Create payload
    payload = {
        'video_id': video_id,
        'exp': exp_time,
        'iat': datetime.utcnow(),
        'user_agent': request.user_agent.string[:100] if request.user_agent else 'Unknown'
    }
    
    # Generate token
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    return token

def validate_jwt_token(token, video_id=None):
    """Validate the JWT token for video access"""
    try:
        # Decode and validate token
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        # Check if token is for the requested video (if provided)
        if video_id and payload.get('video_id') != video_id:
            return False
        
        # Check user agent to prevent token sharing
        if request.user_agent and payload.get('user_agent') != request.user_agent.string[:100]:
            app.logger.warning(f"User agent mismatch: {payload.get('user_agent')} vs {request.user_agent.string[:100]}")
            return False
            
        return True
    except jwt.ExpiredSignatureError:
        app.logger.warning("Token expired")
        return False
    except jwt.DecodeError:
        app.logger.warning("Token invalid")
        return False
    except Exception as e:
        app.logger.error(f"Token validation error: {str(e)}")
        return False

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.args.get('token')
        video_id = kwargs.get('video_id')
        
        # Validate token
        if not token or not validate_jwt_token(token, video_id):
            abort(403)  # Forbidden
        
        return f(*args, **kwargs)
    
    return decorated_function

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/batches')
def batches():
    return render_template('batches.html')

@app.route('/batch_content')
def batch_content():
    try:
        # Parse the data.txt file to organize content by chapters
        chapters = {}
        current_chapter = None
        
        with open('data.txt', 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Split content by the section marker
            sections = content.split('\\n')
            
            for section in sections:
                if not section.strip():
                    continue
                
                # Parse each line in the section
                lines = section.strip().split('\n')
                if not lines:
                    continue
                
                # Extract chapter name from the first non-empty line or from content
                chapter_match = None
                for line in lines:
                    if "CH" in line and ":" in line:
                        chapter_parts = line.split(':')[0].strip()
                        if "CH" in chapter_parts:
                            # Extract chapter number
                            ch_parts = chapter_parts.split("CH")
                            if len(ch_parts) > 1:
                                ch_num = ch_parts[1].strip().split(" ")[0].strip()
                                try:
                                    ch_num = int(ch_num)
                                    chapter_match = f"Chapter {ch_num}"
                                    break
                                except ValueError:
                                    pass
                
                if not chapter_match:
                    if "CH 1" in section or "Ch 1" in section or "Ch - 1" in section:
                        chapter_match = "Chapter 1"
                    elif "CH 2" in section or "Ch 2" in section or "Ch - 2" in section:
                        chapter_match = "Chapter 2"
                    elif "CH 3" in section or "Ch 3" in section or "Ch - 3" in section:
                        chapter_match = "Chapter 3"
                    elif "CH 4" in section or "Ch 4" in section or "Ch - 4" in section:
                        chapter_match = "Chapter 4"
                    elif "CH 5" in section or "Ch 5" in section or "Ch - 5" in section:
                        chapter_match = "Chapter 5"
                    elif "CH 6" in section or "Ch 6" in section or "Ch - 6" in section:
                        chapter_match = "Chapter 6"
                    elif "CH 7" in section or "Ch 7" in section or "Ch - 7" in section:
                        chapter_match = "Chapter 7"
                    elif "CH 8" in section or "Ch 8" in section or "Ch - 8" in section:
                        chapter_match = "Chapter 8"
                    elif "CH 9" in section or "Ch 9" in section or "Ch - 9" in section:
                        chapter_match = "Chapter 9"
                    elif "G.O.C." in section:
                        chapter_match = "General Organic Chemistry"
                    else:
                        if current_chapter:
                            chapter_match = current_chapter
                        else:
                            chapter_match = "Course Materials"
                
                current_chapter = chapter_match
                
                # Create chapter if it doesn't exist
                if chapter_match not in chapters:
                    chapters[chapter_match] = {
                        'lectures': [],
                        'pdfs': []
                    }
                
                # Process each line to extract lectures and PDFs
                for line in lines:
                    if not line.strip():
                        continue
                    
                    if ':' in line:
                        parts = line.split(':', 1)
                        title = parts[0].strip()
                        url = parts[1].strip()
                        
                        # Clean up URL - remove trailing backslashes and spaces
                        url = url.rstrip('\\').strip()
                        
                        # Determine if it's a lecture (video) or PDF
                        if '.pdf' in url.lower():
                            chapters[chapter_match]['pdfs'].append({
                                'title': title,
                                'url': url
                            })
                        elif 'L0' in title or 'L1' in title or 'video' in url.lower() or '.m3u8' in url.lower() or 'encrypted.mp4' in url.lower():
                            # Extract a unique video ID from the URL
                            video_id = url.split('/')[-1].split('.')[0]
                            if '-' in video_id:
                                video_id = video_id.split('-')[-1]
                            
                            chapters[chapter_match]['lectures'].append({
                                'title': title,
                                'video_id': video_id,
                                'url': url
                            })
        
        # Sort chapters by chapter number
        sorted_chapters = {}
        chapter_order = []
        
        # Add numbered chapters first in order
        for i in range(1, 10):
            chapter_name = f"Chapter {i}"
            if chapter_name in chapters:
                chapter_order.append(chapter_name)
        
        # Add any remaining chapters
        for chapter_name in chapters:
            if chapter_name not in chapter_order:
                chapter_order.append(chapter_name)
        
        # Create the sorted dictionary
        for chapter_name in chapter_order:
            sorted_chapters[chapter_name] = chapters[chapter_name]
        
        # Render the template with the organized data
        return render_template('batch_content.html', chapters=sorted_chapters)
    
    except Exception as e:
        app.logger.error(f"Error in batch_content: {e}")
        # Pass an error warning to the template
        return render_template('batch_content.html', 
                              warning_message=f"Error loading course content: {str(e)}",
                              chapters={})

@app.route('/api/chapters')
def get_chapters():
    chapters = parse_data_file()
    return jsonify(chapters)

@app.route('/player/<video_id>')
def player(video_id):
    try:
        app.logger.info(f"Looking for video with ID: {video_id}")
        # Parse data.txt to extract lectures
        with open('data.txt', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Dictionary to store lecture info
        lectures_dict = {}
        
        # Process each line in the file
        for line in content.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('\\n') or '\\n' in line:
                continue
                
            # Check if line contains a URL
            if 'http' in line and ':' in line:
                # Split by colon (but only the first occurrence to handle URLs with colons)
                parts = line.split(':', 1)
                if len(parts) == 2:
                    title = parts[0].strip()
                    url = parts[1].strip()
                    
                    # Check for video IDs in the URL
                    if video_id in url:
                        app.logger.info(f"Found video: {title}, URL: {url}")
                        # Generate token for this video
                        token = generate_jwt_token(video_id)
                        return render_template('player.html', 
                                              video_id=video_id, 
                                              lecture_name=title, 
                                              token=token)
        
        # Also check for the new format
        for line in content.strip().split('\n'):
            line = line.strip()
            if line.startswith('+'):
                # Format: + Title | Info | URL
                parts = line[1:].strip().split(' | ')
                if len(parts) >= 3:
                    title = parts[0].strip()
                    url = parts[2].strip()
                    if video_id in url:
                        app.logger.info(f"Found video in new format: {title}, URL: {url}")
                        token = generate_jwt_token(video_id)
                        return render_template('player.html', 
                                              video_id=video_id, 
                                              lecture_name=title, 
                                              token=token)
                        
        # If we reach here, try matching directly against the master-ID.number pattern
        pattern = f"master-{video_id}"
        for line in content.strip().split('\n'):
            line = line.strip()
            if pattern in line and ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    title = parts[0].strip()
                    url = parts[1].strip()
                    app.logger.info(f"Found video by master ID: {title}, URL: {url}")
                    token = generate_jwt_token(video_id)
                    return render_template('player.html', 
                                          video_id=video_id, 
                                          lecture_name=title, 
                                          token=token)
        
        # If we reach here, the video was not found
        app.logger.error(f"Video not found for ID: {video_id}")
        warning_message = "Lecture not found. Please select a valid lecture."
        return render_template('player.html', 
                              warning_message=warning_message,
                              video_id="", lecture_name="", token="")
    
    except Exception as e:
        app.logger.error(f"Error in player route: {str(e)}")
        warning_message = f"Error loading video: {str(e)}"
        return render_template('player.html', 
                              warning_message=warning_message,
                              video_id="", lecture_name="", token="")

@app.route('/api/refresh-token/<video_id>')
def refresh_token(video_id):
    """Refresh the video access token"""
    chapters = parse_data_file()
    
    # Verify video_id exists
    video_exists = False
    for chapter in chapters.values():
        for lecture in chapter['lectures']:
            if lecture.get('video_id') == video_id:
                video_exists = True
                break
        if video_exists:
            break
    
    if not video_exists:
        return jsonify({"error": "Video not found"}), 404
    
    # Generate a new token
    token = generate_jwt_token(video_id)
    
    return jsonify({"token": token})

@app.route('/proxy/video/<video_id>')
@token_required
def proxy_video(video_id):
    quality = request.args.get('quality', '720p')
    token = request.args.get('token')
    chapters = parse_data_file()
    
    # Debug
    app.logger.info(f"Video request: {video_id}, quality: {quality}")
    
    # Find the lecture URL by video_id
    lecture_url = None
    for chapter in chapters.values():
        for lecture in chapter['lectures']:
            if lecture.get('video_id') == video_id:
                lecture_url = lecture['url']
                break
        if lecture_url:
            break
    
    if not lecture_url:
        app.logger.error(f"Video not found: {video_id}")
        return "Video not found", 404
    
    # Replace quality parameter if needed
    if quality != 'auto' and '720p' in lecture_url:
        lecture_url = lecture_url.replace('720p', quality)
    
    app.logger.info(f"Proxying URL: {lecture_url}")
    
    # Proxy the content
    try:
        # Get the content
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Referer': 'https://gyanshala.com/'
        }
        
        req = requests.get(lecture_url, headers=headers)
        app.logger.info(f"Response status: {req.status_code}")
        
        if req.status_code != 200:
            app.logger.error(f"Error fetching content: {req.status_code}")
            return f"Error fetching content: {req.status_code}", 500
        
        # For m3u8 files, we need to rewrite the URLs
        if lecture_url.endswith('.m3u8'):
            app.logger.info("Processing m3u8 file")
            content = req.text
            
            # Create the response with text content
            response = Response(content)
            response.headers['Content-Type'] = 'application/vnd.apple.mpegurl'
        else:
            # For other content, just pass through
            response = Response(req.content)
            response.content_type = req.headers.get('Content-Type', 'application/octet-stream')
        
        # Set CORS headers
        response.headers['Access-Control-Allow-Origin'] = '*'
        
        return response
        
    except Exception as e:
        app.logger.error(f"Error proxying video: {str(e)}")
        return f"Error playing video: {str(e)}", 500

@app.route('/vs/<path:segment_path>')
@token_required
def proxy_video_segment(segment_path):
    token = request.args.get('token')
    
    try:
        # Decode the URL-safe base64 encoded path
        decoded_bytes = base64.urlsafe_b64decode(segment_path.encode())
        actual_url = decoded_bytes.decode()
        
        app.logger.info(f"Decoded segment URL: {actual_url}")
        
        # Proxy the content
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Referer': 'https://gyanshala.com/'
        }
        
        try:
            req = requests.get(actual_url, headers=headers)
            app.logger.info(f"Segment response status: {req.status_code}")
            
            if req.status_code != 200:
                app.logger.error(f"Error fetching segment: {req.status_code}")
                return f"Error fetching segment: {req.status_code}", 500
            
            # Create a response with the content
            response = Response(req.content)
            
            # Set content type based on URL
            if actual_url.endswith('.ts'):
                response.headers['Content-Type'] = 'video/mp2t'
            elif actual_url.endswith('.m3u8'):
                response.headers['Content-Type'] = 'application/vnd.apple.mpegurl'
            else:
                response.content_type = req.headers.get('Content-Type', 'application/octet-stream')
            
            # Set CORS headers
            response.headers['Access-Control-Allow-Origin'] = '*'
            
            return response
            
        except requests.RequestException as e:
            app.logger.error(f"Request error for segment {actual_url}: {str(e)}")
            return f"Error connecting to video segment: {str(e)}", 500
            
    except Exception as e:
        app.logger.error(f"Error processing segment path {segment_path}: {str(e)}")
        return f"Error processing video segment: {str(e)}", 500

@app.route('/proxy_pdf/<token>')
def proxy_pdf(token):
    try:
        # Decode the token to get PDF information
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            pdf_url = payload['url']
            pdf_title = payload.get('title', 'Document')
            can_download = payload.get('dl', False)
        except Exception as e:
            app.logger.error(f"Invalid PDF token: {e}")
            return f"Invalid token: {str(e)}", 401
        
        app.logger.info(f"Proxying PDF from: {pdf_url}")
        
        # Download the PDF from the source
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Referer': 'https://gyanshala.com/'
            }
            response = requests.get(pdf_url, stream=True, headers=headers, timeout=10)
            
            if response.status_code != 200:
                app.logger.error(f"Failed to fetch PDF from {pdf_url}: {response.status_code}")
                return f"Error fetching PDF: Status code {response.status_code}", response.status_code
        except requests.exceptions.RequestException as e:
            app.logger.error(f"Request error fetching PDF from {pdf_url}: {e}")
            return f"Error connecting to PDF source: {str(e)}", 500
        
        # Create a response with the PDF content
        proxy_response = make_response(response.content)
        proxy_response.headers['Content-Type'] = 'application/pdf'
        
        # Only allow download if permission is set
        if can_download:
            # Create safe filename with the title
            safe_filename = re.sub(r'[^\w\s-]', '', pdf_title).strip().replace(' ', '_')
            safe_filename = f"{safe_filename}_From_MrGadhvii.pdf"
            
            # Set Content-Disposition header to force download with filename
            proxy_response.headers['Content-Disposition'] = f'attachment; filename="{safe_filename}"'
        else:
            # Set Content-Disposition to inline to prevent easy downloading
            proxy_response.headers['Content-Disposition'] = 'inline'
        
        # Cache control and security headers
        proxy_response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        proxy_response.headers['Pragma'] = 'no-cache'
        proxy_response.headers['Expires'] = '0'
        
        return proxy_response
    
    except Exception as e:
        app.logger.error(f"Error in proxy_pdf: {e}")
        return f"Error: {str(e)}", 500

# Load PDF configuration
def load_pdf_config():
    try:
        with open('pdf_config.json', 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Error loading PDF config: {e}")
        return {"default": {"dl": False}, "pdfs": []}

# Get PDF download permission
def get_pdf_permission(pdf_title):
    config = load_pdf_config()
    default_permission = config.get("default", {}).get("dl", False)
    
    # Search for the specific PDF by title
    for pdf in config.get("pdfs", []):
        if pdf.get("title") == pdf_title:
            return pdf.get("dl", default_permission)
    
    return default_permission

@app.route('/api/get_pdf_url/<pdf_url_base64>')
def get_pdf_url(pdf_url_base64):
    try:
        # Base64 decode the URL
        pdf_url = base64.b64decode(pdf_url_base64).decode('utf-8')
        
        # Clean up URL by removing trailing backslashes and extra spaces
        pdf_url = pdf_url.rstrip('\\').strip()
        
        app.logger.info(f"Processing PDF URL: {pdf_url}")
        
        pdf_title = request.args.get('title', 'Document')
        
        # Get download permission
        can_download = get_pdf_permission(pdf_title)
        
        # Generate signed token for URL
        token_payload = {
            'url': pdf_url,
            'title': pdf_title,
            'exp': datetime.utcnow() + timedelta(hours=2),
            'dl': can_download
        }
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        # Create safe filename with the title
        safe_filename = re.sub(r'[^\w\s-]', '', pdf_title).strip().replace(' ', '_')
        safe_filename = f"{safe_filename}_From_MrGadhvii.pdf"
        
        # Return signed URL with token
        signed_url = f"/proxy_pdf/{token}"
        return jsonify({
            'url': signed_url, 
            'filename': safe_filename,
            'can_download': can_download
        })
    except Exception as e:
        app.logger.error(f"Error generating PDF URL: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/pdf_viewer/<token>')
def pdf_viewer(token):
    try:
        # Decode the token to get PDF information
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            pdf_url = payload['url']
            pdf_title = payload.get('title', 'Document')
            can_download = payload.get('dl', False)
        except Exception as e:
            # Return with a warning message for invalid token
            return render_template('pdf_viewer.html', 
                                 warning_message=f"Invalid token: {str(e)}",
                                 pdf_url="", pdf_title="Document", token="", can_download=False)
        
        # Render PDF viewer with the token for authenticated access
        return render_template('pdf_viewer.html', 
                              pdf_url=f"/proxy_pdf/{token}", 
                              pdf_title=pdf_title,
                              token=token,
                              can_download=can_download)
    except Exception as e:
        logging.error(f"Error in PDF viewer: {e}")
        # Return with a warning message
        return render_template('pdf_viewer.html', 
                             warning_message=f"Error loading PDF: {str(e)}",
                             pdf_url="", pdf_title="Document", token="", can_download=False)

@app.route('/api/get_video_url/<video_id>')
def get_video_url(video_id):
    """Generate a direct video URL with token validation"""
    quality = request.args.get('quality', 'auto')
    token = request.args.get('token', '')
    
    try:
        # Verify token
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            if payload.get('video_id') != video_id:
                return jsonify({"error": "Invalid token"}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 403
        
        app.logger.info(f"Getting video URL for ID: {video_id}")
        
        # Find the lecture URL by video_id
        lecture_url = None
        
        with open('data.txt', 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Regular format (title:url)
            for line in content.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                    
                if ':' in line and 'http' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        title = parts[0].strip()
                        url = parts[1].strip()
                        
                        # Check if this URL contains the video_id
                        if video_id in url:
                            lecture_url = url
                            app.logger.info(f"Found video: {title}, URL: {url}")
                            break
            
            # If not found, check for master-ID pattern
            if not lecture_url:
                pattern = f"master-{video_id}"
                for line in content.strip().split('\n'):
                    line = line.strip()
                    if pattern in line and ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            title = parts[0].strip()
                            url = parts[1].strip()
                            lecture_url = url
                            app.logger.info(f"Found video by master ID: {title}, URL: {url}")
                            break
        
        if not lecture_url:
            app.logger.error(f"Video URL not found for ID: {video_id}")
            return jsonify({"error": "Video not found"}), 404
        
        # Add an expiry time for security
        expires = int(time.time()) + 3600  # 1 hour expiry
        
        # Return the direct URL with token
        return jsonify({
            "url": lecture_url,
            "expires": expires,
            "token": token
        })
        
    except Exception as e:
        app.logger.error(f"Error getting video URL: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/get_signed_url')
@token_required
def get_signed_url():
    """Generate a signed URL for a resource"""
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    # Get the resource through our server
    proxy_url = url_for('proxy_resource', _external=True) + "?url=" + base64.urlsafe_b64encode(url.encode()).decode() + "&token=" + request.args.get('token')
    
    # Return the proxy URL
    return jsonify({
        "signed_url": proxy_url
    })

@app.route('/proxy/resource')
@token_required
def proxy_resource():
    """Generic proxy for any resource"""
    url = request.args.get('url')
    if not url:
        return "No URL provided", 400
    
    try:
        # Decode the URL
        decoded_url = base64.urlsafe_b64decode(url.encode()).decode()
        app.logger.info(f"Proxying resource: {decoded_url}")
        
        # Headers for the request
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Referer': 'https://gyanshala.com/',
            'Origin': 'https://gyanshala.com'
        }
        
        # Make request to the original URL
        req = requests.get(decoded_url, headers=headers)
        
        if req.status_code != 200:
            app.logger.error(f"Error fetching resource: {req.status_code}")
            return f"Error fetching resource: {req.status_code}", 500
        
        # Check if it's a manifest file
        is_manifest = decoded_url.endswith('.m3u8')
        
        # Special handling for m3u8 files to rewrite URLs
        if is_manifest:
            content = req.text
            app.logger.info(f"Processing m3u8 manifest: {decoded_url}")
            app.logger.debug(f"Original manifest content: {content}")
            
            # Parse URL to get base components
            parsed_url = urllib.parse.urlparse(decoded_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{os.path.dirname(parsed_url.path)}"
            if not base_url.endswith('/'):
                base_url += '/'
            
            app.logger.info(f"Base URL for manifest: {base_url}")
            
            # Process each line
            processed_lines = []
            for line in content.splitlines():
                line = line.strip()
                
                # Pass through comments and directives
                if line.startswith('#') or not line:
                    processed_lines.append(line)
                    continue
                
                # Handle segment and playlist URLs
                if line.endswith('.ts') or line.endswith('.m3u8') or '.ts?' in line or '.m3u8?' in line:
                    try:
                        # Determine if it's an absolute or relative URL
                        if line.startswith('http'):
                            full_url = line
                        else:
                            # Handle relative paths correctly
                            full_url = urllib.parse.urljoin(base_url, line)
                        
                        app.logger.debug(f"Processing segment URL: {line} -> {full_url}")
                        
                        # Create a proxy URL for this resource
                        encoded_url = base64.urlsafe_b64encode(full_url.encode()).decode()
                        proxy_url = url_for('proxy_resource', url=encoded_url, token=request.args.get('token'), _external=True)
                        processed_lines.append(proxy_url)
                    except Exception as e:
                        app.logger.error(f"Error processing URL {line}: {str(e)}")
                        # Keep original line as fallback
                        processed_lines.append(line)
                else:
                    # Pass through other content
                    processed_lines.append(line)
            
            # Join the processed lines into a single string
            processed_content = '\n'.join(processed_lines)
            app.logger.debug(f"Processed manifest content: {processed_content}")
            
            # Create response with the processed content
            response = Response(processed_content)
            response.headers['Content-Type'] = 'application/vnd.apple.mpegurl'
        else:
            # For other types of files, just pass through the content
            response = Response(req.content)
            
            # Copy important headers
            for header in ['Content-Type', 'Content-Length', 'Cache-Control']:
                if header in req.headers:
                    response.headers[header] = req.headers[header]
            
            # Set content type if it wasn't in the headers
            if 'Content-Type' not in response.headers:
                if decoded_url.endswith('.ts'):
                    response.headers['Content-Type'] = 'video/mp2t'
                else:
                    response.headers['Content-Type'] = 'application/octet-stream'
        
        # Set CORS headers
        response.headers['Access-Control-Allow-Origin'] = '*'
        
        return response
    
    except Exception as e:
        app.logger.error(f"Error proxying resource: {str(e)}", exc_info=True)
        return f"Error accessing resource: {str(e)}", 500

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "Access denied. Invalid or expired token."}), 403

# Add new API endpoint for changing video quality
@app.route('/api/change_quality/<video_id>', methods=['GET'])
def change_quality(video_id):
    """API endpoint to change video quality"""
    quality = request.args.get('quality', 'auto')
    token = request.args.get('token', '')
    
    # Validate token
    if not token:
        return jsonify({"error": "Invalid token", "status": "error"}), 400
    
    # Log the quality change request
    print(f"Quality change requested: video_id={video_id}, quality={quality}")
    
    try:
        # Find the video by ID
        video_data = None
        lecture_url = None
        
        # Read data.txt to find the video URL
        with open('data.txt', 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Regular format (title:url)
            for line in content.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                    
                if ':' in line and 'http' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        title = parts[0].strip()
                        url = parts[1].strip()
                        
                        # Check if this URL contains the video_id
                        if video_id in url:
                            lecture_url = url
                            print(f"Found video: {title}, URL: {url}")
                            break
            
            # If not found, check for master-ID pattern
            if not lecture_url:
                pattern = f"master-{video_id}"
                for line in content.strip().split('\n'):
                    line = line.strip()
                    if pattern in line and ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            title = parts[0].strip()
                            url = parts[1].strip()
                            lecture_url = url
                            print(f"Found video by master ID: {title}, URL: {url}")
                            break
        
        if not lecture_url:
            return jsonify({"error": f"Video with ID {video_id} not found", "status": "error"}), 404
        
        # Clean up URL - remove trailing backslashes and spaces
        base_url = lecture_url.rstrip('\\').strip()
        if not base_url:
            return jsonify({"error": "Video URL not available", "status": "error"}), 404
        
        # Construct URL with quality parameter
        if quality == 'auto':
            # For auto quality, use the original URL
            new_url = base_url
        else:
            # Parse the URL to extract components
            if '/hls/' in base_url:
                # Pattern: .../hls/720p/...
                parts = base_url.split('/hls/')
                if len(parts) >= 2:
                    sub_parts = parts[1].split('/')
                    if len(sub_parts) >= 2 and re.match(r'^\d+p$', sub_parts[0]):
                        # Replace the quality part
                        sub_parts[0] = quality
                        parts[1] = '/'.join(sub_parts)
                        new_url = parts[0] + '/hls/' + parts[1]
                    else:
                        # Can't determine the quality pattern, use the original
                        new_url = base_url
                else:
                    new_url = base_url
            else:
                # Try general pattern: .../720p/...
                new_url = re.sub(r'/\d+p/', f'/{quality}/', base_url)
        
        print(f"Quality changed: {quality}, New URL: {new_url}")
        
        return jsonify({
            "url": new_url,
            "quality": quality,
            "status": "success"
        })
    
    except Exception as e:
        print(f"Error changing quality: {str(e)}")
        return jsonify({"error": f"Failed to change quality: {str(e)}", "status": "error"}), 500

# Add ping endpoint to keep the app alive
@app.route('/ping')
def ping():
    """Simple endpoint for the ping service to hit"""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return jsonify({
        'status': 'alive',
        'time': current_time,
        'environment': os.environ.get('RENDER_SERVICE_NAME', 'development')
    })

if __name__ == '__main__':
    try:
        # Clear terminal at startup
        clear_terminal()
        
        # Start the terminal cleaner
        start_terminal_cleaner_and_ping_service()
        
        # Start the Flask application
        app.run(host='0.0.0.0', port=8080, debug=True)
    except Exception as e:
        print(f"Error starting application: {e}")
