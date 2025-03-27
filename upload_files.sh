#!/bin/bash
# upload_files.sh - Upload logs and reports to Nextcloud/Owncloud with improved reliability
# 
# Features:
# - Multiple retry attempts for failed uploads
# - Support for Nextcloud/Owncloud (SupportFiles) shared folder URLs
# - Automatic file discovery in logs and reports directories
# - Enhanced logging and debugging
# - Progress tracking for large files
# - Timestamp prefixing for uploaded files

# Configuration
VERSION="1.0.0"
MAX_RETRIES=3                  # Number of retry attempts for failed uploads
CONNECT_TIMEOUT=60             # Connection timeout in seconds
TRANSFER_TIMEOUT=1800          # Transfer timeout in seconds (30 minutes)
VERBOSE_MODE=true              # Enable detailed logging
PUBSUFFIX="public.php/webdav"  # Nextcloud/Owncloud WebDAV endpoint

# Set up logging
mkdir -p logs
LOG_FILE="logs/upload.log"
echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Starting SupportFiles uploader v${VERSION}" | tee -a "$LOG_FILE"

# Function for logging
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$timestamp - $level - $message" | tee -a "$LOG_FILE"
}

log "INFO" "Starting with configuration: MAX_RETRIES=$MAX_RETRIES, CONNECT_TIMEOUT=$CONNECT_TIMEOUT, TRANSFER_TIMEOUT=$TRANSFER_TIMEOUT"

# Parse command-line arguments
INSECURE=""
PASSWORD=""
UPLOAD_URL=""

print_usage() {
    echo "Usage: $0 [options] <upload-url>"
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -v, --verbose           Enable verbose output"
    echo "  -q, --quiet             Suppress output"
    echo "  -k, --insecure          Allow insecure SSL connections"
    echo "  -p, --password PASSWORD Use specified password for authentication"
    echo "  -d, --dirs DIRS         Specify directories to upload (comma-separated)"
    echo ""
    echo "Example: $0 -v https://supportfiles.firemon.com/s/abcdefg12345"
    echo "The upload URL should be a Nextcloud/Owncloud shared folder link"
}

# Process arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_usage
            exit 0
            ;;
        -v|--verbose)
            VERBOSE_MODE=true
            shift
            ;;
        -q|--quiet)
            VERBOSE_MODE=false
            shift
            ;;
        -k|--insecure)
            INSECURE="-k"
            log "INFO" "Insecure mode enabled - SSL certificate validation disabled"
            shift
            ;;
        -p|--password)
            PASSWORD="$2"
            log "INFO" "Using provided password for authentication"
            shift 2
            ;;
        -d|--dirs)
            CUSTOM_DIRS="$2"
            log "INFO" "Using custom directories: $CUSTOM_DIRS"
            shift 2
            ;;
        *)
            UPLOAD_URL="$1"
            shift
            ;;
    esac
done

# Load environment variables from .env
if [ -f .env ]; then
    log "INFO" "Loading variables from .env file"
    while IFS= read -r line; do
        # Skip comment lines and empty lines
        [[ $line =~ ^[[:space:]]*# ]] && continue
        [[ -z $line ]] && continue
        
        # Extract variable assignment
        var_def=$(echo "$line" | sed -E 's/#.*$//' | tr -d '[:space:]')
        
        # Skip if not a valid assignment
        [[ ! $var_def =~ ^[A-Za-z0-9_]+=.+ ]] && continue
        
        # Split into name and value
        var_name=$(echo "$var_def" | cut -d= -f1)
        var_value=$(echo "$var_def" | cut -d= -f2-)
        
        # Strip quotes from value
        var_value=$(echo "$var_value" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")
        
        # Export the variable with stripped quotes
        export "$var_name=$var_value"
    done < .env
fi

# Use NEXTCLOUD_URL from environment if UPLOAD_URL is not provided
if [ -z "$UPLOAD_URL" ]; then
    UPLOAD_URL="$NEXTCLOUD_URL"
    if [ -z "$UPLOAD_URL" ]; then
        log "ERROR" "No upload URL provided. Use $0 -h for usage information."
        exit 1
    fi
fi

# Use PASSWORD from environment if not provided as argument
if [ -z "$PASSWORD" ]; then
    PASSWORD="$NEXTCLOUD_PASSWORD"
fi

# Extract cloud URL and folder token
# Remove /s/token from the end of the URL to get the base URL
CLOUD_URL="${UPLOAD_URL%/s/*}"
# Extract token from the URL
FOLDER_TOKEN="${UPLOAD_URL##*/s/}"

if [ -z "$CLOUD_URL" ]; then
    log "ERROR" "Invalid URL format. Expected format: https://supportfiles.firemon.com/s/abcdefg12345"
    exit 1
fi

if [ -z "$FOLDER_TOKEN" ]; then
    log "ERROR" "Could not extract folder token from URL"
    exit 1
fi

log "INFO" "Cloud URL: $CLOUD_URL"
log "INFO" "Folder Token: $FOLDER_TOKEN"

# Check for curl
if ! command -v curl &>/dev/null; then
    log "ERROR" "curl is required but not installed. Please install curl and try again."
    exit 1
fi

# Verify connectivity to the cloud server
log "INFO" "Testing connectivity to $CLOUD_URL"
if ! curl $INSECURE -s -m 10 -o /dev/null -w "%{http_code}" "$CLOUD_URL" | grep -q "2[0-9][0-9]\|3[0-9][0-9]"; then
    log "WARNING" "Could not connect to $CLOUD_URL. Check the URL and try again."
    # Continue anyway as the URL might be correct but just not accessible via GET
fi

# Get timestamp for filename prefix
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
log "INFO" "Using timestamp: $TIMESTAMP"

# Function to upload a file
upload_file() {
    local source_file="$1"
    local dest_filename="$2"
    local attempt=1
    local success=false
    local response_file=$(mktemp)
    
    while [ $attempt -le $MAX_RETRIES ] && [ "$success" = "false" ]; do
        log "INFO" "Uploading $source_file to $dest_filename (Attempt $attempt of $MAX_RETRIES)"
        
        # Get file size for progress tracking
        local file_size=$(stat -c %s "$source_file" 2>/dev/null || wc -c < "$source_file" 2>/dev/null)
        
        # Create human-readable size
        local hr_size
        if [ $file_size -lt 1024 ]; then
            hr_size="${file_size} bytes"
        elif [ $file_size -lt 1048576 ]; then
            hr_size="$(echo "scale=2; $file_size/1024" | bc) KB"
        elif [ $file_size -lt 1073741824 ]; then
            hr_size="$(echo "scale=2; $file_size/1048576" | bc) MB"
        else
            hr_size="$(echo "scale=2; $file_size/1073741824" | bc) GB"
        fi
        
        log "INFO" "File size: $hr_size"
        
        # Set up the curl command with proper headers for Nextcloud
        local curl_opts="-T \"$source_file\" -u \"$FOLDER_TOKEN:$PASSWORD\" -H \"X-Requested-With: XMLHttpRequest\""
        
        if [ "$VERBOSE_MODE" = "true" ]; then
            curl_opts="$curl_opts -v"
        else
            curl_opts="$curl_opts -s"
        fi
        
        # Add timeouts and SSL options
        curl_opts="$curl_opts $INSECURE --connect-timeout $CONNECT_TIMEOUT --max-time $TRANSFER_TIMEOUT"
        
        # Upload file with progress indicator
        log "INFO" "Starting upload..."
        eval curl $curl_opts --progress-bar "$CLOUD_URL/$PUBSUFFIX/$dest_filename" > "$response_file" 2>&1
        
        local curl_status=$?
        
        if [ $curl_status -eq 0 ]; then
            # Check if response contains error message
            if grep -q "<s:exception>" "$response_file" || grep -q "<d:error" "$response_file"; then
                log "WARNING" "Server returned an error for $dest_filename"
                
                if [ "$VERBOSE_MODE" = "true" ]; then
                    log "DEBUG" "Server response: $(cat "$response_file")"
                fi
                
                # Check for authentication errors
                if grep -q "NotAuthenticated\|Cannot authenticate" "$response_file"; then
                    log "ERROR" "Authentication failed. Check folder token and password."
                    rm -f "$response_file"
                    return 1
                fi
                
                attempt=$((attempt + 1))
                if [ $attempt -le $MAX_RETRIES ]; then
                    log "INFO" "Retrying in 5 seconds..."
                    sleep 5
                fi
            else
                log "INFO" "Successfully uploaded $dest_filename"
                success=true
            fi
        else
            log "WARNING" "Failed to upload $dest_filename (curl exit code: $curl_status)"
            
            if [ "$VERBOSE_MODE" = "true" ] && [ -s "$response_file" ]; then
                log "DEBUG" "Curl output: $(cat "$response_file")"
            fi
            
            attempt=$((attempt + 1))
            if [ $attempt -le $MAX_RETRIES ]; then
                log "INFO" "Retrying in 5 seconds..."
                sleep 5
            fi
        fi
    done
    
    rm -f "$response_file"
    
    if [ "$success" = "true" ]; then
        return 0
    else
        return 1
    fi
}

# Process directories to upload files
dirs_to_process="logs,reports"
if [ -n "$CUSTOM_DIRS" ]; then
    dirs_to_process="$CUSTOM_DIRS"
fi

# Count and collect files
total_found=0
total_uploaded=0
total_failed=0
failed_files=""

IFS=',' read -ra DIRS <<< "$dirs_to_process"
for dir in "${DIRS[@]}"; do
    dir=$(echo "$dir" | xargs)  # Trim whitespace
    
    if [ -d "$dir" ]; then
        log "INFO" "Processing directory: $dir"
        
        # Get list of files
        files=$(find "$dir" -type f -name "*.log" -o -name "*.json" -o -name "*.html" -o -name "*.txt" 2>/dev/null)
        file_count=$(echo "$files" | grep -c .)
        
        if [ $file_count -eq 0 ]; then
            log "INFO" "No files found in $dir directory"
            continue
        fi
        
        total_found=$((total_found + file_count))
        log "INFO" "Found $file_count files in $dir directory"
        
        # Process each file
        while IFS= read -r file; do
            # Skip empty lines
            [ -z "$file" ] && continue
            
            # Skip the current upload log
            if [ "$file" = "$LOG_FILE" ]; then
                log "INFO" "Skipping current log file $file"
                continue
            fi
            
            # Create a unique name with timestamp and path info
            filename=$(basename "$file")
            dir_name=$(basename "$dir")
            unique_name="${TIMESTAMP}_${dir_name}_${filename}"
            
            log "INFO" "Processing $file -> $unique_name"
            
            if upload_file "$file" "$unique_name"; then
                total_uploaded=$((total_uploaded + 1))
            else
                log "ERROR" "Failed to upload $file after $MAX_RETRIES attempts"
                total_failed=$((total_failed + 1))
                failed_files="$failed_files\n$file"
            fi
        done <<< "$files"
    else
        log "WARNING" "Directory not found: $dir"
    fi
done

# Print summary
log "INFO" "Upload summary:"
log "INFO" "Found $total_found files (excluding current log file)"
log "INFO" "Successfully uploaded $total_uploaded files"
log "INFO" "Failed to upload $total_failed files"

if [ $total_failed -gt 0 ]; then
    log "WARNING" "Failed files:"
    echo -e "$failed_files" | tee -a "$LOG_FILE"
    exit 1
else
    log "INFO" "Upload completed successfully"
    exit 0
fi