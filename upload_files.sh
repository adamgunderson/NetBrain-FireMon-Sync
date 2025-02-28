#!/bin/bash
# upload_files.sh
#
# SFTP Upload Script for NetBrain-FireMon Sync Logs and Reports
# Uses native /usr/bin/sftp command for file uploads

# Setup logging
LOG_FILE="sftp_upload.log"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
UPLOADED_FILES=0
FAILED_FILES=0
SFTP_BATCH_FILE=$(mktemp)

# Load environment variables from .env if file exists
if [ -f .env ]; then
    echo "Loading environment variables from .env file"
    export $(grep -v '^#' .env | xargs)
fi

# Clean up the batch file when the script exits
cleanup() {
    [ -f "$SFTP_BATCH_FILE" ] && rm -f "$SFTP_BATCH_FILE"
}
trap cleanup EXIT

# Log function to write to both console and log file
log() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} - $1"
    echo -e "${timestamp} - $1" >> "$LOG_FILE"
}

# Error handler
handle_error() {
    log "ERROR: $1"
    exit 1
}

# Check required environment variables
check_env_vars() {
    if [ -z "$SFTP_HOST" ]; then
        handle_error "SFTP_HOST environment variable is not set"
    fi
    
    if [ -z "$SFTP_USER" ]; then
        handle_error "SFTP_USER environment variable is not set"
    fi
    
    if [ -z "$SFTP_PASS" ]; then
        log "WARNING: SFTP_PASS not set. Will rely on SSH keys or prompt for password"
    fi
    
    SFTP_PORT=${SFTP_PORT:-22}
    log "Using SFTP settings: Host=$SFTP_HOST, User=$SFTP_USER, Port=$SFTP_PORT"
}

# Create all necessary remote directories
create_remote_dirs() {
    local remote_path="$1"
    
    # Split the path and create each directory level
    local path_parts=$(echo "$remote_path" | tr '/' ' ')
    local current_path=""
    
    # Add mkdir commands to batch file
    echo "# Creating directory structure for $remote_path" >> "$SFTP_BATCH_FILE"
    for part in $path_parts; do
        if [ -n "$part" ]; then
            if [ -z "$current_path" ]; then
                current_path="$part"
            else
                current_path="$current_path/$part"
            fi
            echo "mkdir -p $current_path" >> "$SFTP_BATCH_FILE"
        fi
    done
    
    log "Added commands to create directory: $remote_path"
}

# Add a file upload command to the batch file
add_upload_command() {
    local local_file="$1"
    local remote_path="$2"
    
    # Skip if file doesn't exist
    if [ ! -f "$local_file" ]; then
        log "WARNING: Local file not found: $local_file"
        ((FAILED_FILES++))
        return 1
    fi
    
    # Remove leading slash and normalize path
    remote_path="${remote_path#/}"
    
    log "Adding upload: $local_file -> $remote_path"
    
    # Get the directory part of the remote path
    local remote_dir=$(dirname "$remote_path")
    
    # Make sure the remote directory exists
    create_remote_dirs "$remote_dir"
    
    # Add the put command to upload the file
    echo "put \"$local_file\" \"$remote_path\"" >> "$SFTP_BATCH_FILE"
    
    ((UPLOADED_FILES++))
    return 0
}

# Add directory upload commands to the batch file
add_directory_upload() {
    local local_dir="$1"
    local remote_dir="$2"
    
    if [ ! -d "$local_dir" ]; then
        log "Local directory not found: $local_dir"
        return 1
    fi
    
    log "Adding directory upload: $local_dir -> $remote_dir"
    
    # Create the base remote directory
    create_remote_dirs "$remote_dir"
    
    # Use find to get all files in the directory and subdirectories
    find "$local_dir" -type f | while read local_file; do
        # Calculate the relative path
        local rel_path="${local_file#$local_dir/}"
        local remote_path="${remote_dir}/${rel_path}"
        
        # Upload the file 
        add_upload_command "$local_file" "$remote_path"
    done
}

# List directory contents
list_directory_contents() {
    local dir="$1"
    if [ -d "$dir" ]; then
        log "Directory exists: $dir"
        log "Directory contents:"
        find "$dir" -type f | while read file; do
            local size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file")
            log "  - $file ($size bytes)"
        done
    else
        log "Directory does not exist: $dir"
    fi
}

# Execute the SFTP batch file
execute_sftp_batch() {
    log "Executing SFTP batch file with $(grep -c "^put" "$SFTP_BATCH_FILE") file transfers"
    
    # Add final exit command
    echo "bye" >> "$SFTP_BATCH_FILE"
    
    # Log the commands (without sensitive info)
    log "SFTP commands to execute:"
    grep -v "^#" "$SFTP_BATCH_FILE" | head -n 20 >> "$LOG_FILE"
    if [ $(grep -v "^#" "$SFTP_BATCH_FILE" | wc -l) -gt 20 ]; then
        echo "... and more commands" >> "$LOG_FILE"
    fi
    
    # Connect using sshpass if password is provided, otherwise rely on SSH keys
    if [ -n "$SFTP_PASS" ]; then
        if command -v sshpass >/dev/null 2>&1; then
            log "Using sshpass for authentication"
            sshpass -p "$SFTP_PASS" sftp -b "$SFTP_BATCH_FILE" -P "$SFTP_PORT" "$SFTP_USER@$SFTP_HOST" 2>&1 | tee -a "$LOG_FILE"
            SFTP_EXIT_CODE=${PIPESTATUS[0]}
        else
            log "WARNING: sshpass not installed. Cannot use SFTP_PASS variable."
            log "Please install sshpass or use SSH keys for authentication."
            sftp -b "$SFTP_BATCH_FILE" -P "$SFTP_PORT" "$SFTP_USER@$SFTP_HOST" 2>&1 | tee -a "$LOG_FILE"
            SFTP_EXIT_CODE=${PIPESTATUS[0]}
        fi
    else
        sftp -b "$SFTP_BATCH_FILE" -P "$SFTP_PORT" "$SFTP_USER@$SFTP_HOST" 2>&1 | tee -a "$LOG_FILE"
        SFTP_EXIT_CODE=${PIPESTATUS[0]}
    fi
    
    if [ $SFTP_EXIT_CODE -ne 0 ]; then
        log "ERROR: SFTP command failed with exit code $SFTP_EXIT_CODE"
        FAILED_FILES=$UPLOADED_FILES  # Mark all files as failed
        UPLOADED_FILES=0
        return 1
    fi
    
    log "SFTP transfer completed successfully"
    return 0
}

# Main function
main() {
    log "Starting SFTP upload script"
    
    # Check environment variables
    check_env_vars
    
    # Create the remote base directory with timestamp
    REMOTE_BASE="$TIMESTAMP"
    log "Remote base directory: $REMOTE_BASE"
    
    # Initialize batch file with comments
    echo "# SFTP Batch file created $(date)" > "$SFTP_BATCH_FILE"
    echo "# For uploading NetBrain-FireMon files" >> "$SFTP_BATCH_FILE"
    
    # Check and add logs directory to upload
    LOGS_DIR="logs"
    list_directory_contents "$LOGS_DIR"
    if [ -d "$LOGS_DIR" ]; then
        add_directory_upload "$LOGS_DIR" "${REMOTE_BASE}/logs"
    else
        log "WARNING: Logs directory not found"
    fi
    
    # Check and add reports directory to upload
    REPORTS_DIR="reports"
    list_directory_contents "$REPORTS_DIR"
    if [ -d "$REPORTS_DIR" ]; then
        add_directory_upload "$REPORTS_DIR" "${REMOTE_BASE}/reports"
    else
        log "WARNING: Reports directory not found"
    fi
    
    # Execute the SFTP batch
    execute_sftp_batch
    SFTP_RESULT=$?
    
    # Print summary
    log "Upload completed with status: $SFTP_RESULT"
    log "Files successfully uploaded: $UPLOADED_FILES"
    log "Failed uploads: $FAILED_FILES"
    
    if [ $FAILED_FILES -gt 0 ]; then
        log "WARNING: Some files failed to upload"
        exit 1
    fi
    
    if [ $UPLOADED_FILES -eq 0 ]; then
        log "WARNING: No files were uploaded"
        exit 1
    fi
    
    log "All files uploaded successfully"
    exit 0
}

# Run the main function
main