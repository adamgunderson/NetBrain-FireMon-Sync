#!/bin/bash
# upload_files.sh - Upload logs and reports to SFTP server with improved reliability
# 
# Features:
# - Multiple retry attempts for failed uploads
# - Increased timeouts for slow connections
# - Support for both curl and sftp command methods
# - Improved password handling
# - Enhanced logging and debugging
# - Progress tracking for large files

# Configuration
MAX_RETRIES=3                  # Number of retry attempts for failed uploads
CONNECT_TIMEOUT=60             # Connection timeout in seconds (increased from 30)
TRANSFER_TIMEOUT=1800          # Transfer timeout in seconds (30 minutes, increased from 10)
VERBOSE_MODE=true              # Enable detailed logging
BATCH_MODE=true                # Enable batch processing of multiple files

# Set up logging
mkdir -p logs
LOG_FILE="logs/sftp_upload.log"
echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Starting root directory uploader (improved version)" | tee -a "$LOG_FILE"

# Function for logging
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$timestamp - $level - $message" | tee -a "$LOG_FILE"
}

log "INFO" "Starting with configuration: MAX_RETRIES=$MAX_RETRIES, CONNECT_TIMEOUT=$CONNECT_TIMEOUT, TRANSFER_TIMEOUT=$TRANSFER_TIMEOUT"

# Load environment variables from .env
if [ -f .env ]; then
    log "INFO" "Loading variables from .env file"
    # Only process lines that have actual variable assignments without comments
    while IFS= read -r line; do
        # Skip comment lines and empty lines
        [[ $line =~ ^[[:space:]]*# ]] && continue
        [[ -z $line ]] && continue
        
        # Extract variable assignment (stops at first # if there's a comment)
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

# Check required variables
if [ -z "$SFTP_HOST" ]; then
    log "ERROR" "Missing SFTP_HOST in .env file"
    exit 1
fi

if [ -z "$SFTP_USER" ]; then
    log "ERROR" "Missing SFTP_USER in .env file"
    exit 1
fi

if [ -z "$SFTP_PASS" ]; then
    log "ERROR" "Missing SFTP_PASS in .env file"
    exit 1
fi

# Set default port if not specified
SFTP_PORT=${SFTP_PORT:-22}

# Create timestamp for filename prefix
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
log "INFO" "Using timestamp: $TIMESTAMP"

# Log settings (without showing the password)
log "INFO" "Upload settings:"
log "INFO" "  Host: $SFTP_HOST"
log "INFO" "  User: $SFTP_USER"
log "INFO" "  Port: $SFTP_PORT"

# Check available tools
USE_CURL=false
USE_SFTP=false
USE_LFTP=false

if command -v curl &> /dev/null; then
    # Check if curl has SFTP support
    curl --version | grep -i sftp &> /dev/null
    if [ $? -eq 0 ]; then
        USE_CURL=true
        log "INFO" "Using curl for uploads (primary method)"
    fi
fi

if command -v lftp &> /dev/null; then
    USE_LFTP=true
    log "INFO" "lftp is available (will be used if curl fails)"
fi

if command -v sftp &> /dev/null; then
    USE_SFTP=true
    log "INFO" "sftp command is available (will be used as backup method)"
fi

if [ "$USE_CURL" = "false" ] && [ "$USE_LFTP" = "false" ] && [ "$USE_SFTP" = "false" ]; then
    log "ERROR" "No suitable upload tools available. Please install curl with SFTP support, lftp, or sftp"
    exit 1
fi

# Function to test connection to SFTP server
test_connection() {
    log "INFO" "Testing connection to SFTP server..."
    
    if [ "$USE_CURL" = "true" ]; then
        curl --insecure --connect-timeout 30 -v "sftp://$SFTP_USER:$SFTP_PASS@$SFTP_HOST:$SFTP_PORT/" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            log "INFO" "Connection test successful using curl"
            return 0
        else
            log "WARNING" "Connection test failed using curl, will try alternatives"
        fi
    fi

    if [ "$USE_LFTP" = "true" ]; then
        echo "ls" | lftp -u "$SFTP_USER,$SFTP_PASS" "sftp://$SFTP_HOST:$SFTP_PORT" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            log "INFO" "Connection test successful using lftp"
            return 0
        else
            log "WARNING" "Connection test failed using lftp, will try sftp"
        fi
    fi

    if [ "$USE_SFTP" = "true" ]; then
        echo "ls" | sshpass -p "$SFTP_PASS" sftp -P "$SFTP_PORT" -o StrictHostKeyChecking=no "$SFTP_USER@$SFTP_HOST" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            log "INFO" "Connection test successful using sftp"
            return 0
        else
            log "WARNING" "Connection test failed using sftp"
        fi
    fi
    
    log "ERROR" "All connection tests failed"
    return 1
}

# Function to upload a file using curl
upload_with_curl() {
    local local_file="$1"
    local remote_file="$2"
    local attempt=1
    local max_attempts=$MAX_RETRIES
    local success=false
    
    while [ $attempt -le $max_attempts ] && [ "$success" = "false" ]; do
        log "INFO" "Uploading $local_file to $remote_file (Attempt $attempt of $max_attempts)"
        
        if [ "$VERBOSE_MODE" = "true" ]; then
            # Verbose mode with progress meter
            curl --insecure -v --connect-timeout $CONNECT_TIMEOUT --max-time $TRANSFER_TIMEOUT \
                -T "$local_file" "sftp://$SFTP_USER:$SFTP_PASS@$SFTP_HOST:$SFTP_PORT/$remote_file" 2>&1 | tee -a "$LOG_FILE"
        else
            # Non-verbose mode with progress bar but less logging
            curl --insecure --progress-bar --connect-timeout $CONNECT_TIMEOUT --max-time $TRANSFER_TIMEOUT \
                -T "$local_file" "sftp://$SFTP_USER:$SFTP_PASS@$SFTP_HOST:$SFTP_PORT/$remote_file" 2>&1 | tee -a "$LOG_FILE"
        fi
        
        if [ ${PIPESTATUS[0]} -eq 0 ]; then
            log "INFO" "Successfully uploaded $local_file (Attempt $attempt)"
            success=true
            break
        else
            log "WARNING" "Failed to upload $local_file (Attempt $attempt)"
            attempt=$((attempt + 1))
            if [ $attempt -le $max_attempts ]; then
                log "INFO" "Retrying in 5 seconds..."
                sleep 5
            fi
        fi
    done
    
    if [ "$success" = "true" ]; then
        return 0
    else
        return 1
    fi
}

# Function to upload a file using lftp
upload_with_lftp() {
    local local_file="$1"
    local remote_file="$2"
    local attempt=1
    local max_attempts=$MAX_RETRIES
    local success=false
    
    while [ $attempt -le $max_attempts ] && [ "$success" = "false" ]; do
        log "INFO" "Uploading $local_file using lftp (Attempt $attempt of $max_attempts)"
        
        lftp -c "open -u $SFTP_USER,$SFTP_PASS sftp://$SFTP_HOST:$SFTP_PORT; put -E \"$local_file\" -o \"$remote_file\"" 2>&1 | tee -a "$LOG_FILE"
        
        if [ ${PIPESTATUS[0]} -eq 0 ]; then
            log "INFO" "Successfully uploaded $local_file using lftp (Attempt $attempt)"
            success=true
            break
        else
            log "WARNING" "Failed to upload $local_file using lftp (Attempt $attempt)"
            attempt=$((attempt + 1))
            if [ $attempt -le $max_attempts ]; then
                log "INFO" "Retrying in 5 seconds..."
                sleep 5
            fi
        fi
    done
    
    if [ "$success" = "true" ]; then
        return 0
    else
        return 1
    fi
}

# Function to create an SFTP batch file
create_sftp_batch() {
    local batch_file="$1"
    local uploads="$2"
    
    # Clear the batch file
    > "$batch_file"
    
    # Add the upload commands to the batch file
    echo "$uploads" > "$batch_file"
    echo "bye" >> "$batch_file"
}

# Function to upload files using sftp
upload_with_sftp() {
    local local_file="$1"
    local remote_file="$2"
    local attempt=1
    local max_attempts=$MAX_RETRIES
    local success=false
    
    while [ $attempt -le $max_attempts ] && [ "$success" = "false" ]; do
        log "INFO" "Uploading $local_file using sftp (Attempt $attempt of $max_attempts)"
        
        local batch_file=$(mktemp)
        echo "put \"$local_file\" \"$remote_file\"" > "$batch_file"
        echo "bye" >> "$batch_file"
        
        # Check if we can use sshpass
        if command -v sshpass &> /dev/null; then
            sshpass -p "$SFTP_PASS" sftp -P "$SFTP_PORT" -b "$batch_file" -o StrictHostKeyChecking=no "$SFTP_USER@$SFTP_HOST" 2>&1 | tee -a "$LOG_FILE"
            result=$?
        elif command -v expect &> /dev/null; then
            # Create an expect script
            expect_script=$(mktemp)
            echo "#!/usr/bin/expect -f" > "$expect_script"
            echo "set timeout 3600" >> "$expect_script"
            echo "spawn sftp -P $SFTP_PORT -b $batch_file -o StrictHostKeyChecking=no $SFTP_USER@$SFTP_HOST" >> "$expect_script"
            echo "expect \"assword:\"" >> "$expect_script"
            echo "send \"$SFTP_PASS\r\"" >> "$expect_script"
            echo "expect eof" >> "$expect_script"
            chmod +x "$expect_script"
            
            "$expect_script" 2>&1 | tee -a "$LOG_FILE"
            result=$?
            
            rm -f "$expect_script"
        else
            # Direct SFTP with manual password entry (not ideal for automation)
            log "WARNING" "Running SFTP with batch file (will prompt for password)"
            sftp -P "$SFTP_PORT" -b "$batch_file" -o StrictHostKeyChecking=no "$SFTP_USER@$SFTP_HOST" 2>&1 | tee -a "$LOG_FILE"
            result=$?
        fi
        
        rm -f "$batch_file"
        
        if [ $result -eq 0 ]; then
            log "INFO" "Successfully uploaded $local_file using sftp (Attempt $attempt)"
            success=true
            break
        else
            log "WARNING" "Failed to upload $local_file using sftp (Attempt $attempt)"
            attempt=$((attempt + 1))
            if [ $attempt -le $max_attempts ]; then
                log "INFO" "Retrying in 5 seconds..."
                sleep 5
            fi
        fi
    done
    
    if [ "$success" = "true" ]; then
        return 0
    else
        return 1
    fi
}

# Function to upload with any available method
upload_file() {
    local local_file="$1"
    local remote_file="$2"
    
    # First try with curl if available
    if [ "$USE_CURL" = "true" ]; then
        upload_with_curl "$local_file" "$remote_file"
        if [ $? -eq 0 ]; then
            return 0
        else
            log "WARNING" "Curl upload failed, trying alternative methods"
        fi
    fi
    
    # Try lftp next if available
    if [ "$USE_LFTP" = "true" ]; then
        upload_with_lftp "$local_file" "$remote_file"
        if [ $? -eq 0 ]; then
            return 0
        else
            log "WARNING" "lftp upload failed, trying sftp"
        fi
    fi
    
    # Finally try sftp
    if [ "$USE_SFTP" = "true" ]; then
        upload_with_sftp "$local_file" "$remote_file"
        if [ $? -eq 0 ]; then
            return 0
        else
            log "WARNING" "All upload methods failed for $local_file"
        fi
    fi
    
    # If we get here, all methods failed
    return 1
}

# Test connection to SFTP server
if ! test_connection; then
    log "ERROR" "Could not connect to SFTP server. Please check credentials and connection settings."
    exit 1
fi

# Count and collect files
total_found=0
total_uploaded=0
total_failed=0
failed_files=""

# Process logs directory
if [ -d "logs" ]; then
    log_files=$(find logs -type f -print)
    log_count=$(echo "$log_files" | wc -l)
    total_found=$((total_found + log_count))
    
    log "INFO" "Found $log_count files in logs directory"
    
    # Process each log file 
    for log_file in $log_files; do
        filename=$(basename "$log_file")
        # Skip the current upload log
        if [ "$log_file" = "$LOG_FILE" ]; then
            log "INFO" "Skipping current log file $log_file"
            continue
        fi
        
        # Create a unique name with timestamp and path info
        unique_name="${TIMESTAMP}_logs_${filename}"
        
        log "INFO" "Processing $log_file -> $unique_name"
        
        if upload_file "$log_file" "$unique_name"; then
            log "INFO" "Successfully uploaded $log_file"
            total_uploaded=$((total_uploaded + 1))
        else
            log "ERROR" "Failed to upload $log_file after multiple attempts"
            total_failed=$((total_failed + 1))
            failed_files="$failed_files\n$log_file"
        fi
    done
fi

# Process reports directory
if [ -d "reports" ]; then
    report_files=$(find reports -type f -print)
    report_count=$(echo "$report_files" | wc -l)
    total_found=$((total_found + report_count))
    
    log "INFO" "Found $report_count files in reports directory"
    
    # Process each report file
    for report_file in $report_files; do
        filename=$(basename "$report_file")
        # Create a unique name with timestamp and path info
        unique_name="${TIMESTAMP}_reports_${filename}"
        
        log "INFO" "Processing $report_file -> $unique_name"
        
        if upload_file "$report_file" "$unique_name"; then
            log "INFO" "Successfully uploaded $report_file"
            total_uploaded=$((total_uploaded + 1))
        else
            log "ERROR" "Failed to upload $report_file after multiple attempts"
            total_failed=$((total_failed + 1))
            failed_files="$failed_files\n$report_file"
        fi
    done
fi

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