#!/bin/bash
# upload_files.sh - Upload files directly to SFTP root directory
# Works with SFTP servers that restrict users to the root directory

# Set up logging
LOG_FILE="logs/sftp_upload.log"
echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Starting root directory uploader" | tee -a "$LOG_FILE"

# Load environment variables from .env
if [ -f .env ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Loading variables from .env file" | tee -a "$LOG_FILE"
    export $(grep -v '^#' .env | xargs)
fi

# Check required variables
if [ -z "$SFTP_HOST" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR - Missing SFTP_HOST in .env file" | tee -a "$LOG_FILE"
    exit 1
fi

if [ -z "$SFTP_USER" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR - Missing SFTP_USER in .env file" | tee -a "$LOG_FILE"
    exit 1
fi

if [ -z "$SFTP_PASS" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR - Missing SFTP_PASS in .env file" | tee -a "$LOG_FILE"
    exit 1
fi

# Set default port if not specified
SFTP_PORT=${SFTP_PORT:-22}

# Create timestamp for filename prefix
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Using timestamp: $TIMESTAMP" | tee -a "$LOG_FILE"

# Log settings (without showing the password)
echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Upload settings:" | tee -a "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO -   Host: $SFTP_HOST" | tee -a "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO -   User: $SFTP_USER" | tee -a "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO -   Port: $SFTP_PORT" | tee -a "$LOG_FILE"

# Check available tools
USE_CURL=false
USE_SFTP=false

if command -v curl &> /dev/null; then
    # Check if curl has SFTP support
    curl --version | grep -i sftp &> /dev/null
    if [ $? -eq 0 ]; then
        USE_CURL=true
        echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Using curl for uploads" | tee -a "$LOG_FILE"
    fi
fi

if [ "$USE_CURL" = "false" ] && command -v sftp &> /dev/null; then
    USE_SFTP=true
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Using sftp for uploads" | tee -a "$LOG_FILE"
fi

if [ "$USE_CURL" = "false" ] && [ "$USE_SFTP" = "false" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR - Neither curl with SFTP support nor sftp command available" | tee -a "$LOG_FILE"
    exit 1
fi

# Function to upload a file using curl
upload_with_curl() {
    local local_file="$1"
    local remote_file="$2"
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Uploading $local_file to $remote_file" | tee -a "$LOG_FILE"
    
    curl --insecure -v --connect-timeout 30 --max-time 600 \
      -T "$local_file" "sftp://$SFTP_USER:$SFTP_PASS@$SFTP_HOST:$SFTP_PORT/$remote_file" 2>&1 | tee -a "$LOG_FILE"
    
    return ${PIPESTATUS[0]}
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
    local batch_file=$(mktemp)
    local sftp_commands="$1"
    
    # Create the batch file
    create_sftp_batch "$batch_file" "$sftp_commands"
    
    # Check if we can use expect
    if command -v expect &> /dev/null; then
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
        # Direct SFTP with manual password entry
        echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Running SFTP with batch file (will prompt for password)" | tee -a "$LOG_FILE"
        sftp -P "$SFTP_PORT" -b "$batch_file" -o StrictHostKeyChecking=no "$SFTP_USER@$SFTP_HOST" 2>&1 | tee -a "$LOG_FILE"
        result=$?
    fi
    
    rm -f "$batch_file"
    return $result
}

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
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Found $log_count files in logs directory" | tee -a "$LOG_FILE"
    
    # Process each log file using a for loop instead of a while loop to avoid subshell variable scope issues
    for log_file in $log_files; do
        filename=$(basename "$log_file")
        # Create a unique name with timestamp and path info
        unique_name="${TIMESTAMP}_logs_${filename}"
        
        echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Processing $log_file -> $unique_name" | tee -a "$LOG_FILE"
        
        if [ "$USE_CURL" = "true" ]; then
            # Upload with curl
            if upload_with_curl "$log_file" "$unique_name"; then
                echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Successfully uploaded $log_file" | tee -a "$LOG_FILE"
                total_uploaded=$((total_uploaded + 1))
            else
                echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR - Failed to upload $log_file" | tee -a "$LOG_FILE"
                total_failed=$((total_failed + 1))
                failed_files="$failed_files\n$log_file"
            fi
        elif [ "$USE_SFTP" = "true" ]; then
            # Build SFTP batch commands
            sftp_commands="put \"$log_file\" \"$unique_name\""
            
            if upload_with_sftp "$sftp_commands"; then
                echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Successfully uploaded $log_file" | tee -a "$LOG_FILE"
                total_uploaded=$((total_uploaded + 1))
            else
                echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR - Failed to upload $log_file" | tee -a "$LOG_FILE"
                total_failed=$((total_failed + 1))
                failed_files="$failed_files\n$log_file"
            fi
        fi
    done
fi

# Process reports directory
if [ -d "reports" ]; then
    report_files=$(find reports -type f -print)
    report_count=$(echo "$report_files" | wc -l)
    total_found=$((total_found + report_count))
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Found $report_count files in reports directory" | tee -a "$LOG_FILE"
    
    # Process each report file using a for loop
    for report_file in $report_files; do
        filename=$(basename "$report_file")
        # Create a unique name with timestamp and path info
        unique_name="${TIMESTAMP}_reports_${filename}"
        
        echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Processing $report_file -> $unique_name" | tee -a "$LOG_FILE"
        
        if [ "$USE_CURL" = "true" ]; then
            # Upload with curl
            if upload_with_curl "$report_file" "$unique_name"; then
                echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Successfully uploaded $report_file" | tee -a "$LOG_FILE"
                total_uploaded=$((total_uploaded + 1))
            else
                echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR - Failed to upload $report_file" | tee -a "$LOG_FILE"
                total_failed=$((total_failed + 1))
                failed_files="$failed_files\n$report_file"
            fi
        elif [ "$USE_SFTP" = "true" ]; then
            # Build SFTP batch commands
            sftp_commands="put \"$report_file\" \"$unique_name\""
            
            if upload_with_sftp "$sftp_commands"; then
                echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Successfully uploaded $report_file" | tee -a "$LOG_FILE"
                total_uploaded=$((total_uploaded + 1))
            else
                echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR - Failed to upload $report_file" | tee -a "$LOG_FILE"
                total_failed=$((total_failed + 1))
                failed_files="$failed_files\n$report_file"
            fi
        fi
    done
fi

# Print summary
echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Upload summary:" | tee -a "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Found $total_found files" | tee -a "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Successfully uploaded $total_uploaded files" | tee -a "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Failed to upload $total_failed files" | tee -a "$LOG_FILE"

if [ $total_failed -gt 0 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - WARNING - Failed files:" | tee -a "$LOG_FILE"
    echo -e "$failed_files" | tee -a "$LOG_FILE"
    exit 1
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - Upload completed successfully" | tee -a "$LOG_FILE"
    exit 0
fi