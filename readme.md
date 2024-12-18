# NetBrain to FireMon Device Synchronization Service

This service synchronizes device inventory, configurations, and grouping between NetBrain and FireMon.

## Features

- Device synchronization from NetBrain to FireMon
- Configuration synchronization and updates
- Device group hierarchy maintenance
- Automated licensing management
- Support for multiple device types
- Dry run mode for testing
- Comprehensive logging

## Prerequisites

- Python 3.8 or higher
- Access to NetBrain API
- Access to FireMon API
- Required Python packages (see requirements.txt)

## Installation

1. Download / Clone the repository:
```bash
git clone https://github.com/adamgunderson/NetBrain-FireMon-Sync.git
```
or
```
wget https://github.com/adamgunderson/NetBrain-FireMon-Sync/archive/refs/heads/main.zip
unzip main.zip
```

2. Create and activate a virtual environment:
```bash
cd Netbrain-FireMon-Sync
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required packages:
```bash
python3 venv/bin/pip install -r requirements.txt
```
or
```
python3 venv/bin/pip install requests dataclasses python-dotenv pyyaml urllib3 typing-extensions python-dateutil fcntl-linux pytz pyyaml
```

4. Create environment configuration:
```bash
cp .env.example .env
```

5. Create sync mappings configuration:
```bash
cp sync-mappings.yaml.example sync-mappings.yaml
```

## Configuration

### Environment Variables (.env)

Configure the following environment variables in your `.env` file:

```ini
# NetBrain Configuration
NETBRAIN_HOST=https://netbrain.company.com
NETBRAIN_USERNAME=sync-service
NETBRAIN_PASSWORD=your-secure-password
NETBRAIN_TENANT=Default

# FireMon Configuration
FIREMON_HOST=https://firemon.company.com
FIREMON_USERNAME=sync-service
FIREMON_PASSWORD=your-secure-password
FIREMON_DOMAIN_ID=1

# Sync Configuration
SYNC_INTERVAL_MINUTES=60
DRY_RUN=false
```

### Sync Mappings (sync-mappings.yaml)

Configure the mappings between NetBrain and FireMon in `sync-mappings.yaml`:

1. Collector Mapping:
   - Maps NetBrain site codes to FireMon collector group IDs
   ```yaml
   collector_mapping:
     NA: "1716af41-caf5-40c6-a81b-84202fc640aa"
     EU: "2826b52-d7b6-5bf7-bc2b-95313f751bb"
   ```

2. Device Pack Mapping:
   - Maps NetBrain device types to FireMon device packs
   ```yaml
   device_pack_mapping:
     "Cisco IOS Switch":
       device_pack_id: 25
       artifact_id: "cisco_ios"
       group_id: "com.fm.sm.dp.cisco-ios"
       device_type: "ROUTER_SWITCH"
       device_name: "IOS"
   ```

3. Configuration File Mapping:
   - Maps NetBrain commands to FireMon configuration files
   ```yaml
   config_file_mapping:
     "Cisco IOS Switch":
       "show running-config": "config_xml"
       "show version": "version_xml"
   ```

## Usage

### Running the Service

1. Start the service:
```bash
python3 main.py
```

2. For dry run mode (no changes made):
```bash
DRY_RUN=true python3 main.py
```

### Service Operation

The service performs the following:

1. Device Synchronization:
   - Creates new devices in FireMon that exist in NetBrain
   - Updates existing device configurations
   - Optionally unlicenses devices that no longer exist in NetBrain

2. Group Synchronization:
   - Creates device groups in FireMon matching NetBrain site hierarchy
   - Maintains device group membership

3. Configuration Synchronization:
   - Updates device configurations in FireMon when newer in NetBrain
   - Maps configuration files according to device type

### Logging

Logs are written to both console and file:
- Location: `logs/sync-service.log`
- Log rotation: 10MB file size, keeps last 5 files
- Configure level in .env: `LOG_LEVEL=info`

## Error Handling

The service includes robust error handling:
- Automatic retry on API failures
- Detailed error logging
- Graceful degradation when partial synchronization fails
- Automatic token refresh

## Limitations

- One-way sync (NetBrain to FireMon only)
- Device configurations must be available in NetBrain
- Device types must be mapped in configuration

## Troubleshooting

1. Check logs in `logs/sync-service.log`
2. Verify API connectivity
3. Confirm mapping configuration
4. Ensure required permissions in both systems
