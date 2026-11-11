## Setup Instructions (for new system)

# Activate virtual environment
source .venv/bin/activate

# Monitor indefinitely (Ctrl-C to stop)
python3 -m runtime_engine.main --db monitor.db monitor

-------------------------------------------
# Threat testing
mkdir -p /tmp/rte-lab

cp /bin/bash /tmp/rte-lab/test-shell

chmod +x /tmp/rte-lab/test-shell

THREAT  
1. Start your engine in one terminal:
2. In another terminal, run:
    /tmp/rte-lab/test-shell -c 'sleep 8'

