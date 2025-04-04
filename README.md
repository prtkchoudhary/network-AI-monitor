# AI-Powered Network Monitor with DDoS Detection

A real-time network monitoring application with AI-powered DDoS detection capabilities.

## Features

- Real-time network traffic monitoring
- DDoS attack detection using multiple ML models
- Suspicious IP blocking
- Beautiful and intuitive user interface
- Detailed anomaly logging

## Requirements

- Python 3.7 or higher
- Required Python packages (install using `pip install -r requirements.txt`):
  - PyQt5
  - psutil
  - numpy
  - scikit-learn
  - pyqtgraph

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd network monitor
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the application:
```bash
python main.py
```

### Features

1. **Network Monitoring**
   - Real-time display of network traffic
   - Sent and received bytes per second
   - Connection count monitoring

2. **DDoS Detection**
   - Uses multiple ML models (Isolation Forest, One-Class SVM, Local Outlier Factor)
   - Real-time anomaly detection
   - Automatic suspicious IP blocking

3. **User Interface**
   - Start/Stop monitoring
   - Reset statistics
   - Manual IP blocking
   - Detailed anomaly logs

## Note

- The application requires administrative privileges for IP blocking functionality
- DDoS detection sensitivity can be adjusted in `utils/constants.py`
- Logs are saved to `ddos_logs.txt`
