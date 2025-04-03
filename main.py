import sys
from PyQt5.QtWidgets import QApplication
from gui.main_window import NetworkMonitorGUI

def main():
    """Application entry point."""
    app = QApplication(sys.argv)
    
    # Global exception handler
    def exception_hook(exctype, value, traceback):
        print(f"Unhandled exception: {exctype.__name__}: {value}")
        sys.__excepthook__(exctype, value, traceback)
        QApplication.quit()
    
    sys.excepthook = exception_hook
    
    window = NetworkMonitorGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
