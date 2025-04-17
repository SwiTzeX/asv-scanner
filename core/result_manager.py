import threading

# Global scan result storage
results_dict = {}

# Global lock for multithreading
lock = threading.Lock()
