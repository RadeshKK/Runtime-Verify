import time
import psutil
import os
from typing import List, Tuple, Dict, Any
from runtimeverify.detector.interfaces import BaseDetector
from runtimeverify.detector import DetectorResult

class ReplayEngine:
    """
    Replays a sequence of states through a detector and records the precise 
    point of detection and resource usage.
    """
    def __init__(self, detector: BaseDetector):
        self.detector = detector

    def run(self, sequence: List[str]) -> Tuple[List[bool], List[int], float, float]:
        """
        Feeds a sequence into the detector and monitors results.

        Returns:
            A tuple containing:
            - List[bool]: Prediction sequence (True if DRIFT/REJECT_H0)
            - List[int]: Indices of all detections
            - float: Total runtime in ms
            - float: Peak memory usage in MB
        """
        process = psutil.Process(os.getpid())
        start_mem = process.memory_info().rss
        
        predictions = []
        detection_indices = []
        
        start_time = time.perf_counter()
        
        # We assume the sequence represents the 'target' states of transitions
        # For simplicity in replay, we assume a fixed dummy source state or 
        # rely on the detector's internal state tracking from previous update()
        for idx, state in enumerate(sequence):
            result = self.detector.update(state)
            
            is_anomaly = result.decision in ("DRIFT", "REJECT_H0")
            predictions.append(is_anomaly)
            if is_anomaly:
                detection_indices.append(idx)
        
        end_time = time.perf_counter()
        end_mem = process.memory_info().rss
        
        runtime_ms = (end_time - start_time) * 1000
        memory_mb = (end_mem - start_mem) / (1024 * 1024)
        
        return predictions, detection_indices, runtime_ms, max(0.0, memory_mb)
