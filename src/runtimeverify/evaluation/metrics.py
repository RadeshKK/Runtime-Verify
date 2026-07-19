from typing import List, Dict

class EvaluationMetrics:
    """
    Computes statistical evaluation metrics (accuracy, delay, timings)
    over a set of trace benchmarks.
    """
    
    @staticmethod
    def calculate_classification_metrics(
        ground_truths: List[bool], 
        predictions: List[bool]
    ) -> Dict[str, float]:
        """
        Calculates precision, recall, f1, FPR, and FNR.
        
        Args:
            ground_truths: True if trace is anomalous, False if normal.
            predictions: True if detector flagged ANOMALY, False otherwise.
        """
        tp = fp = tn = fn = 0
        
        for gt, pred in zip(ground_truths, predictions):
            if gt is True and pred is True:
                tp += 1
            elif gt is False and pred is True:
                fp += 1
            elif gt is False and pred is False:
                tn += 1
            elif gt is True and pred is False:
                fn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2.0 * (precision * recall) / (precision + recall) if (precision + recall) > 0.0 else 0.0
        
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
        
        accuracy = (tp + tn) / len(ground_truths) if ground_truths else 0.0

        return {
            "true_positives": float(tp),
            "false_positives": float(fp),
            "true_negatives": float(tn),
            "false_negatives": float(fn),
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
        }

    @staticmethod
    def calculate_average_delay(delays: List[int]) -> float:
        """Calculates the average number of observations before detection was triggered."""
        if not delays:
            return 0.0
        return sum(delays) / len(delays)
