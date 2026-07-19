from typing import Dict, Any, List

class ReportGenerator:
    """
    Utility class that constructs formatted text/markdown report dashboards 
    summarizing benchmark runs and model comparison tables.
    """

    @staticmethod
    def generate_markdown(
        detector_name: str,
        metrics: Dict[str, float],
        average_delay: float,
        latencies: List[float]
    ) -> str:
        """Formats evaluation metrics into an auditable markdown report."""
        
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        max_latency = max(latencies) if latencies else 0.0
        
        tp = int(metrics.get("true_positives", 0))
        fp = int(metrics.get("false_positives", 0))
        tn = int(metrics.get("true_negatives", 0))
        fn = int(metrics.get("false_negatives", 0))

        report = f"""# Evaluation Report: `{detector_name}`
**Tuning Parameters & Metrics Summary**

## 📈 Performance Summary

| Metric | Value |
| :--- | :--- |
| **Accuracy** | {metrics.get("accuracy", 0.0):.4f} |
| **Precision** | {metrics.get("precision", 0.0):.4f} |
| **Recall (TPR)** | {metrics.get("recall", 0.0):.4f} |
| **F1 Score** | {metrics.get("f1_score", 0.0):.4f} |
| **False Positive Rate (FPR)** | {metrics.get("false_positive_rate", 0.0):.4f} |
| **False Negative Rate (FNR)** | {metrics.get("false_negative_rate", 0.0):.4f} |
| **Average Detection Delay** | {average_delay:.2f} observations |

## 🎛️ Confusion Matrix

| | Predicted Normal | Predicted Anomaly |
| :--- | :---: | :---: |
| **Actual Normal** | **TN:** {tn} | **FP:** {fp} |
| **Actual Anomaly** | **FN:** {fn} | **TP:** {tp} |

## ⏱️ Latency Benchmark

* **Average Step Latency:** {avg_latency:.4f} ms
* **Maximum Step Latency:** {max_latency:.4f} ms
* **Throughput:** {(1000.0 / avg_latency if avg_latency > 0 else 0.0):.1f} steps/second

---
"""
        return report

    @staticmethod
    def generate_comparison_table(results: List[Dict[str, Any]]) -> str:
        """Generates a comparison table comparing multiple detectors."""
        table = """# Detector Comparison Benchmark

| Detector Name | Accuracy | F1 Score | FPR | FNR | Avg Delay (Steps) | Avg Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
"""
        for r in results:
            name = r["name"]
            metrics = r["metrics"]
            delay = r["average_delay"]
            avg_lat = r["avg_latency"]
            
            table += f"| `{name}` | {metrics.get('accuracy', 0.0):.4f} | {metrics.get('f1_score', 0.0):.4f} | {metrics.get('false_positive_rate', 0.0):.4f} | {metrics.get('false_negative_rate', 0.0):.4f} | {delay:.2f} | {avg_lat:.4f} ms |\n"
            
        return table
